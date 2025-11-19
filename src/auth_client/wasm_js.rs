use crate::{
    ArcIdentity, AuthClientError,
    api::{
        AuthResponseSuccess, IdentityServiceResponseKind, IdentityServiceResponseMessage,
        InternetIdentityAuthRequest,
    },
    idle_manager::{IdleManager, IdleManagerOptions},
    key::{BaseKeyType, Key, KeyWithRaw},
    option::{AuthClientLoginOptions, IdleOptions, wasm_js::AuthClientCreateOptions},
    storage::{
        KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY, KEY_VECTOR, StoredKey,
        async_storage::{AuthClientStorage, LocalStorage},
    },
    util::{callback::OnSuccess, delegation_chain::DelegationChain},
};
use futures::{
    future::{AbortHandle, Abortable},
    lock::Mutex as FutureMutex,
};
use gloo_events::EventListener;
use gloo_utils::{format::JsValueSerdeExt, window};
use ic_agent::{
    export::Principal,
    identity::{AnonymousIdentity, DelegatedIdentity, DelegationError, Identity, SignedDelegation},
};
use parking_lot::Mutex;
use serde_wasm_bindgen::from_value;
use std::{cell::RefCell, fmt, sync::Arc, time::Duration};
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    Location, MessageEvent,
    wasm_bindgen::{JsCast, JsValue},
};

const IDENTITY_PROVIDER_DEFAULT: &str = "https://identity.internetcomputer.org";
const IDENTITY_PROVIDER_ENDPOINT: &str = "#authorize";

const INTERRUPT_CHECK_INTERVAL: Duration = Duration::from_millis(500);
/// The error message when a user interrupts the authentication process.
pub const ERROR_USER_INTERRUPT: &str = "UserInterrupt";

thread_local! {
    static ACTIVE_LOGIN: RefCell<Option<ActiveLogin>> = const { RefCell::new(None) };
}

/// Holds the resources for an active login process.
/// When this struct is dropped, it automatically cleans up all associated resources.
#[derive(Debug)]
struct ActiveLogin {
    idp_window: web_sys::Window,
    _message_handler: EventListener,
    interruption_check_abort_handle: AbortHandle,
}

impl Drop for ActiveLogin {
    fn drop(&mut self) {
        // Abort the interruption check task.
        self.interruption_check_abort_handle.abort();
        // Close the IdP window, ignoring errors if it's already closed.
        let _ = self.idp_window.close();
        // The message_handler (EventListener) is automatically dropped, removing the listener.
    }
}

pub(super) struct AuthClientInner {
    pub identity: Arc<Mutex<ArcIdentity>>,
    pub key: Key,
    pub storage: FutureMutex<Box<dyn AuthClientStorage>>,
    pub chain: Arc<Mutex<Option<DelegationChain>>>,
    pub idle_manager: Mutex<Option<IdleManager>>,
    pub idle_options: Option<IdleOptions>,
}

impl fmt::Debug for AuthClientInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthClientInner")
            .field("key", &self.key)
            .field("idle_options", &self.idle_options)
            .finish()
    }
}

impl Drop for AuthClientInner {
    fn drop(&mut self) {
        ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());
    }
}

/// The tool for managing authentication and identity.
///
/// It maintains the state of the user's identity and provides methods for authentication.
#[derive(Clone, Debug)]
pub struct AuthClient(Arc<AuthClientInner>);

impl AuthClient {
    /// Default time to live for the session in nanoseconds (8 hours).
    const DEFAULT_TIME_TO_LIVE: u64 = 8 * 60 * 60 * 1_000_000_000;

    /// Create a new [`AuthClientBuilder`] for building an AuthClient.
    pub fn builder() -> AuthClientBuilder {
        AuthClientBuilder::new()
    }

    /// Creates a new [`AuthClient`] with default options.
    pub async fn new() -> Result<Self, AuthClientError> {
        Self::new_with_options(AuthClientCreateOptions::default()).await
    }

    /// Creates a new [`AuthClient`] with the provided options.
    pub async fn new_with_options(
        options: AuthClientCreateOptions,
    ) -> Result<Self, AuthClientError> {
        let AuthClientCreateOptions {
            identity,
            storage,
            key_type: _key_type,
            idle_options,
        } = options;

        let mut storage = storage.unwrap_or_else(|| Box::new(LocalStorage::new()));
        let options_identity_is_some = identity.is_some();

        let key = Self::create_or_load_key(identity, storage.as_mut()).await?;

        let (chain, identity) = Self::load_delegation_chain(storage.as_mut(), &key).await;

        let idle_manager =
            Self::create_idle_manager(&idle_options, &chain, options_identity_is_some);

        Ok(Self(Arc::new(AuthClientInner {
            identity: Arc::new(Mutex::new(identity)),
            key,
            storage: FutureMutex::new(storage),
            chain: Arc::new(Mutex::new(chain)),
            idle_manager: Mutex::new(idle_manager),
            idle_options,
        })))
    }

    /// Creates a new key if one is not found in storage, otherwise loads the existing key.
    async fn create_or_load_key(
        identity: Option<ArcIdentity>,
        storage: &mut dyn AuthClientStorage,
    ) -> Result<Key, AuthClientError> {
        match identity {
            Some(identity) => Ok(Key::Identity(identity)),
            None => match storage.get(KEY_STORAGE_KEY).await {
                Ok(Some(stored_key)) => {
                    let private_key = stored_key.decode()?;
                    Ok(Key::WithRaw(KeyWithRaw::new(private_key)))
                }
                Ok(None) => {
                    let mut rng = rand::thread_rng();
                    let private_key = ed25519_dalek::SigningKey::generate(&mut rng).to_bytes();
                    storage
                        .set(KEY_STORAGE_KEY, StoredKey::Raw(private_key))
                        .await?;
                    Ok(Key::WithRaw(KeyWithRaw::new(private_key)))
                }
                Err(e) => Err(e.into()),
            },
        }
    }

    /// Extracts delegation data from a delegation chain if it is valid.
    fn get_delegation_data(
        chain: &Option<DelegationChain>,
    ) -> Option<(Vec<u8>, Vec<SignedDelegation>)> {
        if let Some(chain_inner) = chain.as_ref() {
            if chain_inner.is_delegation_valid(None) {
                let public_key = chain_inner.public_key.clone();
                let delegations = chain_inner.delegations.clone();
                Some((public_key, delegations))
            } else {
                None
            }
        } else {
            Some((Vec::new(), Vec::new()))
        }
    }

    /// Loads a delegation chain from storage and updates the identity if the chain is valid.
    async fn load_delegation_chain(
        storage: &mut dyn AuthClientStorage,
        key: &Key,
    ) -> (Option<DelegationChain>, ArcIdentity) {
        let mut identity = ArcIdentity::from(key);
        let mut chain: Option<DelegationChain> = None;

        match storage.get(KEY_STORAGE_DELEGATION).await {
            Ok(Some(chain_stored)) => {
                let chain_stored = chain_stored.encode();
                let chain_result = DelegationChain::from_json(&chain_stored);
                chain = Some(chain_result);

                let delegation_data = Self::get_delegation_data(&chain);

                match delegation_data {
                    Some((public_key, delegations)) => {
                        if !public_key.is_empty() {
                            identity =
                                ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                                    public_key,
                                    Box::new(key.as_arc_identity()),
                                    delegations,
                                )));
                        }
                    }
                    None => {
                        #[cfg(feature = "tracing")]
                        info!("Found invalid delegation chain in storage - clearing credentials");
                        if let Err(_e) = Self::delete_storage(storage).await {
                            #[cfg(feature = "tracing")]
                            error!("Failed to delete storage: {}", _e);
                        }
                        identity = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
                        chain = None;
                    }
                }
            }
            Ok(None) => (),
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Failed to load delegation chain from storage: {}", _e);
            }
        }

        (chain, identity)
    }

    /// Creates an idle manager if idle detection is not disabled.
    fn create_idle_manager(
        idle_options: &Option<IdleOptions>,
        chain: &Option<DelegationChain>,
        identity_is_some: bool,
    ) -> Option<IdleManager> {
        if !idle_options
            .as_ref()
            .and_then(|o| o.disable_idle)
            .unwrap_or(false)
            && (chain.is_some() || identity_is_some)
        {
            let idle_manager_options: Option<IdleManagerOptions> = idle_options
                .as_ref()
                .map(|o| o.idle_manager_options.clone());
            Some(IdleManager::new(idle_manager_options))
        } else {
            None
        }
    }

    /// Returns the idle manager if it exists.
    pub fn idle_manager(&self) -> Option<IdleManager> {
        self.0.idle_manager.lock().clone()
    }

    /// Registers the default idle callback.
    fn register_default_idle_callback(&self) {
        if let Some(options) = self.0.idle_options.as_ref() {
            if options.disable_default_idle_callback.unwrap_or_default() {
                return;
            }

            if options.idle_manager_options.on_idle.lock().is_empty() {
                if let Some(idle_manager) = self.0.idle_manager.lock().as_ref() {
                    let client = self.clone();
                    let callback = move || {
                        let client = client.clone();
                        spawn_local(async move {
                            client.logout(None).await;
                            match window().location().reload() {
                                Ok(_) => (),
                                Err(_e) => {
                                    #[cfg(feature = "tracing")]
                                    error!("Failed to reload page: {_e:?}");
                                }
                            };
                        });
                    };
                    idle_manager.register_callback(callback);
                }
            }
        }
    }

    /// Handles a successful authentication response.
    async fn handle_success(
        &self,
        message: AuthResponseSuccess,
        on_success: Option<OnSuccess>,
    ) -> Result<(), DelegationError> {
        // Take and drop the ActiveLogin struct, which handles all resource cleanup.
        let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());

        let delegations = message.delegations.clone();
        let user_public_key = message.user_public_key.clone();

        let delegation_chain = DelegationChain {
            delegations: delegations.clone(),
            public_key: user_public_key.clone(),
        };

        self.update_storage_with_delegation(&delegation_chain).await;
        self.update_identity_with_delegation(
            &delegation_chain,
            user_public_key.clone(),
            delegations.clone(),
        );

        self.verify_and_fix_authentication(
            &user_public_key,
            &delegations,
            &delegation_chain.to_json(),
        );

        self.maybe_create_idle_manager();

        if let Some(on_success_cb) = on_success {
            on_success_cb.0.lock()(message.clone());
        }

        Ok(())
    }

    /// Stores the delegation chain and key in storage.
    async fn update_storage_with_delegation(&self, delegation_chain: &DelegationChain) {
        if let Key::WithRaw(key) = &self.0.key {
            if let Err(_e) = self
                .0
                .storage
                .lock()
                .await
                .set(KEY_STORAGE_KEY, StoredKey::Raw(*key.raw_key()))
                .await
            {
                #[cfg(feature = "tracing")]
                error!("Failed to store key: {}", _e);
            }
        }

        let chain_json = delegation_chain.to_json();
        if let Err(_e) = self
            .0
            .storage
            .lock()
            .await
            .set(
                KEY_STORAGE_DELEGATION,
                StoredKey::String(chain_json.clone()),
            )
            .await
        {
            #[cfg(feature = "tracing")]
            error!("Failed to store delegation: {}", _e);
        }
    }

    /// Updates the in-memory identity with the new delegation.
    fn update_identity_with_delegation(
        &self,
        delegation_chain: &DelegationChain,
        user_public_key: Vec<u8>,
        delegations: Vec<SignedDelegation>,
    ) {
        *self.0.chain.lock() = Some(delegation_chain.clone());
        *self.0.identity.lock() =
            ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                user_public_key,
                Box::new(self.0.key.as_arc_identity()),
                delegations,
            )));
    }

    /// Verifies that the user is authenticated and attempts to fix the state if not.
    fn verify_and_fix_authentication(
        &self,
        user_public_key: &[u8],
        delegations: &[SignedDelegation],
        chain_json: &str,
    ) {
        if self.is_authenticated() {
            return;
        }

        #[cfg(feature = "tracing")]
        warn!("CRITICAL: is_authenticated() returned false after successful login");

        let _is_not_anonymous = self
            .identity()
            .sender()
            .map(|s| s != Principal::anonymous())
            .unwrap_or(false);
        let _has_chain = self.0.chain.lock().is_some();
        #[cfg(feature = "tracing")]
        debug!(
            "is_authenticated(): is_not_anonymous={}, has_chain={}",
            _is_not_anonymous, _has_chain
        );

        *self.0.chain.lock() = Some(DelegationChain::from_json(chain_json));

        let is_auth_retry = self.is_authenticated();
        #[cfg(feature = "tracing")]
        debug!("After fix attempt: is_authenticated() = {}", is_auth_retry);

        if !is_auth_retry {
            if let Ok(_principal) = self.identity().sender() {
                #[cfg(feature = "tracing")]
                debug!("Current principal: {}", _principal);
            }

            *self.0.identity.lock() =
                ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                    user_public_key.to_vec(),
                    Box::new(self.0.key.as_arc_identity()),
                    delegations.to_vec(),
                )));

            let _final_auth_check = self.is_authenticated();
            #[cfg(feature = "tracing")]
            debug!("Final check: is_authenticated() = {}", _final_auth_check);
        }
    }

    /// Creates an idle manager if one does not exist and idle detection is not disabled.
    fn maybe_create_idle_manager(&self) {
        let disable_idle = self
            .0
            .idle_options
            .as_ref()
            .and_then(|o| o.disable_idle)
            .unwrap_or(false);

        if self.0.idle_manager.lock().is_none() && !disable_idle {
            let idle_manager_options = self
                .0
                .idle_options
                .as_ref()
                .map(|o| o.idle_manager_options.clone());
            let new_idle_manager = IdleManager::new(idle_manager_options);
            *self.0.idle_manager.lock() = Some(new_idle_manager);

            if self.0.idle_manager.lock().is_some() {
                self.register_default_idle_callback();
            }
        }
    }

    /// Returns the identity of the user.
    pub fn identity(&self) -> Arc<dyn Identity> {
        self.0.identity.lock().as_arc_identity()
    }

    /// Returns the principal of the user.
    pub fn principal(&self) -> Result<Principal, String> {
        self.identity().sender()
    }

    /// Checks if the user is authenticated.
    pub fn is_authenticated(&self) -> bool {
        let is_not_anonymous = self
            .identity()
            .sender()
            .map(|s| s != Principal::anonymous())
            .unwrap_or(false);

        let is_valid_chain = self
            .0
            .chain
            .lock()
            .as_ref()
            .is_some_and(|c| c.is_delegation_valid(None));

        is_not_anonymous && is_valid_chain
    }

    /// Logs the user in with default options.
    pub fn login(&self) {
        self.login_with_options(AuthClientLoginOptions::default());
    }

    /// Logs the user in with the provided options.
    pub fn login_with_options(&self, options: AuthClientLoginOptions) {
        ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());

        let identity_provider_url = match Self::create_idp_url(&options) {
            Some(url) => url,
            None => return,
        };

        let idp_window = match Self::open_idp_window(&identity_provider_url, &options) {
            Some(window) => window,
            None => return,
        };

        let abort_handle = Self::spawn_interruption_check(&idp_window, &options);

        let _message_handler =
            self.get_event_handler(idp_window.clone(), identity_provider_url, options);

        let active_login = ActiveLogin {
            idp_window,
            _message_handler,
            interruption_check_abort_handle: abort_handle,
        };

        ACTIVE_LOGIN.with(|cell| *cell.borrow_mut() = Some(active_login));
    }

    /// Creates the identity provider URL.
    fn create_idp_url(options: &AuthClientLoginOptions) -> Option<web_sys::Url> {
        let identity_provider_url = match options.identity_provider {
            Some(ref url) => url as &str,
            None => IDENTITY_PROVIDER_DEFAULT,
        };

        match web_sys::Url::new(identity_provider_url) {
            Ok(url) => {
                url.set_hash(IDENTITY_PROVIDER_ENDPOINT);
                Some(url)
            }
            Err(_err) => {
                #[cfg(feature = "tracing")]
                {
                    use wasm_bindgen::convert::TryFromJsValue;
                    match String::try_from_js_value(_err) {
                        Ok(msg) => error!("Failed to create URL: {}", msg),
                        Err(_) => error!("Failed to create URL"),
                    };
                }
                None
            }
        }
    }

    /// Opens the identity provider window.
    fn open_idp_window(
        url: &web_sys::Url,
        options: &AuthClientLoginOptions,
    ) -> Option<web_sys::Window> {
        match window().open_with_url_and_target_and_features(
            &url.href(),
            "idpWindow",
            options.window_opener_features.as_deref().unwrap_or(""),
        ) {
            Ok(Some(window_handle)) => Some(window_handle),
            Ok(None) => {
                let error_message = "Failed to open IdP window. Check popup blocker.".to_string();
                if let Some(cb) = &options.on_error {
                    cb.0.lock()(Some(error_message.clone()));
                }
                None
            }
            Err(e) => {
                let error_message = format!("Error opening IdP window: {:?}", e);
                if let Some(cb) = &options.on_error {
                    cb.0.lock()(Some(error_message.clone()));
                }
                None
            }
        }
    }

    /// Spawns a task to check for user interruption.
    fn spawn_interruption_check(
        idp_window: &web_sys::Window,
        options: &AuthClientLoginOptions,
    ) -> AbortHandle {
        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        let interruption_check_task = {
            let idp_window_clone = idp_window.clone();
            let on_error_clone = options.on_error.clone();

            async move {
                gloo_timers::future::sleep(Duration::from_secs(1)).await;
                loop {
                    if idp_window_clone.closed().unwrap_or(true) {
                        let error_message = ERROR_USER_INTERRUPT.to_string();
                        if let Some(on_error) = on_error_clone {
                            on_error.0.lock()(Some(error_message.clone()));
                        }
                        let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());
                        break;
                    }
                    gloo_timers::future::sleep(INTERRUPT_CHECK_INTERVAL).await;
                }
            }
        };

        let abortable_task = Abortable::new(interruption_check_task, abort_registration);
        spawn_local(async {
            let _ = abortable_task.await;
        });

        abort_handle
    }

    /// Returns an event handler for the login process.
    fn get_event_handler(
        &self,
        idp_window: web_sys::Window,
        identity_provider_url: web_sys::Url,
        options: AuthClientLoginOptions,
    ) -> EventListener {
        let client = self.clone();

        let callback = move |event: &web_sys::Event| {
            let event = match event.dyn_ref::<MessageEvent>() {
                Some(event) => event,
                None => return,
            };

            if event.origin() != identity_provider_url.origin() {
                return;
            }

            let message = from_value::<IdentityServiceResponseMessage>(event.data())
                .map_err(|e| e.to_string());

            let max_time_to_live = options
                .max_time_to_live
                .unwrap_or(Self::DEFAULT_TIME_TO_LIVE);

            let handle_error_wrapper = |error: String| {
                #[cfg(feature = "tracing")]
                error!("AuthClient login failed in event handler: {}", &error);
                let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());
                if let Some(on_error_cb) = options.clone().on_error {
                    on_error_cb.0.lock()(Some(error.clone()));
                }
            };

            match message.and_then(|m| m.kind()) {
                Ok(kind) => match kind {
                    IdentityServiceResponseKind::Ready => {
                        client.handle_ready_response(
                            &idp_window,
                            &identity_provider_url,
                            &options,
                            max_time_to_live,
                            &handle_error_wrapper,
                        );
                    }
                    IdentityServiceResponseKind::AuthSuccess(response) => {
                        client.handle_auth_success_response(response, &options);
                    }
                    IdentityServiceResponseKind::AuthFailure(error_message) => {
                        handle_error_wrapper(error_message);
                    }
                },
                Err(e) => {
                    handle_error_wrapper(e);
                }
            }
        };

        EventListener::new(&window(), "message", callback)
    }

    /// Handles the `Ready` message from the identity provider.
    fn handle_ready_response(
        &self,
        idp_window: &web_sys::Window,
        identity_provider_url: &web_sys::Url,
        options: &AuthClientLoginOptions,
        max_time_to_live: u64,
        handle_error_wrapper: &dyn Fn(String),
    ) {
        use web_sys::js_sys::{Reflect, Uint8Array};

        let request = InternetIdentityAuthRequest {
            kind: "authorize-client".to_string(),
            session_public_key: self.0.key.public_key().expect("Failed to get public key"),
            max_time_to_live: Some(max_time_to_live),
            allow_pin_authentication: options.allow_pin_authentication,
            derivation_origin: options.derivation_origin.clone(),
        };
        let request_js_value = match JsValue::from_serde(&request) {
            Ok(value) => value,
            Err(err) => {
                handle_error_wrapper(format!("Failed to serialize request: {}", err));
                return;
            }
        };

        let session_public_key_js = Uint8Array::from(&request.session_public_key[..]).into();
        if Reflect::set(
            &request_js_value,
            &JsValue::from_str("sessionPublicKey"),
            &session_public_key_js,
        )
        .is_err()
        {
            handle_error_wrapper("Failed to set sessionPublicKey on request".to_string());
            return;
        }

        if let Some(custom_values) = options.custom_values.clone() {
            Self::set_custom_values(&request_js_value, custom_values, handle_error_wrapper);
        }

        if idp_window
            .post_message(&request_js_value, &identity_provider_url.origin())
            .is_err()
        {
            handle_error_wrapper("Failed to post message to IdP window".to_string());
        }
    }

    /// Sets custom values on the request object.
    fn set_custom_values(
        request_js_value: &JsValue,
        custom_values: serde_json::Map<String, serde_json::Value>,
        handle_error_wrapper: &dyn Fn(String),
    ) {
        for (k, v) in custom_values.into_iter() {
            match JsValue::from_serde(&v) {
                Ok(value) => {
                    if web_sys::js_sys::Reflect::set(
                        request_js_value,
                        &JsValue::from_str(&k),
                        &value,
                    )
                    .is_err()
                    {
                        handle_error_wrapper(format!("Failed to set custom value '{}'", k));
                    }
                }
                Err(err) => {
                    handle_error_wrapper(format!(
                        "Failed to serialize custom value '{}': {}",
                        k, err
                    ));
                }
            }
        }
    }

    /// Handles the `AuthResponseSuccess` message from the identity provider.
    fn handle_auth_success_response(
        &self,
        response: AuthResponseSuccess,
        options: &AuthClientLoginOptions,
    ) {
        let client_clone = self.clone();
        let on_success = options.on_success.clone();
        let on_error = options.on_error.clone();
        spawn_local(async move {
            if let Err(e) = client_clone.handle_success(response, on_success).await {
                #[cfg(feature = "tracing")]
                error!("Error during handle_success: {}", e);
                if let Some(on_error_cb) = on_error {
                    on_error_cb.0.lock()(Some(format!(
                        "Error processing successful login: {:?}",
                        e
                    )));
                }
            }
        });
    }

    /// Logs out the user and clears the stored identity.
    async fn logout_core(
        identity: Arc<Mutex<ArcIdentity>>,
        storage: &mut dyn AuthClientStorage,
        chain: Arc<Mutex<Option<DelegationChain>>>,
        return_to: Option<Location>,
    ) {
        if let Err(_e) = Self::delete_storage(storage).await {
            #[cfg(feature = "tracing")]
            error!("Failed to delete storage: {}", _e);
        }

        // Reset this auth client to a non-authenticated state.
        *identity.lock() = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
        chain.lock().take();

        if let Some(location) = return_to {
            Self::redirect_user(location);
        }
    }

    /// Handles redirecting the user after logout.
    fn redirect_user(location: Location) {
        let href = match location.href() {
            Ok(href) => href,
            Err(_) => {
                #[cfg(feature = "tracing")]
                error!("Could not get href from return_to location");
                return;
            }
        };

        let history_redirect_success = window()
            .history()
            .and_then(|history| history.push_state_with_url(&JsValue::null(), "", Some(&href)))
            .is_ok();

        if history_redirect_success {
            return;
        }

        // Fallback to assigning location.href
        if window().location().set_href(&href).is_err() {
            #[cfg(feature = "tracing")]
            error!("Failed to set href during logout");
        }
    }

    /// Log the user out.
    /// If a return URL is provided, the user will be redirected to that URL after logging out.
    pub async fn logout(&self, return_to: Option<Location>) {
        if let Some(idle_manager) = self.0.idle_manager.lock().take() {
            drop(idle_manager);
        }

        let mut storage_lock = self.0.storage.lock().await;
        let storage_ref: &mut dyn AuthClientStorage = &mut **storage_lock;
        Self::logout_core(
            self.0.identity.clone(),
            storage_ref,
            self.0.chain.clone(),
            return_to,
        )
        .await;
    }

    /// Deletes the stored keys from the provided storage.
    async fn delete_storage(
        storage: &mut dyn AuthClientStorage,
    ) -> Result<(), crate::storage::StorageError> {
        storage.remove(KEY_STORAGE_KEY).await?;
        storage.remove(KEY_STORAGE_DELEGATION).await?;
        storage.remove(KEY_VECTOR).await?;
        Ok(())
    }
}

/// Builder for the [`AuthClient`].
#[derive(Default)]
pub struct AuthClientBuilder {
    identity: Option<ArcIdentity>,
    storage: Option<Box<dyn AuthClientStorage>>,
    key_type: Option<BaseKeyType>,
    idle_options: Option<IdleOptions>,
}

impl AuthClientBuilder {
    /// Creates a new [`AuthClientBuilder`].
    fn new() -> Self {
        Self::default()
    }

    /// An optional identity to use as the base. If not provided, an `Ed25519` key pair will be used.
    pub fn identity(mut self, identity: ArcIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Optional storage with get, set, and remove methods. Currentry only `LocalStorage` is supported.
    pub fn storage<S>(mut self, storage: S) -> Self
    where
        S: AuthClientStorage + 'static,
    {
        self.storage = Some(Box::new(storage));
        self
    }

    /// The type of key to use for the base key. If not provided, `Ed25519` will be used by default.
    pub fn key_type(mut self, key_type: BaseKeyType) -> Self {
        self.key_type = Some(key_type);
        self
    }

    /// Options for handling idle timeouts. If not provided, default options will be used.
    pub fn idle_options(mut self, idle_options: IdleOptions) -> Self {
        self.idle_options = Some(idle_options);
        self
    }

    // --- Methods to configure IdleOptions directly on the builder ---

    /// Helper to get mutable access to idle_options, creating default if None.
    fn idle_options_mut(&mut self) -> &mut IdleOptions {
        self.idle_options.get_or_insert_with(IdleOptions::default)
    }

    /// If set to `true`, disables the idle timeout functionality.
    pub fn disable_idle(mut self, disable_idle: bool) -> Self {
        self.idle_options_mut().disable_idle = Some(disable_idle);
        self
    }

    /// If set to `true`, disables the default idle timeout callback.
    pub fn disable_default_idle_callback(mut self, disable_default_idle_callback: bool) -> Self {
        self.idle_options_mut().disable_default_idle_callback = Some(disable_default_idle_callback);
        self
    }

    /// Options for the [`IdleManager`] that handles idle timeouts.
    pub fn idle_manager_options(mut self, idle_manager_options: IdleManagerOptions) -> Self {
        self.idle_options_mut().idle_manager_options = idle_manager_options;
        self
    }

    /// Sets a callback to be executed when the system becomes idle.
    ///
    /// It is possible to set multiple callbacks.
    pub fn on_idle<F>(mut self, on_idle: F) -> Self
    where
        F: FnMut() + Send + 'static,
    {
        let options = self.idle_options_mut();
        options
            .idle_manager_options
            .on_idle
            .lock()
            .push(Box::new(on_idle));
        self
    }

    /// The duration of inactivity after which the system is considered idle.
    pub fn idle_timeout(mut self, idle_timeout: u32) -> Self {
        self.idle_options_mut().idle_manager_options.idle_timeout = Some(idle_timeout);
        self
    }

    /// A delay for debouncing scroll events.
    pub fn scroll_debounce(mut self, scroll_debounce: u32) -> Self {
        self.idle_options_mut().idle_manager_options.scroll_debounce = Some(scroll_debounce);
        self
    }

    /// A flag indicating whether to capture scroll events.
    pub fn capture_scroll(mut self, capture_scroll: bool) -> Self {
        self.idle_options_mut().idle_manager_options.capture_scroll = Some(capture_scroll);
        self
    }

    /// Builds a new [`AuthClient`].
    pub async fn build(self) -> Result<AuthClient, AuthClientError> {
        let options = AuthClientCreateOptions {
            identity: self.identity,
            storage: self.storage,
            key_type: self.key_type,
            idle_options: self.idle_options,
        };

        AuthClient::new_with_options(options).await
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[test]
    fn test_idle_options_builder() {
        let options = IdleOptions::builder()
            .disable_idle(true)
            .disable_default_idle_callback(true)
            .idle_manager_options(
                IdleManagerOptions::builder()
                    .on_idle(|| {})
                    .idle_timeout(1000)
                    .scroll_debounce(500)
                    .capture_scroll(true)
                    .build(),
            )
            .build();
        assert_eq!(options.disable_idle, Some(true));
        assert_eq!(options.disable_default_idle_callback, Some(true));
        assert_eq!(options.idle_manager_options.on_idle.lock().len(), 1);
        assert_eq!(options.idle_manager_options.idle_timeout, Some(1000));
        assert_eq!(options.idle_manager_options.scroll_debounce, Some(500));
        assert_eq!(options.idle_manager_options.capture_scroll, Some(true));
    }

    #[test]
    fn test_base_key_type_default() {
        assert_eq!(BaseKeyType::default(), BaseKeyType::Ed25519);
    }

    #[test]
    fn test_auth_client_login_options_builder() {
        let custom_values = vec![("key".to_string(), "value".into())]
            .into_iter()
            .collect();

        let options = AuthClientLoginOptions::builder()
            .allow_pin_authentication(true)
            .custom_values(custom_values)
            .on_error(|_| {})
            .on_success(|_| {})
            .build();

        assert_eq!(options.allow_pin_authentication, Some(true));
        assert!(options.on_error.is_some());
        assert!(options.on_success.is_some());
        assert!(options.custom_values.is_some());
    }

    #[wasm_bindgen_test]
    async fn test_auth_client_builder() {
        let mut rng = rand::thread_rng();
        let private_key = ed25519_dalek::SigningKey::generate(&mut rng).to_bytes();
        let identity = ArcIdentity::Ed25519(Arc::new(
            ic_agent::identity::BasicIdentity::from_raw_key(&private_key),
        ));

        let idle_options = IdleOptions::builder()
            .disable_idle(true)
            .disable_default_idle_callback(true)
            .idle_manager_options(
                IdleManagerOptions::builder()
                    .on_idle(|| {})
                    .idle_timeout(1000)
                    .scroll_debounce(500)
                    .capture_scroll(true)
                    .build(),
            )
            .build();

        let auth_client = AuthClient::builder()
            .identity(identity.clone())
            .idle_options(idle_options)
            .build()
            .await
            .unwrap();

        assert!(!auth_client.is_authenticated());
        assert_eq!(
            auth_client.identity().sender().unwrap(),
            identity.as_arc_identity().sender().unwrap()
        ); // Check if identity was set
    }
}
