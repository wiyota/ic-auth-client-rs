use super::{
    ArcIdentity, AuthClientLoginOptions, BaseKeyType, IdleOptions, Key, KeyWithRaw, OnError,
    OnErrorAsync, OnSuccess, OnSuccessAsync,
};
use crate::{
    api::{
        AuthResponseSuccess, IdentityServiceResponseKind, IdentityServiceResponseMessage,
        InternetIdentityAuthRequest,
    },
    idle_manager::{IdleManager, IdleManagerOptions},
    storage::{
        KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY, KEY_VECTOR, StoredKey,
        async_storage::{AuthClientStorage, AuthClientStorageType},
    },
    util::delegation_chain::DelegationChain,
};
use futures::future::{AbortHandle, Abortable, BoxFuture};
use gloo_events::EventListener;
use gloo_utils::{format::JsValueSerdeExt, window};
use ic_agent::{
    export::Principal,
    identity::{AnonymousIdentity, DelegatedIdentity, DelegationError, Identity},
};
use parking_lot::Mutex;
use serde_wasm_bindgen::from_value;
use std::{cell::RefCell, future::Future, sync::Arc, time::Duration};
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    Location, MessageEvent,
    wasm_bindgen::{JsCast, JsValue},
};

const IDENTITY_PROVIDER_DEFAULT: &str = "https://identity.internetcomputer.org";
const IDENTITY_PROVIDER_ENDPOINT: &str = "#authorize";

const ED25519_KEY_LABEL: &str = "Ed25519";

const INTERRUPT_CHECK_INTERVAL: Duration = Duration::from_millis(500);
/// The error message when a user interrupts the authentication process.
pub const ERROR_USER_INTERRUPT: &str = "UserInterrupt";

thread_local! {
    static ACTIVE_LOGIN: RefCell<Option<ActiveLogin>> = RefCell::new(None);
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

#[derive(Debug)]
struct AuthClientInner {
    identity: Arc<Mutex<ArcIdentity>>,
    key: Key,
    storage: Mutex<AuthClientStorageType>,
    chain: Arc<Mutex<Option<DelegationChain>>>,
    idle_manager: Mutex<Option<IdleManager>>,
    idle_options: Option<IdleOptions>,
}

impl Drop for AuthClientInner {
    fn drop(&mut self) {
        ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());
    }
}

/// The tool for managing authentication and identity.
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
    pub async fn new() -> Result<Self, DelegationError> {
        Self::new_with_options(AuthClientCreateOptions::default()).await
    }

    /// Creates a new [`AuthClient`] with the provided options.
    pub async fn new_with_options(
        options: AuthClientCreateOptions,
    ) -> Result<Self, DelegationError> {
        let mut storage = options.storage.unwrap_or_default();
        let options_identity_is_some = options.identity.is_some();

        let key = match options.identity {
            Some(identity) => Key::Identity(identity),
            None => {
                if let Some(stored_key) = storage.get(KEY_STORAGE_KEY).await {
                    let private_key = stored_key.decode().map_err(|e| {
                        DelegationError::IdentityError(format!(
                            "Failed to decode private key: {}",
                            e
                        ))
                    })?;
                    Key::WithRaw(KeyWithRaw::new(private_key))
                } else {
                    let mut rng = rand::thread_rng();
                    let private_key = ed25519_dalek::SigningKey::generate(&mut rng).to_bytes();
                    let _ = storage
                        .set(
                            KEY_STORAGE_KEY,
                            StoredKey::String(StoredKey::encode(&private_key)),
                        )
                        .await;
                    Key::WithRaw(KeyWithRaw::new(private_key))
                }
            }
        };

        let mut identity = match &key {
            Key::WithRaw(k) => k.identity.clone(),
            Key::Identity(i) => i.clone(),
        };
        let mut chain: Option<DelegationChain> = None;

        // Now we definitely have a key, we can load delegation if it exists
        let chain_stored = storage.get(KEY_STORAGE_DELEGATION).await;

        if let Some(chain_stored) = chain_stored {
            let chain_stored = match chain_stored {
                StoredKey::String(chain_stored) => chain_stored,
                StoredKey::Raw(chain_stored) => StoredKey::encode(&chain_stored),
            };

            // Try to load the delegation chain
            let chain_result = DelegationChain::from_json(&chain_stored);
            chain = Some(chain_result);

            // First, extract the needed data from the lock without holding it across await
            let delegation_data = {
                if let Some(chain_inner) = chain.as_ref() {
                    if chain_inner.is_delegation_valid(None) {
                        // Extract the data we need while we have the lock
                        let public_key = chain_inner.public_key.clone();
                        let delegations = chain_inner.delegations.clone();
                        Some((public_key, delegations))
                    } else {
                        // Signal we need to delete storage if delegation is invalid
                        None
                    }
                } else {
                    // No chain data
                    Some((Vec::new(), Vec::new()))
                }
            };

            // Now use the extracted data without holding the lock
            match delegation_data {
                Some((public_key, delegations)) => {
                    if !public_key.is_empty() {
                        // Create the delegated identity using our key
                        identity =
                            ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                                public_key,
                                Box::new(key.as_arc_identity()),
                                delegations,
                            )));
                    }
                }
                None => {
                    // Need to delete storage - delegation chain is invalid
                    #[cfg(feature = "tracing")]
                    info!("Found invalid delegation chain in storage - clearing credentials");
                    Self::delete_storage(&mut storage).await;

                    // Reset to anonymous identity
                    identity = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
                    chain = None;
                }
            }
        }

        let mut idle_manager: Option<IdleManager> = None;
        if !options
            .idle_options
            .as_ref()
            .and_then(|o| o.disable_idle)
            .unwrap_or(false)
            && (chain.is_some() || options_identity_is_some)
        {
            let idle_manager_options: Option<IdleManagerOptions> = options
                .idle_options
                .as_ref()
                .map(|o| o.idle_manager_options.clone());
            idle_manager = Some(IdleManager::new(idle_manager_options));
        }

        Ok(Self(Arc::new(AuthClientInner {
            identity: Arc::new(Mutex::new(identity)),
            key,
            storage: Mutex::new(storage),
            chain: Arc::new(Mutex::new(chain)),
            idle_manager: Mutex::new(idle_manager),
            idle_options: options.idle_options,
        })))
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
        on_success_async: Option<OnSuccessAsync>,
    ) -> Result<(), DelegationError> {
        // Take and drop the ActiveLogin struct, which handles all resource cleanup.
        let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());

        let delegations = message.delegations.clone();
        let user_public_key = message.user_public_key.clone();

        // Create the delegation chain
        let delegation_chain = DelegationChain {
            delegations: delegations.clone(),
            public_key: user_public_key.clone(),
        };

        if let Key::WithRaw(key) = &self.0.key {
            let _ = self
                .0
                .storage
                .lock()
                .set(KEY_STORAGE_KEY, StoredKey::Raw(*key.raw_key()))
                .await;
        }

        // Serialize the chain to JSON
        let chain_json = delegation_chain.to_json();

        // First, save to storage immediately to ensure consistency between refreshes
        // This is critical for authentication persistence
        let _ = self
            .0
            .storage
            .lock()
            .set(
                KEY_STORAGE_DELEGATION,
                StoredKey::String(chain_json.clone()),
            )
            .await;

        // Now update the in-memory state
        {
            *self.0.chain.lock() = Some(delegation_chain.clone());
            *self.0.identity.lock() =
                ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                    user_public_key.clone(),
                    Box::new(self.0.key.as_arc_identity()),
                    delegations.clone(),
                )));
        }

        // Verify authentication state is correct
        let is_auth = self.is_authenticated();
        if !is_auth {
            // This is a severe issue - our in-memory state says we're authenticated,
            // but is_authenticated() disagrees
            #[cfg(feature = "tracing")]
            warn!("CRITICAL: is_authenticated() returned false after successful login");

            // Debug the state to understand why is_authenticated() is returning false
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

            // Try a more direct approach - recreate the delegation chain from JSON
            // This ensures our in-memory and storage states are completely in sync
            *self.0.chain.lock() = Some(DelegationChain::from_json(&chain_json));

            // Check again after our fix attempt
            let is_auth_retry = self.is_authenticated();
            #[cfg(feature = "tracing")]
            debug!("After fix attempt: is_authenticated() = {}", is_auth_retry);

            // If still failing, provide detailed debug information but DO NOT reload
            // Let's try to make it work without a reload
            if !is_auth_retry {
                if let Ok(_principal) = self.identity().sender() {
                    #[cfg(feature = "tracing")]
                    debug!("Current principal: {}", _principal);
                }

                // Attempt one final fix: completely reconstruct the delegated identity
                *self.0.identity.lock() =
                    ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                        user_public_key.clone(),
                        Box::new(self.0.key.as_arc_identity()),
                        delegations.clone(),
                    )));

                // Last check
                let _final_auth_check = self.is_authenticated();
                #[cfg(feature = "tracing")]
                debug!("Final check: is_authenticated() = {}", _final_auth_check);
            }
        }

        // create the idle manager on a successful login if we haven't disabled it
        // and it doesn't already exist.
        let disable_idle = match self.0.idle_options.as_ref() {
            Some(options) => options.disable_idle.unwrap_or(false),
            None => false,
        };
        if self.0.idle_manager.lock().is_none() && !disable_idle {
            let idle_manager_options = self
                .0
                .idle_options
                .as_ref()
                .map(|o| o.idle_manager_options.clone());
            let new_idle_manager = IdleManager::new(idle_manager_options);
            *self.0.idle_manager.lock() = Some(new_idle_manager);

            // Register default callback only if idle_manager was successfully created
            if self.0.idle_manager.lock().is_some() {
                self.register_default_idle_callback();
            }
        }

        // on_success should be the last thing to do to avoid consumers
        // interfering by navigating or refreshing the page
        if let Some(on_success_cb) = on_success {
            on_success_cb.0.lock()(message.clone());
        }
        if let Some(on_success_async_cb) = on_success_async {
            on_success_async_cb.0.lock()(message).await;
        }

        Ok(())
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
            .map_or(false, |c| c.is_delegation_valid(None));

        is_not_anonymous && is_valid_chain
    }

    /// Logs the user in with default options.
    pub fn login(&self) {
        self.login_with_options(AuthClientLoginOptions::default());
    }

    /// Logs the user in with the provided options.
    pub fn login_with_options(&self, options: AuthClientLoginOptions) {
        // If a login process is already active, drop it. This will trigger its Drop implementation,
        // cleaning up associated resources (closing window, aborting tasks, etc.).
        ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());

        // Create the URL of the IDP. (e.g. https://XXXX/#authorize)
        let identity_provider_url = match options.identity_provider {
            Some(ref url) => url as &str,
            None => IDENTITY_PROVIDER_DEFAULT,
        };

        let identity_provider_url = match web_sys::Url::new(identity_provider_url) {
            Ok(url) => url,
            Err(_err) => {
                #[cfg(feature = "tracing")]
                {
                    use wasm_bindgen::convert::TryFromJsValue;
                    match String::try_from_js_value(_err) {
                        Ok(msg) => error!("Failed to create URL: {}", msg),
                        Err(_) => error!("Failed to create URL"),
                    };
                }
                return;
            }
        };

        // Set the correct hash if it isn't already set.
        identity_provider_url.set_hash(IDENTITY_PROVIDER_ENDPOINT);

        // Open a new window with the IDP provider.
        let window_handle_result = window().open_with_url_and_target_and_features(
            &identity_provider_url.href(),
            "idpWindow",
            options.window_opener_features.as_deref().unwrap_or(""),
        );

        let idp_window = match window_handle_result {
            Ok(Some(window_handle)) => window_handle,
            Ok(None) => {
                // Window opening was blocked by the browser (e.g., popup blocker)
                let on_error = options.on_error.clone();
                let on_error_async = options.on_error_async.clone();
                let error_message = "Failed to open IdP window. Check popup blocker.".to_string();
                spawn_local(async move {
                    if let Some(cb) = on_error {
                        cb.0.lock()(Some(error_message.clone()));
                    }
                    if let Some(cb) = on_error_async {
                        cb.0.lock()(Some(error_message)).await;
                    }
                });
                return;
            }
            Err(e) => {
                // Other error during window opening
                let error_message = format!("Error opening IdP window: {:?}", e);
                let on_error = options.on_error.clone();
                let on_error_async = options.on_error_async.clone();
                spawn_local(async move {
                    if let Some(cb) = on_error {
                        cb.0.lock()(Some(error_message.clone()));
                    }
                    if let Some(cb) = on_error_async {
                        cb.0.lock()(Some(error_message)).await;
                    }
                });
                return;
            }
        };

        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        // Task to check for user interruption (closing the window).
        let interruption_check_task = {
            let idp_window_clone = idp_window.clone();
            let on_error_clone = options.on_error.clone();
            let on_error_async_clone = options.on_error_async.clone();

            async move {
                // Give the authentication process a moment to start before checking for interruptions
                gloo_timers::future::sleep(Duration::from_secs(1)).await;

                loop {
                    if idp_window_clone.closed().unwrap_or(true) {
                        // Window is closed. This is a user interrupt.
                        let error_message = ERROR_USER_INTERRUPT.to_string();
                        if let Some(on_error) = on_error_clone {
                            on_error.0.lock()(Some(error_message.clone()));
                        }
                        if let Some(on_error_async) = on_error_async_clone {
                            on_error_async.0.lock()(Some(error_message)).await;
                        }
                        // Clean up by taking the active_login from the client.
                        let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());
                        break;
                    }
                    gloo_timers::future::sleep(INTERRUPT_CHECK_INTERVAL).await;
                }
            }
        };

        let abortable_task = Abortable::new(interruption_check_task, abort_registration);
        spawn_local(async {
            // The task will be aborted if the AbortHandle is dropped or abort() is called.
            // We don't care about the result here.
            let _ = abortable_task.await;
        });

        // Add an event listener to handle responses.
        let _message_handler =
            self.get_event_handler(idp_window.clone(), identity_provider_url, options);

        let active_login = ActiveLogin {
            idp_window,
            _message_handler,
            interruption_check_abort_handle: abort_handle,
        };

        // Store the active login information.
        ACTIVE_LOGIN.with(|cell| *cell.borrow_mut() = Some(active_login));
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
                // Ignore any event that is not from the identity provider
                return;
            }

            let message = from_value::<IdentityServiceResponseMessage>(event.data())
                .map_err(|e| e.to_string());

            let max_time_to_live = options
                .max_time_to_live
                .unwrap_or(Self::DEFAULT_TIME_TO_LIVE);

            let handle_error_wrapper = |error: String| {
                let on_error = options.on_error.clone();
                let on_error_async = options.on_error_async.clone();
                spawn_local(async move {
                    #[cfg(feature = "tracing")]
                    error!("AuthClient login failed in event handler: {}", &error);

                    // Take and drop the ActiveLogin struct, which handles all resource cleanup.
                    let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());

                    // Call the error callback
                    if let Some(on_error_cb) = on_error {
                        on_error_cb.0.lock()(Some(error.clone()));
                    }
                    if let Some(on_error_async_cb) = on_error_async {
                        on_error_async_cb.0.lock()(Some(error)).await;
                    }
                });
            };

            match message.and_then(|m| m.kind()) {
                Ok(kind) => match kind {
                    IdentityServiceResponseKind::Ready => {
                        use web_sys::js_sys::{Reflect, Uint8Array};

                        let request = InternetIdentityAuthRequest {
                            kind: "authorize-client".to_string(),
                            session_public_key: client
                                .0
                                .key
                                .public_key()
                                .expect("Failed to get public key"),
                            max_time_to_live: Some(max_time_to_live),
                            allow_pin_authentication: options.allow_pin_authentication,
                            derivation_origin: options.derivation_origin.clone(),
                        };
                        let request_js_value = match JsValue::from_serde(&request) {
                            Ok(value) => value,
                            Err(err) => {
                                handle_error_wrapper(format!(
                                    "Failed to serialize request: {}",
                                    err
                                ));
                                return;
                            }
                        };

                        let session_public_key_js =
                            Uint8Array::from(&request.session_public_key[..]).into();
                        if Reflect::set(
                            &request_js_value,
                            &JsValue::from_str("sessionPublicKey"),
                            &session_public_key_js,
                        )
                        .is_err()
                        {
                            handle_error_wrapper(
                                "Failed to set sessionPublicKey on request".to_string(),
                            );
                            return;
                        }

                        if let Some(custom_values) = options.custom_values.clone() {
                            for (k, v) in custom_values.into_iter() {
                                match JsValue::from_serde(&v) {
                                    Ok(value) => {
                                        if Reflect::set(
                                            &request_js_value,
                                            &JsValue::from_str(&k),
                                            &value,
                                        )
                                        .is_err()
                                        {
                                            handle_error_wrapper(format!(
                                                "Failed to set custom value '{}'",
                                                k
                                            ));
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

                        if idp_window
                            .post_message(&request_js_value, &identity_provider_url.origin())
                            .is_err()
                        {
                            handle_error_wrapper(
                                "Failed to post message to IdP window".to_string(),
                            );
                        }
                    }
                    IdentityServiceResponseKind::AuthSuccess(response) => {
                        let client_clone = client.clone();
                        let on_success = options.on_success.clone();
                        let on_success_async = options.on_success_async.clone();
                        let on_error = options.on_error.clone();
                        spawn_local(async move {
                            if let Err(e) = client_clone
                                .handle_success(response, on_success, on_success_async)
                                .await
                            {
                                // Handle potential errors from handle_success itself
                                #[cfg(feature = "tracing")]
                                error!("Error during handle_success: {}", e);
                                // Optionally call on_error here as well
                                if let Some(on_error_cb) = on_error {
                                    on_error_cb.0.lock()(Some(format!(
                                        "Error processing successful login: {:?}",
                                        e
                                    )));
                                }
                            }
                        });
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

    /// Logs out the user and clears the stored identity.
    async fn logout_core<S: AuthClientStorage>(
        identity: Arc<Mutex<ArcIdentity>>,
        storage: &mut S,
        chain: Arc<Mutex<Option<DelegationChain>>>,
        return_to: Option<Location>,
    ) {
        Self::delete_storage(storage).await;

        // Reset this auth client to a non-authenticated state.
        *identity.lock() = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
        chain.lock().take();

        // If a return URL is provided, redirect the user to that URL.
        if let Some(return_to) = return_to {
            let window = window();
            let href_result = return_to.href();
            if let Ok(href) = href_result {
                if let Ok(history) = window.history() {
                    if history
                        .push_state_with_url(&JsValue::null(), "", Some(&href))
                        .is_err()
                        && window.location().set_href(&href).is_err()
                    {
                        #[cfg(feature = "tracing")]
                        error!("Failed to set href during logout");
                    }
                } else if window.location().set_href(&href).is_err() {
                    #[cfg(feature = "tracing")]
                    error!("Failed to set href during logout (no history)");
                }
            }
        }
    }

    /// Log the user out.
    /// If a return URL is provided, the user will be redirected to that URL after logging out.
    pub async fn logout(&self, return_to: Option<Location>) {
        if let Some(idle_manager) = self.0.idle_manager.lock().take() {
            drop(idle_manager);
        }

        let mut storage_lock = self.0.storage.lock();
        Self::logout_core(
            self.0.identity.clone(),
            &mut *storage_lock,
            self.0.chain.clone(),
            return_to,
        )
        .await;
    }

    /// Deletes the stored keys from the provided storage.
    async fn delete_storage<S>(storage: &mut S)
    where
        S: AuthClientStorage,
    {
        let _ = storage.remove(KEY_STORAGE_KEY).await;
        let _ = storage.remove(KEY_STORAGE_DELEGATION).await;
        let _ = storage.remove(KEY_VECTOR).await;
    }
}

/// Builder for the [`AuthClient`].
#[derive(Default)]
pub struct AuthClientBuilder {
    identity: Option<ArcIdentity>,
    storage: Option<AuthClientStorageType>,
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
    pub fn storage(mut self, storage: AuthClientStorageType) -> Self {
        self.storage = Some(storage);
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
    pub async fn build(self) -> Result<AuthClient, DelegationError> {
        let options = AuthClientCreateOptions {
            identity: self.identity,
            storage: self.storage,
            key_type: self.key_type,
            idle_options: self.idle_options,
        };

        AuthClient::new_with_options(options).await
    }
}

/// Options for creating a new [`AuthClient`].
#[derive(Default, Clone, bon::Builder)]
pub struct AuthClientCreateOptions {
    /// An optional identity to use as the base. If not provided, an `Ed25519` key pair will be used.
    pub identity: Option<ArcIdentity>,
    /// Optional storage with get, set, and remove methods. Currentry only `LocalStorage` is supported.
    pub storage: Option<AuthClientStorageType>,
    /// The type of key to use for the base key. If not provided, `Ed25519` will be used by default.
    pub key_type: Option<BaseKeyType>,
    /// Options for handling idle timeouts. If not provided, default options will be used.
    pub idle_options: Option<IdleOptions>,
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[test]
    fn test_idle_options_builder() {
        let options = IdleOptionsBuilder::new()
            .disable_idle(true)
            .disable_default_idle_callback(true)
            .on_idle(|| {})
            .idle_timeout(1000)
            .scroll_debounce(500)
            .capture_scroll(true)
            .build();
        assert_eq!(options.disable_idle, Some(true));
        assert_eq!(options.disable_default_idle_callback, Some(true));
        assert_eq!(options.idle_manager_options.on_idle.lock().len(), 1);
        assert_eq!(options.idle_manager_options.idle_timeout, Some(1000));
        assert_eq!(options.idle_manager_options.scroll_debounce, Some(500));
        assert_eq!(options.idle_manager_options.capture_scroll, Some(true));
    }

    #[test]
    fn test_base_key_type_display() {
        assert_eq!(BaseKeyType::Ed25519.to_string(), ED25519_KEY_LABEL);
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
