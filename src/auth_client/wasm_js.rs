use crate::{
    api::{
        AuthResponseSuccess, IdentityServiceResponseKind, IdentityServiceResponseMessage,
        InternetIdentityAuthRequest,
    },
    idle_manager::{IdleManager, IdleManagerOptions},
    storage::{
        AuthClientStorage, AuthClientStorageType, KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY,
        KEY_VECTOR, StoredKey,
    },
    util::delegation_chain::DelegationChain,
};
use ed25519_dalek::SigningKey;
use futures::future::{AbortHandle, Abortable};
use gloo_events::EventListener;
use gloo_utils::{format::JsValueSerdeExt, window};
use ic_agent::{
    export::Principal,
    identity::{AnonymousIdentity, BasicIdentity, DelegatedIdentity, DelegationError, Identity},
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::from_value;
use std::{cell::RefCell, collections::HashMap, fmt, sync::Arc, time::Duration};
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    Location, MessageEvent,
    wasm_bindgen::{JsCast, JsValue},
};

type OnSuccess = Arc<Mutex<Box<dyn FnMut(AuthResponseSuccess) + Send>>>;
type OnError = Arc<Mutex<Box<dyn FnMut(Option<String>) + Send>>>;

const IDENTITY_PROVIDER_DEFAULT: &str = "https://identity.ic0.app";
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
                    let private_key = SigningKey::generate(&mut rng).to_bytes();
                    let _ = storage
                        .set(KEY_STORAGE_KEY, StoredKey::encode(&private_key))
                        .await;
                    Key::WithRaw(KeyWithRaw::new(private_key))
                }
            }
        };

        let mut identity = match &key {
            Key::WithRaw(k) => k.identity.clone(),
            Key::Identity(i) => i.clone(),
        };
        let mut chain: Arc<Mutex<Option<DelegationChain>>> = Arc::new(Mutex::new(None));

        // Now we definitely have a key, we can load delegation if it exists
        let chain_storage = storage.get(KEY_STORAGE_DELEGATION).await;

        if let Some(chain_storage) = chain_storage {
            match chain_storage {
                StoredKey::String(chain_storage) => {
                    // Try to load the delegation chain
                    let chain_result = DelegationChain::from_json(&chain_storage);
                    chain = Arc::new(Mutex::new(Some(chain_result)));

                    // First, extract the needed data from the lock without holding it across await
                    let delegation_data = {
                        let guard = chain.lock();
                        if let Some(chain_inner) = guard.as_ref() {
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
                                identity = ArcIdentity::Delegated(Arc::new(
                                    DelegatedIdentity::new_unchecked(
                                        public_key,
                                        Box::new(key.clone().as_arc_identity()),
                                        delegations,
                                    ),
                                ));
                            }
                        }
                        None => {
                            // Need to delete storage - delegation chain is invalid
                            #[cfg(feature = "tracing")]
                            info!(
                                "Found invalid delegation chain in storage - clearing credentials"
                            );
                            Self::delete_storage(&mut storage).await;

                            // Reset to anonymous identity
                            identity = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
                            chain = Arc::new(Mutex::new(None));
                        }
                    }
                }
            }
        }

        let mut idle_manager: Option<IdleManager> = None;
        if !options
            .idle_options
            .as_ref()
            .and_then(|o| o.disable_idle)
            .unwrap_or(false)
            && (chain.lock().is_some() || options_identity_is_some)
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
            chain,
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
                .set(KEY_STORAGE_KEY, StoredKey::encode(key.raw_key()))
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
            .set(KEY_STORAGE_DELEGATION, chain_json.clone())
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
            on_success_cb.lock()(message);
        }

        Ok(())
    }

    /// Returns the identity of the user.
    pub fn identity(&self) -> Arc<dyn Identity> {
        self.0.identity.lock().as_arc_identity()
    }

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
        let identity_provider_url: web_sys::Url =
            options.identity_provider.clone().unwrap_or_else(|| {
                match web_sys::Url::new(IDENTITY_PROVIDER_DEFAULT) {
                    Ok(url) => url,
                    Err(_) => unreachable!(),
                }
            });

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
                if let Some(on_error) = options.on_error {
                    on_error.lock()(Some(
                        "Failed to open IdP window. Check popup blocker.".to_string(),
                    ));
                }
                return;
            }
            Err(e) => {
                // Other error during window opening
                let error_message = format!("Error opening IdP window: {:?}", e);
                if let Some(on_error) = options.on_error {
                    on_error.lock()(Some(error_message));
                }
                return;
            }
        };

        let (abort_handle, abort_registration) = AbortHandle::new_pair();

        // Task to check for user interruption (closing the window).
        let interruption_check_task = {
            let idp_window_clone = idp_window.clone();
            let on_error_clone = options.on_error.clone();

            async move {
                // Give the authentication process a moment to start before checking for interruptions
                gloo_timers::future::sleep(Duration::from_secs(1)).await;

                loop {
                    if idp_window_clone.closed().unwrap_or(true) {
                        // Window is closed. This is a user interrupt.
                        if let Some(on_error) = on_error_clone {
                            on_error.lock()(Some(ERROR_USER_INTERRUPT.to_string()));
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
                spawn_local(async move {
                    #[cfg(feature = "tracing")]
                    error!("AuthClient login failed in event handler: {}", error);

                    // Take and drop the ActiveLogin struct, which handles all resource cleanup.
                    let _ = ACTIVE_LOGIN.with(|cell| cell.borrow_mut().take());

                    // Call the error callback
                    if let Some(on_error_cb) = on_error {
                        on_error_cb.lock()(Some(error));
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
                            derivation_origin: options
                                .derivation_origin
                                .clone()
                                .map(|d| d.to_string().into()),
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
                            for (k, v) in custom_values {
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
                        let on_error = options.on_error.clone();
                        spawn_local(async move {
                            if let Err(e) = client_clone.handle_success(response, on_success).await
                            {
                                // Handle potential errors from handle_success itself
                                #[cfg(feature = "tracing")]
                                error!("Error during handle_success: {}", e);
                                // Optionally call on_error here as well
                                if let Some(on_error_cb) = on_error {
                                    on_error_cb.lock()(Some(format!(
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
            } else {
                #[cfg(feature = "tracing")]
                error!("Failed to get href from return_to location during logout");
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

    /// A callback function to be executed when the system becomes idle.
    /// Note: This replaces any existing callbacks. Use `add_on_idle` for multiple.
    pub fn on_idle(mut self, on_idle: fn()) -> Self {
        self.idle_options_mut().idle_manager_options.on_idle = Arc::new(Mutex::new(vec![
            Box::new(on_idle) as Box<dyn FnMut() + Send>,
        ]));
        self
    }

    /// Adds a callback function to be executed when the system becomes idle.
    pub fn add_on_idle<F>(mut self, on_idle: F) -> Self
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

#[derive(Clone, Debug)]
pub struct KeyWithRaw {
    key: [u8; 32],
    identity: ArcIdentity,
}

impl KeyWithRaw {
    pub fn new(raw_key: [u8; 32]) -> Self {
        KeyWithRaw {
            key: raw_key,
            identity: ArcIdentity::Ed25519(Arc::new(BasicIdentity::from_raw_key(&raw_key))),
        }
    }

    pub fn raw_key(&self) -> &[u8; 32] {
        &self.key
    }
}

#[derive(Clone, Debug)]
pub enum Key {
    WithRaw(KeyWithRaw),
    Identity(ArcIdentity),
}

impl Key {
    pub fn as_arc_identity(&self) -> Arc<dyn Identity> {
        match self {
            Key::WithRaw(key) => key.identity.as_arc_identity(),
            Key::Identity(identity) => identity.as_arc_identity(),
        }
    }

    pub fn public_key(&self) -> Option<Vec<u8>> {
        match self {
            Key::WithRaw(key) => key.identity.public_key(),
            Key::Identity(identity) => identity.public_key(),
        }
    }
}

impl From<Key> for ArcIdentity {
    fn from(key: Key) -> Self {
        match key {
            Key::WithRaw(key) => key.identity,
            Key::Identity(identity) => identity,
        }
    }
}

impl From<ArcIdentity> for Key {
    fn from(identity: ArcIdentity) -> Self {
        Key::Identity(identity)
    }
}

#[derive(Clone)]
pub enum ArcIdentity {
    Anonymous(Arc<AnonymousIdentity>),
    Ed25519(Arc<BasicIdentity>),
    Delegated(Arc<DelegatedIdentity>),
}

impl Default for ArcIdentity {
    fn default() -> Self {
        ArcIdentity::Anonymous(Arc::new(AnonymousIdentity))
    }
}

impl fmt::Debug for ArcIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArcIdentity::Anonymous(_) => write!(f, "ArcIdentity::Anonymous"),
            ArcIdentity::Ed25519(_) => write!(f, "ArcIdentity::Ed25519"),
            ArcIdentity::Delegated(_) => write!(f, "ArcIdentity::Delegated"),
        }
    }
}

impl ArcIdentity {
    fn as_arc_identity(&self) -> Arc<dyn Identity> {
        match self {
            ArcIdentity::Anonymous(id) => id.clone(),
            ArcIdentity::Ed25519(id) => id.clone(),
            ArcIdentity::Delegated(id) => id.clone(),
        }
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        match self {
            ArcIdentity::Anonymous(id) => id.public_key(),
            ArcIdentity::Ed25519(id) => id.public_key(),
            ArcIdentity::Delegated(id) => id.public_key(),
        }
    }
}

impl From<AnonymousIdentity> for ArcIdentity {
    fn from(identity: AnonymousIdentity) -> Self {
        ArcIdentity::Anonymous(Arc::new(identity))
    }
}

impl From<BasicIdentity> for ArcIdentity {
    fn from(identity: BasicIdentity) -> Self {
        ArcIdentity::Ed25519(Arc::new(identity))
    }
}

impl From<DelegatedIdentity> for ArcIdentity {
    fn from(identity: DelegatedIdentity) -> Self {
        ArcIdentity::Delegated(Arc::new(identity))
    }
}

/// Options for the [`AuthClient::login_with_options`].
#[derive(Clone, Default)]
pub struct AuthClientLoginOptions {
    /// The URL of the identity provider.
    identity_provider: Option<web_sys::Url>,

    /// Expiration of the authentication in nanoseconds.
    max_time_to_live: Option<u64>,

    /// If present, indicates whether or not the Identity Provider should allow the user to authenticate and/or register using a temporary key/PIN identity.
    ///
    /// Authenticating dapps may want to prevent users from using Temporary keys/PIN identities because Temporary keys/PIN identities are less secure than Passkeys (webauthn credentials) and because Temporary keys/PIN identities generally only live in a browser database (which may get cleared by the browser/OS).
    allow_pin_authentication: Option<bool>,

    /// Origin for Identity Provider to use while generating the delegated identity. For II, the derivation origin must authorize this origin by setting a record at `<derivation-origin>/.well-known/ii-alternative-origins`.
    ///
    /// See: <https://github.com/dfinity/internet-identity/blob/main/docs/ii-spec.mdx#alternative-frontend-origins>
    derivation_origin: Option<web_sys::Url>,

    /// Auth Window feature config string.
    ///
    /// # Example
    /// ```ignore
    /// toolbar=0,location=0,menubar=0,width=500,height=500,left=100,top=100
    /// ```
    window_opener_features: Option<String>,

    /// Callback once login has completed.
    on_success: Option<OnSuccess>,

    /// Callback in case authentication fails.
    on_error: Option<OnError>,

    /// Extra values to be passed in the login request during the authorize-ready phase.
    custom_values: Option<HashMap<String, serde_json::Value>>,
}

impl AuthClientLoginOptions {
    /// Creates a new [`AuthClientLoginOptionsBuilder`].
    pub fn builder() -> AuthClientLoginOptionsBuilder {
        AuthClientLoginOptionsBuilder::new()
    }
}

/// Builder for the [`AuthClientLoginOptions`].
pub struct AuthClientLoginOptionsBuilder {
    identity_provider: Option<web_sys::Url>,
    max_time_to_live: Option<u64>,
    allow_pin_authentication: Option<bool>,
    derivation_origin: Option<web_sys::Url>,
    window_opener_features: Option<String>,
    on_success: Option<Box<dyn FnMut(AuthResponseSuccess) + Send>>,
    on_error: Option<Box<dyn FnMut(Option<String>) + Send>>,
    custom_values: Option<HashMap<String, serde_json::Value>>,
}

impl AuthClientLoginOptionsBuilder {
    fn new() -> Self {
        Self {
            identity_provider: None,
            max_time_to_live: None,
            allow_pin_authentication: None,
            derivation_origin: None,
            window_opener_features: None,
            on_success: None,
            on_error: None,
            custom_values: None,
        }
    }

    /// The URL of the identity provider.
    pub fn identity_provider(mut self, identity_provider: web_sys::Url) -> Self {
        self.identity_provider = Some(identity_provider);
        self
    }

    /// Expiration of the authentication in nanoseconds.
    pub fn max_time_to_live(mut self, max_time_to_live: u64) -> Self {
        self.max_time_to_live = Some(max_time_to_live);
        self
    }

    /// If present, indicates whether or not the Identity Provider should allow the user to authenticate and/or register using a temporary key/PIN identity.
    ///
    /// Authenticating dapps may want to prevent users from using Temporary keys/PIN identities because Temporary keys/PIN identities are less secure than Passkeys (webauthn credentials) and because Temporary keys/PIN identities generally only live in a browser database (which may get cleared by the browser/OS).
    pub fn allow_pin_authentication(mut self, allow_pin_authentication: bool) -> Self {
        self.allow_pin_authentication = Some(allow_pin_authentication);
        self
    }

    /// Origin for Identity Provider to use while generating the delegated identity. For II, the derivation origin must authorize this origin by setting a record at `<derivation-origin>/.well-known/ii-alternative-origins`.
    ///
    /// See: <https://github.com/dfinity/internet-identity/blob/main/docs/ii-spec.mdx#alternative-frontend-origins>
    pub fn derivation_origin(mut self, derivation_origin: web_sys::Url) -> Self {
        self.derivation_origin = Some(derivation_origin);
        self
    }

    /// Auth Window feature config string.
    ///
    /// # Example
    /// ```ignore
    /// toolbar=0,location=0,menubar=0,width=500,height=500,left=100,top=100
    /// ```
    pub fn window_opener_features(mut self, window_opener_features: String) -> Self {
        self.window_opener_features = Some(window_opener_features);
        self
    }

    /// Callback once login has completed.
    pub fn on_success<F>(mut self, on_success: F) -> Self
    where
        F: FnMut(AuthResponseSuccess) + Send + 'static,
    {
        self.on_success = Some(Box::new(on_success));
        self
    }

    /// Callback in case authentication fails.
    pub fn on_error<F>(mut self, on_error: F) -> Self
    where
        F: FnMut(Option<String>) + Send + 'static,
    {
        self.on_error = Some(Box::new(on_error));
        self
    }

    /// Extra values to be passed in the login request during the authorize-ready phase.
    pub fn custom_values(mut self, custom_values: HashMap<String, serde_json::Value>) -> Self {
        self.custom_values = Some(custom_values);
        self
    }

    /// Build the [`AuthClientLoginOptions`].
    pub fn build(self) -> AuthClientLoginOptions {
        AuthClientLoginOptions {
            identity_provider: self.identity_provider,
            max_time_to_live: self.max_time_to_live,
            allow_pin_authentication: self.allow_pin_authentication,
            derivation_origin: self.derivation_origin,
            window_opener_features: self.window_opener_features,
            on_success: self.on_success.map(|f| Arc::new(Mutex::new(f))),
            on_error: self.on_error.map(|f| Arc::new(Mutex::new(f))),
            custom_values: self.custom_values,
        }
    }
}

/// Options for creating a new [`AuthClient`].
#[derive(Default, Clone)]
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

/// Options for handling idle timeouts.
#[derive(Default, Clone, Debug)]
pub struct IdleOptions {
    /// If set to `true`, disables the idle timeout functionality.
    pub disable_idle: Option<bool>,
    /// If set to `true`, disables the default idle timeout callback.
    pub disable_default_idle_callback: Option<bool>,
    /// Options for the [`IdleManager`] that handles idle timeouts.
    pub idle_manager_options: IdleManagerOptions,
}

impl IdleOptions {
    /// Create a new [`IdleOptionsBuilder`].
    pub fn builder() -> IdleOptionsBuilder {
        IdleOptionsBuilder::new()
    }
}

/// Builder for [`IdleOptions`].
pub struct IdleOptionsBuilder {
    disable_idle: Option<bool>,
    disable_default_idle_callback: Option<bool>,
    idle_manager_options: IdleManagerOptions,
}

impl IdleOptionsBuilder {
    fn new() -> Self {
        Self {
            disable_idle: None,
            disable_default_idle_callback: None,
            idle_manager_options: IdleManagerOptions::default(),
        }
    }

    /// If set to `true`, disables the idle timeout functionality.
    pub fn disable_idle(mut self, disable_idle: bool) -> Self {
        self.disable_idle = Some(disable_idle);
        self
    }

    /// If set to `true`, disables the default idle timeout callback.
    pub fn disable_default_idle_callback(mut self, disable_default_idle_callback: bool) -> Self {
        self.disable_default_idle_callback = Some(disable_default_idle_callback);
        self
    }

    /// Options for the [`IdleManager`] that handles idle timeouts.
    pub fn idle_manager_options(mut self, idle_manager_options: IdleManagerOptions) -> Self {
        self.idle_manager_options = idle_manager_options;
        self
    }

    /// A callback function to be executed when the system becomes idle.
    /// Note: This replaces any existing callbacks. Use `add_on_idle` for multiple.
    pub fn on_idle(mut self, on_idle: fn()) -> Self {
        self.idle_manager_options.on_idle = Arc::new(Mutex::new(vec![
            Box::new(on_idle) as Box<dyn FnMut() + Send>
        ]));
        self
    }

    /// Adds a callback function to be executed when the system becomes idle.
    pub fn add_on_idle<F>(self, on_idle: F) -> Self
    where
        F: FnMut() + Send + 'static,
    {
        self.idle_manager_options
            .on_idle
            .lock()
            .push(Box::new(on_idle));
        self
    }

    /// The duration of inactivity after which the system is considered idle in milliseconds.
    pub fn idle_timeout(mut self, idle_timeout: u32) -> Self {
        self.idle_manager_options.idle_timeout = Some(idle_timeout);
        self
    }

    /// A delay for debouncing scroll events in milliseconds.
    pub fn scroll_debounce(mut self, scroll_debounce: u32) -> Self {
        self.idle_manager_options.scroll_debounce = Some(scroll_debounce);
        self
    }

    /// A flag indicating whether to capture scroll events.
    pub fn capture_scroll(mut self, capture_scroll: bool) -> Self {
        self.idle_manager_options.capture_scroll = Some(capture_scroll);
        self
    }

    /// Build the [`IdleOptions`].
    pub fn build(self) -> IdleOptions {
        IdleOptions {
            disable_idle: self.disable_idle,
            disable_default_idle_callback: self.disable_default_idle_callback,
            idle_manager_options: self.idle_manager_options,
        }
    }
}

/// Enum representing the type of base key used for the identity.
///
/// Currently, only Ed25519 is supported.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize, Default)]
pub enum BaseKeyType {
    /// Ed25519 base key type.
    #[default]
    Ed25519,
}

impl fmt::Display for BaseKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseKeyType::Ed25519 => write!(f, "{}", ED25519_KEY_LABEL),
        }
    }
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
        let private_key = SigningKey::generate(&mut rng).to_bytes();
        let identity = ArcIdentity::Ed25519(Arc::new(BasicIdentity::from_raw_key(&private_key)));

        let idle_options = IdleOptions::builder()
            .disable_idle(true)
            .disable_default_idle_callback(true)
            .on_idle(|| {})
            .idle_timeout(1000)
            .scroll_debounce(500)
            .capture_scroll(true)
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
