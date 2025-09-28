use crate::{
    ArcIdentity, AuthClientError,
    api::AuthResponseSuccess,
    idle_manager::{IdleManager, IdleManagerOptions},
    key::{BaseKeyType, Key, KeyWithRaw},
    option::{AuthClientLoginOptions, IdleOptions, native::NativeAuthClientCreateOptions},
    storage::{
        KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY, StoredKey,
        sync_storage::{AuthClientStorage, AuthClientStorageType, KeyringStorage},
    },
    util::{callback::OnSuccess, delegation_chain::DelegationChain},
};
use ed25519_dalek::SigningKey;
use futures::{channel::oneshot, executor::block_on};
use ic_agent::{
    export::Principal,
    identity::{AnonymousIdentity, DelegatedIdentity, DelegationError, Identity, SignedDelegation},
};
use parking_lot::Mutex;
use std::{sync::Arc, thread, time::Duration};
use tiny_http::{Response, Server};
use url::Url;

/// Errors that can occur during the login process.
///
/// This enum represents all the possible error conditions that may arise
/// when attempting to authenticate a user through the Internet Identity
/// authentication flow.
#[derive(Debug, thiserror::Error)]
pub enum NativeLoginError {
    /// No free ports are available on the local machine to start the callback server.
    #[error("No free ports available")]
    NoFreePort,
    /// An error occurred while starting or running the local HTTP server.
    #[error("Server error: {0}")]
    ServerError(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Failed to parse a URL during the authentication process.
    #[error("URL parse error: {0}")]
    UrlParseError(#[from] url::ParseError),
    /// Failed to open the user's default web browser for authentication.
    #[error("Failed to open browser: {0}")]
    BrowserOpenError(String),
    /// The server timed out while waiting for the authentication callback.
    #[error("Server receive timed out")]
    ServerTimeout,
    /// The server thread handling the authentication callback panicked.
    #[error("Server thread panicked")]
    ServerThreadPanicked,
    /// Failed to receive the delegation response through the internal message channel.
    #[error("Failed to receive delegation")]
    OneshotRecvError,
    /// Failed to deserialize the JSON response from the identity provider.
    #[error("JSON deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    /// An error occurred while processing the delegation chain.
    #[error("Delegation error: {0}")]
    DelegationError(#[from] DelegationError),
    /// The authentication callback was missing required delegation or error parameters.
    #[error("Missing delegation or error parameter in redirect")]
    MissingDelegationOrError,
    /// The callback server received a request to an unexpected URL path.
    #[error("Unexpected request path: {0}")]
    UnexpectedRequestPath(String),
    /// A custom error occurred during authentication.
    #[error("Custom error: {0}")]
    Custom(String),
}

#[derive(Debug)]
enum CallbackResult {
    Success(AuthResponseSuccess),
    Error(NativeLoginError),
}

#[derive(Debug)]
pub(super) struct AuthClientInner {
    pub identity: Arc<Mutex<ArcIdentity>>,
    pub key: Key,
    pub storage: Mutex<AuthClientStorageType>,
    pub chain: Arc<Mutex<Option<DelegationChain>>>,
    pub idle_manager: Mutex<Option<IdleManager>>,
    pub idle_options: Option<IdleOptions>,
}

/// The tool for managing authentication and identity.
///
/// It maintains the state of the user's identity and provides methods for authentication.
#[derive(Clone, Debug)]
pub struct NativeAuthClient(Arc<AuthClientInner>);

impl NativeAuthClient {
    /// Creates a new [`AuthClient`] with default options.
    pub fn new<T: Into<String>>(service_name: T) -> Result<Self, AuthClientError> {
        let options = NativeAuthClientCreateOptions::builder()
            .storage(AuthClientStorageType::Keyring(KeyringStorage::new(
                service_name.into(),
            )))
            .build();
        Self::new_with_options(options)
    }

    /// Creates a new key if one is not found in storage, otherwise loads the existing key.
    fn create_or_load_key(
        identity: Option<ArcIdentity>,
        storage: &mut AuthClientStorageType,
    ) -> Result<Key, AuthClientError> {
        match identity {
            Some(identity) => Ok(Key::Identity(identity)),
            None => match storage.get(KEY_STORAGE_KEY) {
                Ok(Some(stored_key)) => {
                    let private_key = stored_key.decode().map_err(|e| {
                        DelegationError::IdentityError(format!(
                            "Failed to decode private key: {}",
                            e
                        ))
                    })?;
                    Ok(Key::WithRaw(KeyWithRaw::new(private_key)))
                }
                Ok(None) => {
                    let mut rng = rand::thread_rng();
                    let private_key = SigningKey::generate(&mut rng).to_bytes();
                    storage.set(KEY_STORAGE_KEY, StoredKey::Raw(private_key))?;
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
    fn load_delegation_chain(
        storage: &mut AuthClientStorageType,
        key: &Key,
    ) -> (Option<DelegationChain>, ArcIdentity) {
        let mut identity = ArcIdentity::from(key.clone());
        let mut chain: Option<DelegationChain> = None;

        match storage.get(KEY_STORAGE_DELEGATION) {
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
                        let _ = Self::delete_storage_native(storage);
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

    /// Creates a new [`AuthClient`] with the provided options.
    pub fn new_with_options(
        options: NativeAuthClientCreateOptions,
    ) -> Result<Self, AuthClientError> {
        let mut storage = options.storage;
        let options_identity_is_some = options.identity.is_some();

        let key = Self::create_or_load_key(options.identity, &mut storage)?;

        let (chain, identity) = Self::load_delegation_chain(&mut storage, &key);

        let idle_manager =
            Self::create_idle_manager(&options.idle_options, &chain, options_identity_is_some);

        Ok(Self(Arc::new(AuthClientInner {
            identity: Arc::new(Mutex::new(identity)),
            key,
            storage: Mutex::new(storage),
            chain: Arc::new(Mutex::new(chain)),
            idle_manager: Mutex::new(idle_manager),
            idle_options: options.idle_options,
        })))
    }

    /// Registers the default idle callback, which logs the user out on idle.
    fn register_default_idle_callback_native(&self) {
        if let Some(options) = self.0.idle_options.as_ref() {
            if options.disable_default_idle_callback.unwrap_or_default() {
                return;
            }

            if options.idle_manager_options.on_idle.lock().is_empty() {
                if let Some(idle_manager) = self.0.idle_manager.lock().as_ref() {
                    let client = self.clone();
                    let callback = move || {
                        client.logout();
                    };
                    idle_manager.register_callback(callback);
                }
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

    /// Returns the idle manager if it exists.
    pub fn idle_manager(&self) -> Option<IdleManager> {
        self.0.idle_manager.lock().clone()
    }

    /// Handles a successful authentication response.
    fn handle_success(
        &self,
        message: AuthResponseSuccess,
        on_success: Option<OnSuccess>,
    ) -> Result<(), DelegationError> {
        let delegations = message.delegations.clone();
        let user_public_key = message.user_public_key.clone();

        let delegation_chain = DelegationChain {
            delegations: delegations.clone(),
            public_key: user_public_key.clone(),
        };

        self.update_storage_with_delegation(&delegation_chain);
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
    fn update_storage_with_delegation(&self, delegation_chain: &DelegationChain) {
        if let Key::WithRaw(key) = &self.0.key {
            if let Err(_e) = self
                .0
                .storage
                .lock()
                .set(KEY_STORAGE_KEY, StoredKey::Raw(*key.raw_key()))
            {
                #[cfg(feature = "tracing")]
                error!("Failed to store key: {}", _e);
            }
        }

        let chain_json = delegation_chain.to_json();
        if let Err(_e) = self.0.storage.lock().set(
            KEY_STORAGE_DELEGATION,
            StoredKey::String(chain_json.clone()),
        ) {
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
                self.register_default_idle_callback_native();
            }
        }
    }

    /// Handles the redirect from the identity provider.
    fn handle_get_redirect(request: tiny_http::Request, tx: oneshot::Sender<CallbackResult>) {
        let _ = tx.send(CallbackResult::Error(NativeLoginError::Custom(
            "Login window closed or redirect failed.".to_string(),
        )));
        let response = Response::from_string(
            "<h1>Login failed!</h1><p>Login window closed or redirect failed.</p>",
        )
        .with_header(
            "Content-Type: text/html"
                .parse::<tiny_http::Header>()
                .unwrap(),
        );
        let _ = request.respond(response);
    }

    /// Handles incoming POST requests with authentication data.
    fn handle_post_callback(mut request: tiny_http::Request, tx: oneshot::Sender<CallbackResult>) {
        let mut content = String::new();
        if let Err(e) = request.as_reader().read_to_string(&mut content) {
            let _ = tx.send(CallbackResult::Error(NativeLoginError::ServerError(
                Box::new(e),
            )));
            let _ = request
                .respond(Response::from_string("Error reading request body").with_status_code(500));
            return;
        }

        let json: serde_json::Value = match serde_json::from_str(&content) {
            Ok(json) => json,
            Err(e) => {
                let _ = tx.send(CallbackResult::Error(NativeLoginError::JsonError(e)));
                let _ = request.respond(
                    Response::from_string("Error parsing JSON body").with_status_code(400),
                );
                return;
            }
        };

        let response_type = json["type"].as_str();

        match response_type {
            Some("success") => {
                match serde_json::from_value::<AuthResponseSuccess>(json["data"].clone()) {
                    Ok(success_data) => {
                        let _ = tx.send(CallbackResult::Success(success_data));
                        let _ = request.respond(Response::from_string("OK").with_status_code(200));
                    }
                    Err(e) => {
                        let _ = tx.send(CallbackResult::Error(NativeLoginError::JsonError(e)));
                        let _ = request.respond(
                            Response::from_string("Error parsing success data")
                                .with_status_code(400),
                        );
                    }
                }
            }
            Some("error") => {
                let error_message = json["data"].as_str().unwrap_or("Unknown error").to_string();
                let _ = tx.send(CallbackResult::Error(NativeLoginError::Custom(
                    error_message,
                )));
                let _ = request.respond(Response::from_string("Error").with_status_code(200));
            }
            _ => {
                let _ = tx.send(CallbackResult::Error(NativeLoginError::Custom(
                    "Invalid response type".to_string(),
                )));
                let _ = request
                    .respond(Response::from_string("Invalid response type").with_status_code(400));
            }
        }
    }

    /// Finishes the login process after the delegation has been received.
    async fn finish_login(
        &self,
        rx: oneshot::Receiver<CallbackResult>,
        on_success: Option<OnSuccess>,
    ) -> Result<(), NativeLoginError> {
        let callback_result = rx.await.map_err(|_| NativeLoginError::OneshotRecvError)?;

        match callback_result {
            CallbackResult::Success(auth_success) => {
                match self.handle_success(auth_success, on_success) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(NativeLoginError::DelegationError(e)),
                }
            }
            CallbackResult::Error(e) => Err(e),
        }
    }

    /// Logs the user in by opening a browser window to the identity provider.
    pub fn login<T: AsRef<str> + Send + 'static>(
        &self,
        ii_url: T,
        options: AuthClientLoginOptions,
    ) {
        let client = self.clone();
        let ii_url = ii_url.as_ref().to_string();

        thread::spawn(move || {
            let on_error = options.on_error.clone();
            if let Err(e) = block_on(client.login_task(ii_url, options)) {
                if let Some(on_error) = on_error {
                    on_error.0.lock()(Some(e.to_string()));
                }
            }
        });
    }

    fn start_http_server(server: Server, tx: oneshot::Sender<CallbackResult>, timeout: Duration) {
        thread::spawn(move || {
            let start_time = std::time::Instant::now();

            while start_time.elapsed() < timeout {
                let request = match server.recv_timeout(Duration::from_millis(500)) {
                    Ok(Some(request)) => request,
                    Ok(None) => continue,
                    Err(e) => {
                        #[cfg(feature = "tracing")]
                        error!("Server error while receiving request: {}", e);
                        let _ = tx.send(CallbackResult::Error(NativeLoginError::ServerError(
                            Box::new(e),
                        )));
                        return;
                    }
                };

                let handler: Option<fn(tiny_http::Request, oneshot::Sender<CallbackResult>)> =
                    if request.method() == &tiny_http::Method::Post
                        && request.url().starts_with("/auth-callback")
                    {
                        Some(Self::handle_post_callback)
                    } else if request.method() == &tiny_http::Method::Get {
                        Some(Self::handle_get_redirect)
                    } else {
                        None
                    };

                if let Some(handler_fn) = handler {
                    handler_fn(request, tx);
                    return;
                }

                // Fallback for any other request.
                let response = Response::from_string("").with_status_code(204);
                if let Err(e) = request.respond(response) {
                    #[cfg(feature = "tracing")]
                    error!("Failed to respond to unexpected request: {}", e);
                }
            }

            let _ = tx.send(CallbackResult::Error(NativeLoginError::ServerTimeout));
        });
    }

    async fn login_task<T: AsRef<str>>(
        &self,
        ii_url: T,
        options: AuthClientLoginOptions,
    ) -> Result<(), NativeLoginError> {
        let port = portpicker::pick_unused_port().ok_or(NativeLoginError::NoFreePort)?;
        let redirect_uri = format!("http://127.0.0.1:{}/auth-callback", port);

        let server = Server::http(format!("127.0.0.1:{}", port))?;
        let (tx, rx) = oneshot::channel::<CallbackResult>();

        let public_key_hex = hex::encode(self.0.key.public_key().unwrap());

        let mut url = Url::parse(ii_url.as_ref()).map_err(NativeLoginError::UrlParseError)?;
        Self::set_query_params(&mut url, &options, &redirect_uri, &public_key_hex);

        webbrowser::open(url.as_str())
            .map_err(|e| NativeLoginError::BrowserOpenError(e.to_string()))?;

        let timeout = options.timeout.unwrap_or(Duration::from_secs(300));
        Self::start_http_server(server, tx, timeout);

        self.finish_login(rx, options.on_success).await
    }

    /// Sets the query parameters for the identity provider URL.
    fn set_query_params(
        url: &mut Url,
        options: &AuthClientLoginOptions,
        redirect_uri: &str,
        public_key_hex: &str,
    ) {
        let mut query_pairs = url.query_pairs_mut();
        query_pairs
            .append_pair("redirectUri", redirect_uri)
            .append_pair("pubkey", public_key_hex);

        if let Some(ref identity_provider) = options.identity_provider {
            query_pairs.append_pair("identityProvider", identity_provider);
        }

        if let Some(ref max_time_to_live) = options.max_time_to_live {
            query_pairs.append_pair("maxTimeToLive", &max_time_to_live.to_string());
        }

        if let Some(ref allow_pin_authentication) = options.allow_pin_authentication {
            query_pairs.append_pair(
                "allowPinAuthentication",
                &allow_pin_authentication.to_string(),
            );
        }

        if let Some(ref derivation_origin) = options.derivation_origin {
            query_pairs.append_pair("derivationOrigin", derivation_origin);
        }

        if let Some(ref window_opener_features) = options.window_opener_features {
            query_pairs.append_pair("windowOpenerFeatures", window_opener_features);
        }

        if let Some(ref custom_values) = options.custom_values {
            query_pairs.append_pair("customValues", &format!("{:?}", custom_values));
        }
    }

    /// Core logout logic that clears identity and storage.
    fn logout_core<S: AuthClientStorage>(
        identity: Arc<Mutex<ArcIdentity>>,
        storage: &mut S,
        chain: Arc<Mutex<Option<DelegationChain>>>,
    ) {
        if let Err(_e) = Self::delete_storage_native(storage) {
            #[cfg(feature = "tracing")]
            error!("Failed to delete storage: {}", _e);
        }

        // Reset this auth client to a non-authenticated state.
        *identity.lock() = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
        chain.lock().take();
    }

    /// Log the user out.
    pub fn logout(&self) {
        if let Some(idle_manager) = self.0.idle_manager.lock().take() {
            drop(idle_manager);
        }

        let mut storage_lock = self.0.storage.lock();
        Self::logout_core(
            self.0.identity.clone(),
            &mut *storage_lock,
            self.0.chain.clone(),
        );
    }

    /// Deletes the key and delegation from storage.
    fn delete_storage_native<S>(storage: &mut S) -> Result<(), crate::storage::StorageError>
    where
        S: AuthClientStorage,
    {
        storage.remove(KEY_STORAGE_KEY)?;
        storage.remove(KEY_STORAGE_DELEGATION)?;
        Ok(())
    }
}
