use crate::{
    ArcIdentity,
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
use ic_agent::{
    export::Principal,
    identity::{AnonymousIdentity, DelegatedIdentity, DelegationError, Identity, SignedDelegation},
};
use parking_lot::Mutex;
use std::{
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};
use tiny_http::{Response, Server};
use url::Url;

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
    pub fn new(service_name: String) -> Result<Self, DelegationError> {
        let options = NativeAuthClientCreateOptions::builder()
            .storage(AuthClientStorageType::Keyring(KeyringStorage::new(
                service_name,
            )))
            .build();
        Self::new_with_options(options)
    }

    /// Creates a new key if one is not found in storage, otherwise loads the existing key.
    fn create_or_load_key(
        identity: Option<ArcIdentity>,
        storage: &mut AuthClientStorageType,
    ) -> Result<Key, DelegationError> {
        match identity {
            Some(identity) => Ok(Key::Identity(identity)),
            None => {
                if let Some(stored_key) = storage.get(KEY_STORAGE_KEY) {
                    let private_key = stored_key.decode().map_err(|e| {
                        DelegationError::IdentityError(format!(
                            "Failed to decode private key: {}",
                            e
                        ))
                    })?;
                    Ok(Key::WithRaw(KeyWithRaw::new(private_key)))
                } else {
                    let mut rng = rand::thread_rng();
                    let private_key = SigningKey::generate(&mut rng).to_bytes();
                    storage.set(KEY_STORAGE_KEY, StoredKey::Raw(private_key));
                    Ok(Key::WithRaw(KeyWithRaw::new(private_key)))
                }
            }
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

        if let Some(chain_stored) = storage.get(KEY_STORAGE_DELEGATION) {
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
                    Self::delete_storage_native(storage);
                    identity = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
                    chain = None;
                }
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
    ) -> Result<Self, DelegationError> {
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
            let _ = self
                .0
                .storage
                .lock()
                .set(KEY_STORAGE_KEY, StoredKey::Raw(*key.raw_key()));
        }

        let chain_json = delegation_chain.to_json();
        let _ = self.0.storage.lock().set(
            KEY_STORAGE_DELEGATION,
            StoredKey::String(chain_json.clone()),
        );
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

    /// Processes the query parameters from the redirect URL.
    fn process_query_params(
        request: tiny_http::Request,
        query_params: std::collections::HashMap<String, String>,
        tx: &mpsc::Sender<Result<String, String>>,
    ) {
        if let Some(response) = query_params.get("response") {
            let decoded_response = percent_encoding::percent_decode_str(response)
                .decode_utf8_lossy()
                .to_string();
            let _ = tx.send(Ok(decoded_response));
            let response = Response::from_string(
                "<h1>Login successful!</h1><p>You can close this window.</p>",
            )
            .with_header(
                "Content-Type: text/html"
                    .parse::<tiny_http::Header>()
                    .unwrap(),
            );
            let _ = request.respond(response);
        } else if let Some(error) = query_params.get("error") {
            let _ = tx.send(Err(error.to_string()));
            let response = Response::from_string(format!(
                "<h1>Login failed!</h1><p>Error: {}</p><p>You can close this window.</p>",
                error
            ))
            .with_header(
                "Content-Type: text/html"
                    .parse::<tiny_http::Header>()
                    .unwrap(),
            );
            let _ = request.respond(response);
        } else {
            let _ = tx.send(Err("Missing delegation or error parameter".to_string()));
            let response = Response::from_string(
                "<h1>Login failed!</h1><p>Missing delegation or error parameter.</p><p>You can close this window.</p>",
            )
            .with_header(
                "Content-Type: text/html"
                    .parse::<tiny_http::Header>()
                    .unwrap(),
            );
            let _ = request.respond(response);
        }
    }

    /// Handles the redirect from the identity provider.
    fn handle_redirect(request: tiny_http::Request, tx: &mpsc::Sender<Result<String, String>>) {
        let full_url = format!("http://127.0.0.1{}", request.url());
        if let Ok(url) = Url::parse(&full_url) {
            let query_params: std::collections::HashMap<_, _> =
                url.query_pairs().into_owned().collect();
            Self::process_query_params(request, query_params, tx);
        } else {
            let _ = tx.send(Err("Failed to parse redirect URL".to_string()));
            let response =
                Response::from_string("<h1>Login failed!</h1><p>Could not parse redirect URL.</p>")
                    .with_header(
                        "Content-Type: text/html"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    );
            let _ = request.respond(response);
        }
    }

    /// Handles incoming requests to the local server.
    fn handle_request(request: tiny_http::Request, tx: &mpsc::Sender<Result<String, String>>) {
        if request.url().starts_with("/redirect") {
            Self::handle_redirect(request, tx);
        } else {
            let response = Response::from_string("<h1>Waiting for Internet Identity login...</h1>")
                .with_header(
                    "Content-Type: text/html"
                        .parse::<tiny_http::Header>()
                        .unwrap(),
                );
            let _ = request.respond(response);
            let _ = tx.send(Err("Unexpected request path".to_string()));
        }
    }

    /// Spawns a thread to wait for the delegation from the identity provider.
    fn wait_for_delegation(
        server: Server,
        timeout: Option<Duration>,
        tx: mpsc::Sender<Result<String, String>>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            if let Ok(Some(request)) =
                server.recv_timeout(timeout.unwrap_or(Duration::from_secs(300)))
            {
                Self::handle_request(request, &tx);
            } else {
                let _ = tx.send(Err("Server receive timed out".to_string()));
            }
        })
    }

    /// Finishes the login process after the delegation has been received.
    fn finish_login(
        &self,
        rx: mpsc::Receiver<Result<String, String>>,
        server_handle: thread::JoinHandle<()>,
        on_success: Option<OnSuccess>,
    ) -> Result<(), String> {
        let delegation_str = rx.recv().map_err(|e| e.to_string())??;
        server_handle
            .join()
            .map_err(|_| "Server thread panicked".to_string())?;

        let auth_success: AuthResponseSuccess =
            serde_json::from_str(&delegation_str).map_err(|e| e.to_string())?;

        match self.handle_success(auth_success, on_success) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Logs the user in by opening a browser window to the identity provider.
    pub fn login<T: AsRef<str>>(
        &self,
        ii_url: T,
        options: AuthClientLoginOptions,
    ) -> Result<(), String> {
        let port = portpicker::pick_unused_port().ok_or_else(|| "No free ports".to_string())?;
        let redirect_uri = format!("http://127.0.0.1:{}", port);

        let server = Server::http(redirect_uri.clone()).map_err(|e| e.to_string())?;
        let (tx, rx) = mpsc::channel::<Result<String, String>>();

        let public_key_hex = hex::encode(self.0.key.public_key().unwrap());

        let mut url = Url::parse(ii_url.as_ref()).map_err(|e| e.to_string())?;
        Self::set_query_params(&mut url, &options, &redirect_uri, &public_key_hex);

        webbrowser::open(url.as_str()).map_err(|e| e.to_string())?;

        let server_handle = Self::wait_for_delegation(server, options.timeout, tx);

        self.finish_login(rx, server_handle, options.on_success)
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
        Self::delete_storage_native(storage);

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
    fn delete_storage_native<S>(storage: &mut S)
    where
        S: AuthClientStorage,
    {
        let _ = storage.remove(KEY_STORAGE_KEY);
        let _ = storage.remove(KEY_STORAGE_DELEGATION);
    }
}
