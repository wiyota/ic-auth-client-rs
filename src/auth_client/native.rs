use super::{ArcIdentity, AuthClientLoginOptions, BaseKeyType, IdleOptions, Key, KeyWithRaw};
use crate::{
    api::AuthResponseSuccess,
    auth_client::{OnError, OnErrorAsync, OnSuccess, OnSuccessAsync},
    idle_manager::{IdleManager, IdleManagerOptions},
    storage::{
        KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY, StoredKey,
        sync_storage::{AuthClientStorage, AuthClientStorageType, KeyringStorage},
    },
    util::delegation_chain::DelegationChain,
};
use ed25519_dalek::SigningKey;
use ic_agent::{
    export::Principal,
    identity::{AnonymousIdentity, DelegatedIdentity, DelegationError, Identity},
};
use parking_lot::Mutex;
use std::{
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};
use tiny_http::{Response, Server};
use tokio::task::spawn_local;
use url::Url;

#[derive(Debug)]
struct AuthClientInner {
    identity: Arc<Mutex<ArcIdentity>>,
    key: Key,
    storage: Mutex<AuthClientStorageType>,
    chain: Arc<Mutex<Option<DelegationChain>>>,
    idle_manager: Mutex<Option<IdleManager>>,
    idle_options: Option<IdleOptions>,
}

/// The tool for managing authentication and identity.
/// It maintains the state of the user's identity and provides methods for authentication.
#[derive(Clone, Debug)]
pub struct AuthClient(Arc<AuthClientInner>);

impl AuthClient {
    /// Default time to live for the session in nanoseconds (8 hours).
    const DEFAULT_TIME_TO_LIVE: u64 = 8 * 60 * 60 * 1_000_000_000;

    /// Creates a new [`AuthClient`] with default options.
    pub fn new(service_name: String) -> Result<Self, DelegationError> {
        let options = AuthClientCreateOptions::builder()
            .storage(AuthClientStorageType::Keyring(KeyringStorage::new(
                service_name,
            )))
            .build();
        Self::new_with_options(options)
    }

    /// Creates a new [`AuthClient`] with the provided options.
    pub fn new_with_options(options: AuthClientCreateOptions) -> Result<Self, DelegationError> {
        let mut storage = options.storage;
        let options_identity_is_some = options.identity.is_some();

        let key = match options.identity {
            Some(identity) => Key::Identity(identity),
            None => {
                if let Some(stored_key) = storage.get(KEY_STORAGE_KEY) {
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
                    storage.set(KEY_STORAGE_KEY, StoredKey::Raw(private_key));
                    Key::WithRaw(KeyWithRaw::new(private_key))
                }
            }
        };

        let mut identity = ArcIdentity::from(key.clone());
        let mut chain: Option<DelegationChain> = None;

        let chain_stored = storage.get(KEY_STORAGE_DELEGATION);

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
                    Self::delete_storage(&mut storage);

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
                        client.logout();
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
                .set(KEY_STORAGE_KEY, StoredKey::Raw(*key.raw_key()));
        }

        // Serialize the chain to JSON
        let chain_json = delegation_chain.to_json();

        // First, save to storage immediately to ensure consistency between refreshes
        // This is critical for authentication persistence
        let _ = self.0.storage.lock().set(
            KEY_STORAGE_DELEGATION,
            StoredKey::String(chain_json.clone()),
        );

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
        self.identity().sender().is_ok()
            && self.identity().sender().unwrap() != Principal::anonymous()
            && self
                .0
                .chain
                .lock()
                .as_ref()
                .is_some_and(|c| c.is_delegation_valid(None))
    }

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
        url.query_pairs_mut()
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("pubkey", &public_key_hex);

        webbrowser::open(url.as_str()).map_err(|e| e.to_string())?;

        let server_handle = thread::spawn(move || {
            if let Ok(Some(request)) = server.recv_timeout(Duration::from_secs(300)) {
                if request.url().starts_with("/redirect") {
                    let full_url = format!("http://127.0.0.1{}", request.url());
                    if let Ok(url) = Url::parse(&full_url) {
                        if let Some((_, value)) = url.query_pairs().find(|(k, _)| k == "delegation")
                        {
                            let decoded_delegation = percent_encoding::percent_decode_str(&value)
                                .decode_utf8_lossy()
                                .to_string();
                            let _ = tx.send(Ok(decoded_delegation));
                            let response = Response::from_string(
                                "<h1>Login successful!</h1><p>You can close this window.</p>",
                            )
                            .with_header(
                                "Content-Type: text/html"
                                    .parse::<tiny_http::Header>()
                                    .unwrap(),
                            );
                            let _ = request.respond(response);
                        } else {
                            let _ = tx.send(Err("Missing delegation parameter".to_string()));
                        }
                    }
                } else {
                    let response =
                        Response::from_string("<h1>Waiting for Internet Identity login...</h1>")
                            .with_header(
                                "Content-Type: text/html"
                                    .parse::<tiny_http::Header>()
                                    .unwrap(),
                            );
                    let _ = request.respond(response);
                    let _ = tx.send(Err("Unexpected request path".to_string()));
                }
            } else {
                let _ = tx.send(Err("Server receive timed out".to_string()));
            }
        });

        let delegation_str = rx.recv().map_err(|e| e.to_string())??;
        server_handle
            .join()
            .map_err(|_| "Server thread panicked".to_string())?;

        let auth_success: AuthResponseSuccess =
            serde_json::from_str(&delegation_str).map_err(|e| e.to_string())?;

        self.handle_success(auth_success, options.on_success, options.on_error_async)
    }

    /// Logs out the user and clears the stored identity.
    fn logout_core<S: AuthClientStorage>(
        identity: Arc<Mutex<ArcIdentity>>,
        storage: &mut S,
        chain: Arc<Mutex<Option<DelegationChain>>>,
    ) {
        Self::delete_storage(storage);

        // Reset this auth client to a non-authenticated state.
        *identity.lock() = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
        chain.lock().take();
    }

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

    fn delete_storage<S>(storage: &mut S)
    where
        S: AuthClientStorage,
    {
        let _ = storage.remove(KEY_STORAGE_KEY);
        let _ = storage.remove(KEY_STORAGE_DELEGATION);
    }
}

/// Options for creating a new [`AuthClient`].
#[derive(Clone, bon::Builder)]
pub struct AuthClientCreateOptions {
    /// An optional identity to use as the base. If not provided, an `Ed25519` key pair will be used.
    pub identity: Option<ArcIdentity>,
    /// Storage with get, set, and remove methods. Currentry only `KeyringStorage` is supported.
    pub storage: AuthClientStorageType,
    /// The type of key to use for the base key. If not provided, `Ed25519` will be used by default.
    pub key_type: Option<BaseKeyType>,
    /// Options for handling idle timeouts. If not provided, default options will be used.
    pub idle_options: Option<IdleOptions>,
}
