//! Simple interface to get your web application authenticated with the Internet Identity Service for Rust.
//!
//! This crate is intended for use in front-end WebAssembly environments in conjunction with [ic-agent](https://docs.rs/ic-agent).

use crate::{
    idle_manager::{IdleManager, IdleManagerOptions},
    storage::{
        AuthClientStorage, AuthClientStorageType, KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY,
        KEY_VECTOR,
    },
    util::{delegation_chain::DelegationChain, sleep::sleep},
};
use gloo_events::EventListener;
use gloo_utils::{format::JsValueSerdeExt, window};
use ic_agent::{
    Identity,
    export::Principal,
    identity::{
        AnonymousIdentity, BasicIdentity, DelegatedIdentity, DelegationError, SignedDelegation,
    },
};
use ic_ed25519::PrivateKey;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::from_value;
use std::{
    cell::RefCell,
    collections::HashMap,
    fmt,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex},
};
use storage::StoredKey;
#[cfg(not(target_family = "wasm"))]
use tokio::task::spawn_local;
#[cfg(feature = "tracing")]
use tracing::{debug, error, info, warn};
#[cfg(target_family = "wasm")]
use wasm_bindgen_futures::spawn_local;
use web_sys::{
    Location, MessageEvent,
    wasm_bindgen::{JsCast, JsValue},
};

pub mod idle_manager;
pub mod storage;
mod util;

pub use util::delegation_chain;

thread_local! {
    static EVENT_HANDLERS: RefCell<HashMap<usize, EventListener>> = RefCell::new(HashMap::new());
    static IDP_WINDOWS: RefCell<HashMap<usize, web_sys::Window>> = RefCell::new(HashMap::new());
}

type OnSuccess = Arc<Mutex<Box<dyn FnMut(AuthResponseSuccess) + Send>>>;
type OnError = Arc<Mutex<Box<dyn FnMut(Option<String>) + Send>>>;

const IDENTITY_PROVIDER_DEFAULT: &str = "https://identity.ic0.app";
const IDENTITY_PROVIDER_ENDPOINT: &str = "#authorize";

const ED25519_KEY_LABEL: &str = "Ed25519";

const INTERRUPT_CHECK_INTERVAL: u64 = 500;
/// The error message when a user interrupts the authentication process.
pub const ERROR_USER_INTERRUPT: &str = "UserInterrupt";

/// Represents an Internet Identity authentication request.
///
/// This struct is used to send an authentication request to the Internet Identity Service.
/// It includes all the necessary parameters that the Internet Identity Service needs to authenticate a user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
struct InternetIdentityAuthRequest {
    /// The kind of request. This is typically set to "authorize-client".
    pub kind: String,
    /// The public key of the session.
    pub session_public_key: Vec<u8>,
    /// The maximum time to live for the session, in nanoseconds. If not provided, a default value is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_time_to_live: Option<u64>,
    /// If present, indicates whether or not the Identity Provider should allow the user to authenticate and/or register using a temporary key/PIN identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_pin_authentication: Option<bool>,
    /// Origin for Identity Provider to use while generating the delegated identity. For II, the derivation origin must authorize this origin by setting a record at `<derivation-origin>/.well-known/ii-alternative-origins`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_origin: Option<String>,
}

/// Represents a successful authentication response.
///
/// This struct is used to store the details of a successful authentication response from the Internet Identity Service.
/// It includes the delegations, the user's public key, and the authentication method used.
#[derive(Debug, Clone)]
pub struct AuthResponseSuccess {
    /// The delegations provided by the user during the authentication process.
    pub delegations: Vec<SignedDelegation>,
    /// The public key of the user.
    pub user_public_key: Vec<u8>,
    /// The authentication method used by the user.
    pub authn_method: String,
}

/// Represents a response message from the Identity Service.
///
/// This struct is used to store the details of a response message from the Identity Service.
/// It includes the kind of the response, the delegations, the user's public key, the authentication method used,
/// and the error message in case of failure.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityServiceResponseMessage {
    /// The kind of the response. This is typically set to "authorize-ready", "authorize-client-success", or "authorize-client-failure".
    kind: String,

    /// The delegations provided by the user during the authentication process. This is present in case of a successful authentication.
    delegations: Option<Vec<SignedDelegation>>,

    /// The public key of the user. This is present in case of a successful authentication.
    user_public_key: Option<Vec<u8>>,

    /// The authentication method used by the user. This is present in case of a successful authentication.
    authn_method: Option<String>,

    /// The error message in case of a failed authentication.
    text: Option<String>,
}

impl IdentityServiceResponseMessage {
    /// Returns the kind of the Identity Service response.
    pub fn kind(&self) -> Result<IdentityServiceResponseKind, String> {
        match self.kind.as_str() {
            "authorize-ready" => Ok(IdentityServiceResponseKind::Ready),
            "authorize-client-success" => Ok(IdentityServiceResponseKind::AuthSuccess(
                AuthResponseSuccess {
                    delegations: self.delegations.clone().unwrap_or_default(),
                    user_public_key: self.user_public_key.clone().unwrap_or_default(),
                    authn_method: self.authn_method.clone().unwrap_or_default(),
                },
            )),
            "authorize-client-failure" => Ok(IdentityServiceResponseKind::AuthFailure(
                self.text.clone().unwrap_or_default(),
            )),
            other => Err(format!("Unknown response kind: {}", other)),
        }
    }
}

/// Enum representing the kind of response from the Identity Service.
#[derive(Debug, Clone)]
enum IdentityServiceResponseKind {
    /// Represents a ready state.
    Ready,
    /// Represents a successful authentication response.
    AuthSuccess(AuthResponseSuccess),
    /// Represents a failed authentication response with an error message.
    AuthFailure(String),
}

/// The tool for managing authentication and identity.
/// It maintains the state of the user's identity and provides methods for authentication.
#[derive(Clone, Debug)]
pub struct AuthClient {
    /// The user's identity. This can be an anonymous identity, an Ed25519 identity, or a delegated identity.
    identity: Arc<Mutex<ArcIdentity>>,
    /// The key associated with the user's identity.
    key: Key,
    /// The storage used to persist the user's identity and key.
    storage: AuthClientStorageType,
    /// The delegation chain associated with the user's identity.
    chain: Arc<Mutex<Option<DelegationChain>>>,
    /// The idle manager that handles idle timeouts.
    pub idle_manager: Option<IdleManager>,
    /// The options for handling idle timeouts.
    idle_options: Option<IdleOptions>,
    /// A unique identifier for this instance and its clones, used to associate it with thread-local resources.
    /// Wrapped in Arc to manage cleanup only when the last clone is dropped.
    id: Arc<usize>,
    /// Flag to indicate if the current login flow has completed (success, failure, or interrupt).
    login_complete: Arc<AtomicBool>,
}

impl Drop for AuthClient {
    fn drop(&mut self) {
        // Clean up the thread-local storage only when the last Arc pointing to the id is dropped.
        if Arc::strong_count(&self.id) == 1 {
            let id_val = *self.id; // Get the actual ID value

            // Use try_borrow_mut to avoid panic if already borrowed, e.g., during event handling
            EVENT_HANDLERS.with(|cell| {
                match cell.try_borrow_mut() {
                    Ok(mut map) => {
                        map.remove(&id_val);
                    }
                    Err(_) => {
                        #[cfg(feature = "tracing")]
                        error!("AuthClient::drop: Could not remove event handler for id {} (already borrowed)", id_val);
                    }
                }
            });

            IDP_WINDOWS.with(|cell| {
                match cell.try_borrow_mut() {
                    Ok(mut map) => {
                        // Close the window if it exists before removing it
                        if let Some(window) = map.remove(&id_val) {
                             // Ignore error if window is already closed
                            let _ = window.close();
                        }
                    }
                    Err(_) => {
                        #[cfg(feature = "tracing")]
                        error!("AuthClient::drop: Could not remove IDP window for id {} (already borrowed)", id_val);
                    }
                }
            });
        }
    }
}

impl AuthClient {
    /// Sets the event handler for this instance in thread-local storage.
    fn set_event_handler(&self, handler: EventListener) {
        EVENT_HANDLERS.with(|cell| {
            let mut map = cell.borrow_mut();
            map.insert(*self.id, handler);
        });
    }

    /// Takes the event handler for this instance, removing it from thread-local storage.
    fn take_event_handler(&self) -> Option<EventListener> {
        EVENT_HANDLERS.with(|cell| {
            let mut map = cell.borrow_mut();
            map.remove(&self.id)
        })
    }

    /// Sets the IdP window for this instance in thread-local storage.
    fn set_idp_window(&self, window: web_sys::Window) {
        IDP_WINDOWS.with(|cell| {
            let mut map = cell.borrow_mut();
            map.insert(*self.id, window);
        });
    }

    /// Gets the IdP window for this instance from thread-local storage.
    fn get_idp_window(&self) -> Option<web_sys::Window> {
        IDP_WINDOWS.with(|cell| {
            let map = cell.borrow();
            map.get(&self.id).cloned()
        })
    }

    /// Takes the IdP window for this instance, removing it from thread-local storage.
    fn take_idp_window(&self) -> Option<web_sys::Window> {
        IDP_WINDOWS.with(|cell| {
            let mut map = cell.borrow_mut();
            map.remove(&self.id)
        })
    }

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
                    let private_key = PrivateKey::generate().serialize_raw();
                    let _ = storage
                        .set(KEY_STORAGE_KEY, StoredKey::encode(&private_key))
                        .await;
                    Key::WithRaw(KeyWithRaw::new(private_key))
                }
            }
        };

        let mut identity = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
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
                        if let Ok(guard) = chain.lock() {
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
                        } else {
                            // Couldn't get lock
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
            && (chain.lock().is_ok_and(|c| c.is_some()) || options_identity_is_some)
        {
            let idle_manager_options: Option<IdleManagerOptions> = options
                .idle_options
                .as_ref()
                .map(|o| o.idle_manager_options.clone());
            idle_manager = Some(IdleManager::new(idle_manager_options));
        }

        // Generate a unique ID for this instance
        let id = {
            static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
            // Use Relaxed ordering as we only need atomicity, not synchronization
            Arc::new(NEXT_ID.fetch_add(1, Ordering::Relaxed))
        };

        Ok(Self {
            identity: Arc::new(Mutex::new(identity)),
            key,
            storage,
            chain,
            idle_manager,
            idle_options: options.idle_options,
            id,
            login_complete: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Registers the default idle callback.
    fn register_default_idle_callback(
        identity: Arc<Mutex<ArcIdentity>>,
        storage: AuthClientStorageType,
        chain: Arc<Mutex<Option<DelegationChain>>>,
        idle_manager: Option<IdleManager>,
        idle_options: Option<IdleOptions>,
    ) {
        if let Some(options) = idle_options.as_ref() {
            if options.disable_default_idle_callback.unwrap_or_default() {
                return;
            }

            if options
                .idle_manager_options
                .on_idle
                .as_ref()
                .lock()
                .is_ok_and(|o| o.is_empty())
            {
                if let Some(idle_manager) = idle_manager.as_ref() {
                    let identity = identity.clone();
                    let storage = storage.clone();
                    let chain = chain.clone();
                    let callback = move || {
                        let identity = identity.clone();
                        let storage = storage.clone();
                        let chain = chain.clone();
                        spawn_local(async move {
                            Self::logout_core(identity, storage, chain, None).await;
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
        &mut self,
        message: AuthResponseSuccess,
        on_success: Option<OnSuccess>,
    ) -> Result<(), DelegationError> {
        // Signal that login has completed normally *before* closing the window or calling callbacks.
        // This prevents the check_interruption task from incorrectly flagging a user interrupt.
        self.login_complete.store(true, Ordering::SeqCst);

        // Clean up window and event handler *before* potentially long-running async operations or callbacks
        if let Some(w) = self.take_idp_window() {
            // Ignore error if window is already closed
            let _ = w.close();
        };
        self.take_event_handler(); // Remove event handler associated with this login attempt

        let delegations = message.delegations.clone();
        let user_public_key = message.user_public_key.clone();

        // Create the delegation chain
        let delegation_chain = DelegationChain {
            delegations: delegations.clone(),
            public_key: user_public_key.clone(),
        };

        if let Key::WithRaw(key) = &self.key {
            let _ = self
                .storage
                .set(KEY_STORAGE_KEY, StoredKey::encode(key.raw_key()))
                .await;
        }

        // Serialize the chain to JSON
        let chain_json = delegation_chain.to_json();

        // First, save to storage immediately to ensure consistency between refreshes
        // This is critical for authentication persistence
        let _ = self
            .storage
            .set(KEY_STORAGE_DELEGATION, chain_json.clone())
            .await;

        // Now update the in-memory state
        {
            if let Ok(mut guard) = self.chain.lock() {
                *guard = Some(delegation_chain.clone());
            } else {
                #[cfg(feature = "tracing")]
                error!("Failed to acquire lock on delegation chain during handle_success");
            }

            if let Ok(mut guard) = self.identity.lock() {
                *guard = ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                    user_public_key.clone(),
                    Box::new(self.key.as_arc_identity()),
                    delegations.clone(),
                )));
            } else {
                #[cfg(feature = "tracing")]
                error!("Failed to acquire lock on identity during handle_success");
            }
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

            let _has_chain = if let Ok(guard) = self.chain.lock() {
                guard.is_some()
            } else {
                false
            };

            #[cfg(feature = "tracing")]
            debug!(
                "is_authenticated(): is_not_anonymous={}, has_chain={}",
                _is_not_anonymous, _has_chain
            );

            // Try a more direct approach - recreate the delegation chain from JSON
            // This ensures our in-memory and storage states are completely in sync
            if let Ok(mut guard) = self.chain.lock() {
                *guard = Some(DelegationChain::from_json(&chain_json));
            }

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
                {
                    if let Ok(mut guard) = self.identity.lock() {
                        *guard =
                            ArcIdentity::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                                user_public_key.clone(),
                                Box::new(self.key.as_arc_identity()),
                                delegations.clone(),
                            )));
                    } else {
                        #[cfg(feature = "tracing")]
                        error!("Failed to acquire lock on identity during final fix attempt");
                    }
                }

                // Last check
                let _final_auth_check = self.is_authenticated();
                #[cfg(feature = "tracing")]
                debug!("Final check: is_authenticated() = {}", _final_auth_check);
            }
        }

        // create the idle manager on a successful login if we haven't disabled it
        // and it doesn't already exist.
        let disable_idle = match self.idle_options.as_ref() {
            Some(options) => options.disable_idle.unwrap_or(false),
            None => false,
        };
        if self.idle_manager.is_none() && !disable_idle {
            let idle_manager_options = self
                .idle_options
                .as_ref()
                .map(|o| o.idle_manager_options.clone());
            let new_idle_manager = IdleManager::new(idle_manager_options);
            self.idle_manager = Some(new_idle_manager);

            // Register default callback only if idle_manager was successfully created
            if let Some(idle_manager) = self.idle_manager.as_ref() {
                Self::register_default_idle_callback(
                    self.identity.clone(),
                    self.storage.clone(),
                    self.chain.clone(),
                    Some(idle_manager.clone()),
                    self.idle_options.clone(),
                );
            }
        }

        // on_success should be the last thing to do to avoid consumers
        // interfering by navigating or refreshing the page
        if let Some(on_success_cb) = on_success {
            // Use try_lock to prevent blocking if the callback itself tries to re-enter AuthClient methods.
            if let Ok(mut guard) = on_success_cb.try_lock() {
                (*guard)(message);
            } else {
                #[cfg(feature = "tracing")]
                error!("Failed to acquire lock on on_success callback");
            }
        }

        Ok(())
    }

    /// Returns the identity of the user.
    pub fn identity(&self) -> Arc<dyn Identity> {
        self.identity
            .lock()
            .map(|guard| guard.as_arc_identity())
            .unwrap_or_else(|_| {
                #[cfg(feature = "tracing")]
                error!("Failed to acquire lock on identity");
                Arc::new(AnonymousIdentity)
            })
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

        let is_valid_chain = if let Ok(chain_guard) = self.chain.lock() {
            if let Some(chain) = chain_guard.as_ref() {
                chain.is_delegation_valid(None)
            } else {
                false
            }
        } else {
            false
        };

        is_not_anonymous && is_valid_chain
    }

    /// Logs the user in with default options.
    pub fn login(&mut self) {
        self.login_with_options(AuthClientLoginOptions::default());
    }

    /// Logs the user in with the provided options.
    pub fn login_with_options(&mut self, options: AuthClientLoginOptions) {
        // Reset completion flag for the new login attempt
        self.login_complete.store(false, Ordering::SeqCst);

        let window = web_sys::window().unwrap();

        // Create the URL of the IDP. (e.g. https://XXXX/#authorize)
        let identity_provider_url: web_sys::Url = options
            .identity_provider
            .clone()
            .unwrap_or_else(|| web_sys::Url::new(IDENTITY_PROVIDER_DEFAULT).unwrap());

        // Set the correct hash if it isn't already set.
        identity_provider_url.set_hash(IDENTITY_PROVIDER_ENDPOINT);

        // If `login` has been called previously, then close/remove any previous windows
        // and event listeners.
        if let Some(idp_window) = self.take_idp_window() {
            // Ignore error if window is already closed
            let _ = idp_window.close();
        }
        self.take_event_handler();

        // Open a new window with the IDP provider.
        let window_handle_result = window.open_with_url_and_target_and_features(
            &identity_provider_url.href(),
            "idpWindow",
            options.window_opener_features.as_deref().unwrap_or(""),
        );

        match window_handle_result {
            Ok(Some(window_handle)) => {
                self.set_idp_window(window_handle);

                // Add an event listener to handle responses.
                let handler =
                    self.get_event_handler(identity_provider_url.clone(), options.clone());
                self.set_event_handler(handler);

                // Start checking for interruption, passing the completion flag
                self.check_interruption(options.on_error.clone(), self.login_complete.clone());
            }
            Ok(None) => {
                // Window opening was blocked by the browser (e.g., popup blocker)
                self.login_complete.store(true, Ordering::SeqCst); // Mark as complete (failed)
                if let Some(on_error) = options.on_error {
                    if let Ok(mut guard) = on_error.lock() {
                        (*guard)(Some(
                            "Failed to open IdP window. Check popup blocker.".to_string(),
                        ));
                    } else {
                        #[cfg(feature = "tracing")]
                        error!("Failed to acquire lock on on_error callback");
                    }
                } else {
                    #[cfg(feature = "tracing")]
                    warn!("Failed to open IdP window. Check popup blocker.");
                }
                // Clean up potentially stored (but unused) handler/window refs for this ID
                self.take_event_handler();
                self.take_idp_window();
            }
            Err(e) => {
                // Other error during window opening
                self.login_complete.store(true, Ordering::SeqCst); // Mark as complete (failed)
                let error_message = format!("Error opening IdP window: {:?}", e);
                if let Some(on_error) = options.on_error {
                    if let Ok(mut guard) = on_error.lock() {
                        (*guard)(Some(error_message.clone()));
                    } else {
                        #[cfg(feature = "tracing")]
                        error!("Failed to acquire lock on on_error callback");
                    }
                } else {
                    #[cfg(feature = "tracing")]
                    error!("{}", error_message);
                }
                // Clean up potentially stored (but unused) handler/window refs for this ID
                self.take_event_handler();
                self.take_idp_window();
            }
        }
    }

    /// Checks for user interruption during the login process.
    fn check_interruption(&self, on_error: Option<OnError>, login_complete: Arc<AtomicBool>) {
        let client_id = *self.id;
        let idp_window = self.get_idp_window();
        let login_complete_clone = login_complete.clone();

        spawn_local({
            async move {
                if let Some(idp_window_ref) = idp_window {
                    // Give the authentication process a moment to start before checking for interruptions
                    sleep(1000).await;

                    // Check periodically if the window is still open
                    while !idp_window_ref.closed().unwrap_or(true)
                        && !login_complete_clone.load(Ordering::SeqCst)
                    {
                        sleep(INTERRUPT_CHECK_INTERVAL).await;
                    }

                    // Only report a user interrupt if login isn't already complete AND the window is closed
                    // This avoids false UserInterrupt errors when the window is closed after authentication completes
                    if idp_window_ref.closed().unwrap_or(true)
                        && !login_complete_clone.load(Ordering::SeqCst)
                    {
                        // Clean up resources first
                        let _ = idp_window_ref.close(); // Ignore error if already closed

                        // Remove the event handler from thread-local storage
                        EVENT_HANDLERS.with(|cell| {
                            // Use try_borrow_mut to avoid panic if already borrowed
                            if let Ok(mut map) = cell.try_borrow_mut() {
                                map.remove(&client_id);
                            } else {
                                #[cfg(feature = "tracing")]
                                error!("AuthClient::check_interruption: Could not remove event handler for id {} (already borrowed)", client_id);
                            }
                        });

                        // Also remove the window reference if it wasn't removed by handle_success/handle_failure
                        IDP_WINDOWS.with(|cell| {
                            if let Ok(mut map) = cell.try_borrow_mut() {
                                map.remove(&client_id);
                            } else {
                                #[cfg(feature = "tracing")]
                                error!("AuthClient::check_interruption: Could not remove IDP window for id {} (already borrowed)", client_id);
                            }
                        });

                        // Double-check one last time before triggering the error callback
                        // This helps avoid race conditions where login completion happens right as we're checking
                        if !login_complete_clone.load(Ordering::SeqCst) {
                            // Only now call the error callback if provided
                            if let Some(on_error) = on_error {
                                // Ensure login_complete is set before calling the callback
                                login_complete_clone.store(true, Ordering::SeqCst);
                                if let Ok(mut guard) = on_error.lock() {
                                    (*guard)(Some(ERROR_USER_INTERRUPT.to_string()));
                                } else {
                                    #[cfg(feature = "tracing")]
                                    error!(
                                        "Failed to acquire lock on on_error callback during user interrupt"
                                    );
                                }
                            } else {
                                // If no error handler, still mark as complete to prevent potential issues
                                login_complete_clone.store(true, Ordering::SeqCst);
                            }
                        }
                    } else {
                        // Window is not closed or login is already complete, no need to do anything
                        // Resources will be cleaned up by handle_success/failure or another mechanism
                    }
                }
            }
        });
    }

    /// Returns an event handler for the login process.
    fn get_event_handler(
        &mut self,
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
                // Clone necessary parts, avoid cloning the whole client into the async block if possible
                let login_complete = client.login_complete.clone();
                let on_error = options.on_error.clone();
                let client_id = *client.id; // Get the ID value

                spawn_local(async move {
                    // Signal completion
                    login_complete.store(true, Ordering::SeqCst);

                    // Clean up window and handler (using the ID)
                    if let Some(window) =
                        IDP_WINDOWS.with(|map| map.borrow_mut().remove(&client_id))
                    {
                        let _ = window.close();
                    }
                    EVENT_HANDLERS.with(|map| map.borrow_mut().remove(&client_id));

                    // Call the error callback
                    if let Some(on_error_cb) = on_error {
                        if let Ok(mut guard) = on_error_cb.try_lock() {
                            (*guard)(Some(error));
                        } else {
                            #[cfg(feature = "tracing")]
                            error!("Failed to acquire lock on on_error callback in event handler");
                        }
                    } else {
                        #[cfg(feature = "tracing")]
                        error!("AuthClient login failed in event handler: {}", error);
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

                        if let Some(idp_window) = client.get_idp_window() {
                            if idp_window
                                .post_message(&request_js_value, &identity_provider_url.origin())
                                .is_err()
                            {
                                handle_error_wrapper(
                                    "Failed to post message to IdP window".to_string(),
                                );
                            }
                        } else {
                            // This case might happen if the window was closed unexpectedly between checks
                            handle_error_wrapper(
                                "IdP window not found when trying to post message".to_string(),
                            );
                        }
                    }
                    IdentityServiceResponseKind::AuthSuccess(response) => {
                        let mut client_clone = client.clone();
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
                                    if let Ok(mut guard) = on_error_cb.try_lock() {
                                        (*guard)(Some(format!(
                                            "Error processing successful login: {:?}",
                                            e
                                        )));
                                    }
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
    async fn logout_core(
        identity: Arc<Mutex<ArcIdentity>>,
        mut storage: AuthClientStorageType,
        chain: Arc<Mutex<Option<DelegationChain>>>,
        return_to: Option<Location>,
    ) {
        Self::delete_storage(&mut storage).await;

        // Reset this auth client to a non-authenticated state.
        if let Ok(mut guard) = identity.lock() {
            *guard = ArcIdentity::Anonymous(Arc::new(AnonymousIdentity));
        } else {
            #[cfg(feature = "tracing")]
            error!("Failed to acquire lock on identity during logout");
        }
        if let Ok(mut guard) = chain.try_lock() {
            guard.take();
        } else {
            #[cfg(feature = "tracing")]
            error!("Failed to acquire lock on delegation chain during logout");
        }

        // If a return URL is provided, redirect the user to that URL.
        if let Some(return_to) = return_to {
            if let Some(window) = web_sys::window() {
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
    }

    /// Log the user out.
    /// If a return URL is provided, the user will be redirected to that URL after logging out.
    pub async fn logout(&mut self, return_to: Option<Location>) {
        if let Some(idle_manager) = self.idle_manager.take() {
            drop(idle_manager);
        }

        Self::logout_core(
            self.identity.clone(),
            self.storage.clone(),
            self.chain.clone(),
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
        // Ensure the Arc<Mutex<Vec>> exists
        if Arc::strong_count(&options.idle_manager_options.on_idle) == 0 {
            // This case should ideally not happen if initialized correctly, but handle defensively
            options.idle_manager_options.on_idle = Arc::new(Mutex::new(Vec::new()));
        }
        // Add the new callback
        if let Ok(mut guard) = options.idle_manager_options.on_idle.lock() {
            guard.push(Box::new(on_idle));
        } else {
            #[cfg(feature = "tracing")]
            error!("Failed to lock on_idle callbacks to add new one.");
        }
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
    /// ```
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
    /// ```
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
    pub fn add_on_idle<F>(mut self, on_idle: F) -> Self
    where
        F: FnMut() + Send + 'static,
    {
        // Ensure the Arc<Mutex<Vec>> exists
        if Arc::strong_count(&self.idle_manager_options.on_idle) == 0 {
            // This case should ideally not happen if initialized correctly, but handle defensively
            self.idle_manager_options.on_idle = Arc::new(Mutex::new(Vec::new()));
        }
        // Add the new callback
        if let Ok(mut guard) = self.idle_manager_options.on_idle.lock() {
            guard.push(Box::new(on_idle));
        } else {
            #[cfg(feature = "tracing")]
            error!("Failed to lock on_idle callbacks to add new one.");
        }
        self
    }

    /// The duration of inactivity after which the system is considered idle.
    pub fn idle_timeout(mut self, idle_timeout: u32) -> Self {
        self.idle_manager_options.idle_timeout = Some(idle_timeout);
        self
    }

    /// A delay for debouncing scroll events.
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

    #[wasm_bindgen_test]
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
        assert!(
            options
                .idle_manager_options
                .on_idle
                .as_ref()
                .lock()
                .unwrap()
                .is_empty()
        );
        assert_eq!(options.idle_manager_options.idle_timeout, Some(1000));
        assert_eq!(options.idle_manager_options.scroll_debounce, Some(500));
        assert_eq!(options.idle_manager_options.capture_scroll, Some(true));
    }

    #[wasm_bindgen_test]
    fn test_base_key_type_display() {
        assert_eq!(BaseKeyType::Ed25519.to_string(), ED25519_KEY_LABEL);
    }

    #[wasm_bindgen_test]
    fn test_base_key_type_default() {
        assert_eq!(BaseKeyType::default(), BaseKeyType::Ed25519);
    }

    #[wasm_bindgen_test]
    async fn test_auth_client_builder() {
        let private_key = PrivateKey::generate().serialize_raw();
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

    #[wasm_bindgen_test]
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
}
