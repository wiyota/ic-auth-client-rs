//! Simple interface to get your web application authenticated with the Internet Identity Service for Rust.
//!
//! This crate is intended for use in front-end WebAssembly environments in conjunction with [ic-agent](https://docs.rs/ic-agent).

use crate::{
    idle_manager::{IdleManager, IdleManagerOptions},
    storage::{
        AuthClientStorage, AuthClientStorageType, KEY_STORAGE_DELEGATION, KEY_STORAGE_KEY, KEY_VECTOR,
    },
    util::{delegation_chain::DelegationChain, sleep::sleep},
};
use ed25519_consensus::SigningKey;
use gloo_console::error;
use gloo_events::EventListener;
use gloo_utils::{format::JsValueSerdeExt, window};
use ic_agent::{
    export::Principal,
    identity::{AnonymousIdentity, BasicIdentity, DelegatedIdentity, SignedDelegation, DelegationError},
    Identity,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::from_value;
use std::{cell::RefCell, collections::HashMap, fmt, mem, rc::Rc, sync::Arc};
use storage::StoredKey;
#[cfg(target_family = "wasm")]
use wasm_bindgen_futures::spawn_local;
#[cfg(not(target_family = "wasm"))]
use tokio::task::spawn_local;
use web_sys::{Location, MessageEvent, wasm_bindgen::{JsCast, JsValue}};

pub mod idle_manager;
pub mod storage;
mod util;

pub use util::delegation_chain;

type OnSuccess = Rc<RefCell<Box<dyn FnMut(AuthResponseSuccess)>>>;
type OnError = Rc<RefCell<Box<dyn FnMut(Option<String>)>>>;

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
    pub fn kind(&self) -> IdentityServiceResponseKind {
        match self.kind.as_str() {
            "authorize-ready" => IdentityServiceResponseKind::Ready,
            "authorize-client-success" => {
                IdentityServiceResponseKind::AuthSuccess(AuthResponseSuccess {
                    delegations: self.delegations.clone().unwrap_or_default(),
                    user_public_key: self.user_public_key.clone().unwrap_or_default(),
                    authn_method: self.authn_method.clone().unwrap_or_default(),
                })
            }
            "authorize-client-failure" => {
                IdentityServiceResponseKind::AuthFailure(self.text.clone().unwrap_or_default())
            }
            _ => panic!("Unexpected response kind: {}", self.kind),
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
#[derive(Clone)]
pub struct AuthClient {
    /// The user's identity. This can be an anonymous identity, an Ed25519 identity, or a delegated identity.
    identity: Rc<RefCell<ArcIdentityType>>,
    /// The key associated with the user's identity.
    key: ArcIdentityType,
    /// The storage used to persist the user's identity and key.
    storage: AuthClientStorageType,
    /// The delegation chain associated with the user's identity.
    chain: Rc<RefCell<Option<DelegationChain>>>,
    /// The idle manager that handles idle timeouts.
    pub idle_manager: Option<IdleManager>,
    /// The options for handling idle timeouts.
    idle_options: Rc<Option<IdleOptions>>,
    /// A handle on the Identity Provider (IdP) window. This is used to interact with the IdP during the authentication process.
    idp_window: Rc<RefCell<Option<web_sys::Window>>>,
    /// The event handler for processing events from the IdP. This is used to handle the responses from the IdP during the authentication process.
    event_handler: Rc<RefCell<Option<EventListener>>>,
}

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
    pub async fn new_with_options(options: AuthClientCreateOptions) -> Result<Self, DelegationError> {
        let mut storage = options.storage.unwrap_or_default();

        let mut key: Option<ArcIdentityType> = None;

        if let Some(identity) = options.identity.clone() {
            key = Some(identity.into());
        } else {
            let maybe_local_storage = storage.get(KEY_STORAGE_KEY).await;

            if let Some(maybe_local_storage) = maybe_local_storage {
                let private_key = maybe_local_storage.decode();

                match private_key {
                    Ok(private_key) => {
                        key = Some(ArcIdentityType::Ed25519(Arc::new(
                            BasicIdentity::from_signing_key(private_key),
                        )));
                    }
                    Err(e) => {
                        error!("Failed to decode private key: ", e);
                    }
                }
            }
        }

        let mut identity = ArcIdentityType::Anonymous(Arc::new(AnonymousIdentity));
        let mut chain: Option<DelegationChain> = None;

        let options_identity_is_some = options.identity.is_some();

        if key.is_some() {
            let chain_storage = storage.get(KEY_STORAGE_DELEGATION).await;

            if let Some(op_identity) = options.identity {
                identity = op_identity.into();
            } else if let Some(chain_storage) = chain_storage {
                match chain_storage {
                    StoredKey::String(chain_storage) => {
                        chain = Some(DelegationChain::from_json(&chain_storage));

                        if chain.as_ref().unwrap().is_delegation_valid(None) {
                            let (public_key, delegations) = {
                                let chain = chain.as_mut().unwrap();
                                (
                                    mem::take(&mut chain.public_key),
                                    mem::take(&mut chain.delegations),
                                )
                            };
                            identity =
                                ArcIdentityType::Delegated(Arc::new(DelegatedIdentity::new_unchecked(
                                    public_key,
                                    Box::new(key.clone().unwrap().as_arc_identity()),
                                    delegations,
                                )));
                        } else {
                            Self::delete_storage(&mut storage).await;
                            key = None;
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
            && (chain.is_some() || options_identity_is_some)
        {
            let idle_manager_options: Option<IdleManagerOptions> = options
                .idle_options
                .as_ref()
                .map(|o| o.idle_manager_options.clone());
            idle_manager = Some(IdleManager::new(idle_manager_options));
        }

        if key.is_none() {
            let private_key = SigningKey::new(thread_rng());

            storage
                .set(KEY_STORAGE_KEY, StoredKey::encode(&private_key))
                .await;

            key = Some(ArcIdentityType::Ed25519(Arc::new(
                BasicIdentity::from_signing_key(private_key),
            )));
        }

        Ok(
            Self {
                identity: Rc::new(RefCell::new(identity)),
                key: key.unwrap(),
                storage,
                chain: Rc::new(RefCell::new(chain)),
                idle_manager,
                idle_options: Rc::new(options.idle_options),
                idp_window: Rc::new(RefCell::new(None)),
                event_handler: Rc::new(RefCell::new(None)),
            }
        )
    }

    /// Registers the default idle callback.
    fn register_default_idle_callback(
        identity: Rc<RefCell<ArcIdentityType>>,
        storage: AuthClientStorageType,
        chain: Rc<RefCell<Option<DelegationChain>>>,
        idle_manager: Option<IdleManager>,
        idle_options: Rc<Option<IdleOptions>>,
    ) {
        if let Some(options) = idle_options.as_ref() {
            if options.disable_default_idle_callback.unwrap_or_default() {
                return;
            }

            if options
                .idle_manager_options
                .on_idle
                .as_ref()
                .borrow()
                .is_none()
            {
                if let Some(idle_manager) = idle_manager.as_ref() {
                    let callback = {
                        let identity = identity.clone();
                        let storage = storage.clone();
                        let chain = chain.clone();
                        move || {
                            let identity = identity.clone();
                            let storage = storage.clone();
                            let chain = chain.clone();
                            spawn_local(async move {
                                Self::logout_core(identity, storage, chain, None).await;
                                window().location().reload().unwrap();
                            });
                        }
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
    ) -> Result<(), DelegationError>
    {
        let delegations = message.delegations.clone();
        let user_public_key = message.user_public_key.clone();

        {
            let mut chain_guard = self.chain.borrow_mut();
            *chain_guard = Some(DelegationChain {
                delegations: delegations.clone(),
                public_key: user_public_key.clone(),
            });

            let mut identity_guard = self.identity.borrow_mut();
            *identity_guard = ArcIdentityType::Delegated(Arc::new(
                DelegatedIdentity::new_unchecked(
                    user_public_key.clone(),
                    Box::new(self.key.as_arc_identity()),
                    delegations.clone(),
                )
            ));
        }

        if let Some(w) = self.idp_window.borrow_mut().take() {
            w.close().expect("Failed to close IdP window")
        };

        // create the idle manager on a successful login if we haven't disabled it
        // and it doesn't already exist.
        let disable_idle = match self.idle_options.as_ref() {
            Some(options) => options.disable_idle.unwrap_or(false),
            None => false,
        };
        if self.idle_manager.is_none() && !disable_idle {
            #[allow(clippy::manual_map)] // std Rc can't be mapped
            let idle_manager_options = match self.idle_options.as_ref() {
                Some(options) => Some(options.idle_manager_options.clone()),
                None => None,
            };

            let new_idle_manager = IdleManager::new(idle_manager_options);

            self.idle_manager.replace(new_idle_manager);

            Self::register_default_idle_callback(
                self.identity.clone(),
                self.storage.clone(),
                self.chain.clone(),
                self.idle_manager.clone(),
                self.idle_options.clone(),
            );
        }

        self.event_handler.take();

        let chain = self.chain.borrow().clone();

        if let Some(chain) = chain {
            self.storage
                .set(KEY_STORAGE_DELEGATION, chain.to_json())
                .await;
        }

        // on_success should be the last thing to do to avoid consumers
        // interfering by navigating or refreshing the page
        if let Some(on_success) = on_success {
            on_success.borrow_mut()(message);
        }

        Ok(())
    }

    /// Returns the identity of the user.
    pub fn identity(&self) -> Arc<dyn Identity> {
        let identity_guard = self.identity.borrow();
        identity_guard.as_arc_identity()
    }

    /// Checks if the user is authenticated.
    pub fn is_authenticated(&self) -> bool {
        let is_not_anonymous = self
            .identity()
            .sender()
            .map(|s| s != Principal::anonymous())
            .unwrap_or(false);

        let has_chain = self.chain.borrow().is_some();

        is_not_anonymous && has_chain
    }

    /// Logs the user in with default options.
    pub fn login(&mut self) {
        self.login_with_options(AuthClientLoginOptions::default());
    }

    /// Logs the user in with the provided options.
    pub fn login_with_options(&mut self, options: AuthClientLoginOptions) {
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
        if let Some(idp_window) = self.idp_window.borrow_mut().take() {
            idp_window.close().unwrap();
        }
        self.event_handler.take();

        // Open a new window with the IDP provider.
        self.idp_window = Rc::new(RefCell::new(
            window
                .open_with_url_and_target_and_features(
                    &identity_provider_url.href(),
                    "idpWindow",
                    options.window_opener_features.as_deref().unwrap_or(""),
                )
                .unwrap(),
        ));

        // Add an event listener to handle responses.
        self.event_handler.clone().replace(Some(
            self.get_event_handler(identity_provider_url.clone(), options.clone())
                .unwrap(),
        ));

        self.check_interruption(options.on_error);
    }

    /// Checks for user interruption during the login process.
    fn check_interruption(&self, on_error: Option<OnError>) {
        let event_handler = self.event_handler.clone();
        let idp_window = self.idp_window.clone();

        spawn_local({
            async move {
                loop {
                    // Lock the idp_window only once and release the lock immediately.
                    let idp_window_cloned = idp_window.borrow().clone();

                    // The idp_window is opened and not yet closed by the client.
                    if let Some(idp_window_cloned) = idp_window_cloned {
                        if idp_window_cloned.closed().unwrap() {
                            Self::handle_failure(
                                event_handler,
                                idp_window,
                                Some(ERROR_USER_INTERRUPT.to_string()),
                                on_error,
                            );
                            break;
                        }

                        sleep(INTERRUPT_CHECK_INTERVAL).await;
                    } else {
                        break;
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
    ) -> Result<EventListener, JsValue> {
        let client = self.clone();

        let callback = move |event: &web_sys::Event| {
            let event = event.dyn_ref::<MessageEvent>().unwrap();

            if event.origin() != identity_provider_url.origin() {
                // Ignore any event that is not from the identity provider
                return;
            }

            let message: IdentityServiceResponseMessage = match from_value(event.data()) {
                Ok(msg) => msg,
                Err(e) => {
                    error!(e);
                    return;
                }
            };

            let max_time_to_live = options
                .max_time_to_live
                .unwrap_or(Self::DEFAULT_TIME_TO_LIVE);

            match message.kind() {
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
                    let request_js_value = JsValue::from_serde(&request).unwrap();
                    let session_public_key = Uint8Array::from(&request.session_public_key[..]);
                    Reflect::set(
                        &request_js_value,
                        &JsValue::from_str("sessionPublicKey"),
                        &session_public_key.into(),
                    )
                    .unwrap();

                    if let Some(custom_values) = options.custom_values.clone() {
                        let custom_values = custom_values.into_iter().map(|(k, v)| {
                            (k, JsValue::from_serde(&v).unwrap())
                        }).collect::<HashMap<String, JsValue>>();
                        for (k, v) in custom_values {
                            Reflect::set(&request_js_value, &JsValue::from_str(&k), &v).unwrap();
                        }
                    }

                    if let Some(idp_window) = client.idp_window.borrow().as_ref() {
                        idp_window
                            .post_message(&request_js_value, &identity_provider_url.origin())
                            .unwrap();
                    }
                }
                IdentityServiceResponseKind::AuthSuccess(response) => {
                    let mut client = client.clone();
                    let on_success = options.on_success.clone();
                    spawn_local(async move {
                        client.handle_success(response, on_success).await.unwrap();
                    });
                }
                IdentityServiceResponseKind::AuthFailure(error_message) => {
                    let event_handler = client.event_handler.clone();
                    let idp_window = client.idp_window.clone();
                    let on_error = options.on_error.clone();
                    spawn_local(async move {
                        Self::handle_failure(
                            event_handler,
                            idp_window,
                            Some(error_message),
                            on_error,
                        );
                    });
                }
            }
        };

        Ok(EventListener::new(&window(), "message", callback))
    }

    /// Handles a failed authentication response.
    fn handle_failure(
        event_handler: Rc<RefCell<Option<EventListener>>>,
        idp_window: Rc<RefCell<Option<web_sys::Window>>>,
        error_message: Option<String>,
        on_error: Option<OnError>,
    ) {
        if let Some(idp_window) = idp_window.borrow_mut().take() {
            idp_window.close().unwrap();
        }

        if let Some(on_error) = on_error {
            on_error.borrow_mut()(error_message);
        }

        event_handler.clone().take();
    }

    /// Logs out the user and clears the stored identity.
    async fn logout_core(
        identity: Rc<RefCell<ArcIdentityType>>,
        mut storage: AuthClientStorageType,
        chain: Rc<RefCell<Option<DelegationChain>>>,
        return_to: Option<Location>,
    ) {
        Self::delete_storage(&mut storage).await;

        // Reset this auth client to a non-authenticated state.
        *identity.borrow_mut() = ArcIdentityType::Anonymous(Arc::new(AnonymousIdentity));
        chain.borrow_mut().take();

        // If a return URL is provided, redirect the user to that URL.
        if let Some(return_to) = return_to {
            let window = web_sys::window().unwrap();
            if window
                .history()
                .expect("No history found")
                .push_state_with_url(
                    &JsValue::null(),
                    "",
                    Some(return_to.href().unwrap().as_str()),
                )
                .is_err()
            {
                window
                    .location()
                    .set_href(&return_to.href().unwrap())
                    .expect("Failed to set href");
            }
        }
    }

    /// Log the user out.
    /// If a return URL is provided, the user will be redirected to that URL after logging out.
    pub async fn logout(&self, return_to: Option<Location>) {
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
        storage.remove(KEY_STORAGE_KEY).await;
        storage.remove(KEY_STORAGE_DELEGATION).await;
        storage.remove(KEY_VECTOR).await;
    }
}

/// Builder for the [`AuthClient`].
#[derive(Default)]
pub struct AuthClientBuilder {
    identity: Option<IdentityType>,
    storage: Option<AuthClientStorageType>,
    key_type: Option<BaseKeyType>,
    idle_options: IdleOptions,
}

impl AuthClientBuilder {
    /// Creates a new [`AuthClientBuilder`].
    fn new() -> Self {
        Self::default()
    }

    /// An optional identity to use as the base. If not provided, an `Ed25519` key pair will be used.
    pub fn identity(&mut self, identity: IdentityType) -> &mut Self {
        self.identity = Some(identity);
        self
    }

    /// Optional storage with get, set, and remove methods. Currentry only `LocalStorage` is supported.
    pub fn storage(&mut self, storage: AuthClientStorageType) -> &mut Self {
        self.storage = Some(storage);
        self
    }

    /// The type of key to use for the base key. If not provided, `Ed25519` will be used by default.
    pub fn key_type(&mut self, key_type: BaseKeyType) -> &mut Self {
        self.key_type = Some(key_type);
        self
    }

    /// Options for handling idle timeouts. If not provided, default options will be used.
    pub fn idle_options(&mut self, idle_options: IdleOptions) -> &mut Self {
        self.idle_options = idle_options;
        self
    }

    /// If set to `true`, disables the idle timeout functionality.
    pub fn disable_idle(&mut self, disable_idle: bool) -> &mut Self {
        self.idle_options.disable_idle = Some(disable_idle);
        self
    }

    /// If set to `true`, disables the default idle timeout callback.
    pub fn disable_default_idle_callback(&mut self, disable_default_idle_callback: bool) -> &mut Self {
        self.idle_options.disable_default_idle_callback = Some(disable_default_idle_callback);
        self
    }

    /// Options for the [`IdleManager`] that handles idle timeouts.
    pub fn idle_manager_options(&mut self, idle_manager_options: IdleManagerOptions) -> &mut Self {
        self.idle_options.idle_manager_options = idle_manager_options;
        self
    }

    /// A callback function to be executed when the system becomes idle.
    pub fn on_idle(&mut self, on_idle: fn()) -> &mut Self {
        self.idle_options.idle_manager_options.on_idle = Rc::new(RefCell::new(Some(Box::new(on_idle) as Box<dyn FnMut()>)));
        self
    }

    /// The duration of inactivity after which the system is considered idle.
    pub fn idle_timeout(&mut self, idle_timeout: u32) -> &mut Self {
        self.idle_options.idle_manager_options.idle_timeout = Some(idle_timeout);
        self
    }

    /// A delay for debouncing scroll events.
    pub fn scroll_debounce(&mut self, scroll_debounce: u32) -> &mut Self {
        self.idle_options.idle_manager_options.scroll_debounce = Some(scroll_debounce);
        self
    }

    /// A flag indicating whether to capture scroll events.
    pub fn capture_scroll(&mut self, capture_scroll: bool) -> &mut Self {
        self.idle_options.idle_manager_options.capture_scroll = Some(capture_scroll);
        self
    }

    /// Builds a new [`AuthClient`].
    pub async fn build(&mut self) -> Result<AuthClient, DelegationError> {
        let options = AuthClientCreateOptions {
            identity: mem::take(&mut self.identity),
            storage: mem::take(&mut self.storage),
            key_type: mem::take(&mut self.key_type),
            idle_options: Some(mem::take(&mut self.idle_options)),
        };

        AuthClient::new_with_options(options).await
    }
}

/// Enum representing the different types of identity to use as the base.
#[derive(Clone)]
pub enum IdentityType {
    Anonymous(AnonymousIdentity),
    Ed25519(Arc<BasicIdentity>),
    Delegated(Arc<DelegatedIdentity>),
}

impl From<IdentityType> for ArcIdentityType {
    fn from(id: IdentityType) -> Self {
        match id {
            IdentityType::Anonymous(id) => ArcIdentityType::Anonymous(Arc::new(id)),
            IdentityType::Ed25519(id) => ArcIdentityType::Ed25519(id),
            IdentityType::Delegated(id) => ArcIdentityType::Delegated(id),
        }
    }
}

#[derive(Clone)]
enum ArcIdentityType {
    Anonymous(Arc<AnonymousIdentity>),
    Ed25519(Arc<BasicIdentity>),
    Delegated(Arc<DelegatedIdentity>),
}

impl ArcIdentityType {
    fn as_arc_identity(&self) -> Arc<dyn Identity> {
        match self {
            ArcIdentityType::Anonymous(id) => id.clone(),
            ArcIdentityType::Ed25519(id) => id.clone(),
            ArcIdentityType::Delegated(id) => id.clone(),
        }
    }

    fn public_key(&self) -> Option<Vec<u8>> {
        match self {
            ArcIdentityType::Anonymous(id) => id.public_key(),
            ArcIdentityType::Ed25519(id) => id.public_key(),
            ArcIdentityType::Delegated(id) => id.public_key(),
        }
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
    on_success: Option<Box<dyn FnMut(AuthResponseSuccess)>>,
    on_error: Option<Box<dyn FnMut(Option<String>)>>,
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
        F: FnMut(AuthResponseSuccess) + 'static,
    {
        self.on_success = Some(Box::new(on_success));
        self
    }

    /// Callback in case authentication fails.
    pub fn on_error<F>(mut self, on_error: F) -> Self
    where
        F: FnMut(Option<String>) + 'static,
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
            on_success: self.on_success.map(|f| Rc::new(RefCell::new(f))),
            on_error: self.on_error.map(|f| Rc::new(RefCell::new(f))),
            custom_values: self.custom_values,
        }
    }
}

/// Options for creating a new [`AuthClient`].
#[derive(Default)]
pub struct AuthClientCreateOptions {
    /// An optional identity to use as the base. If not provided, an `Ed25519` key pair will be used.
    pub identity: Option<IdentityType>,
    /// Optional storage with get, set, and remove methods. Currentry only `LocalStorage` is supported.
    pub storage: Option<AuthClientStorageType>,
    /// The type of key to use for the base key. If not provided, `Ed25519` will be used by default.
    pub key_type: Option<BaseKeyType>,
    /// Options for handling idle timeouts. If not provided, default options will be used.
    pub idle_options: Option<IdleOptions>,
}

/// Options for handling idle timeouts.
#[derive(Default)]
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
    pub fn disable_idle(&mut self, disable_idle: bool) -> &mut Self {
        self.disable_idle = Some(disable_idle);
        self
    }

    /// If set to `true`, disables the default idle timeout callback.
    pub fn disable_default_idle_callback(&mut self, disable_default_idle_callback: bool) -> &mut Self {
        self.disable_default_idle_callback = Some(disable_default_idle_callback);
        self
    }

    /// Options for the [`IdleManager`] that handles idle timeouts.
    pub fn idle_manager_options(&mut self, idle_manager_options: IdleManagerOptions) -> &mut Self {
        self.idle_manager_options = idle_manager_options;
        self
    }

    /// A callback function to be executed when the system becomes idle.
    pub fn on_idle(&mut self, on_idle: fn()) -> &mut Self {
        self.idle_manager_options.on_idle = Rc::new(RefCell::new(Some(Box::new(on_idle) as Box<dyn FnMut()>)));
        self
    }

    /// The duration of inactivity after which the system is considered idle.
    pub fn idle_timeout(&mut self, idle_timeout: u32) -> &mut Self {
        self.idle_manager_options.idle_timeout = Some(idle_timeout);
        self
    }

    /// A delay for debouncing scroll events.
    pub fn scroll_debounce(&mut self, scroll_debounce: u32) -> &mut Self {
        self.idle_manager_options.scroll_debounce = Some(scroll_debounce);
        self
    }

    /// A flag indicating whether to capture scroll events.
    pub fn capture_scroll(&mut self, capture_scroll: bool) -> &mut Self {
        self.idle_manager_options.capture_scroll = Some(capture_scroll);
        self
    }

    /// Build the [`IdleOptions`].
    pub fn build(&mut self) -> IdleOptions {
        IdleOptions {
            disable_idle: mem::take(&mut self.disable_idle),
            disable_default_idle_callback: mem::take(&mut self.disable_default_idle_callback),
            idle_manager_options: mem::take(&mut self.idle_manager_options),
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

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_idle_options_builder() {
        let mut builder = IdleOptionsBuilder::new();
        builder.disable_idle(true);
        builder.disable_default_idle_callback(true);
        builder.on_idle(|| {});
        builder.idle_timeout(1000);
        builder.scroll_debounce(500);
        builder.capture_scroll(true);
        let options = builder.build();
        assert_eq!(options.disable_idle, Some(true));
        assert_eq!(options.disable_default_idle_callback, Some(true));
        assert!(options.idle_manager_options.on_idle.borrow().is_some());
        assert_eq!(options.idle_manager_options.idle_timeout, Some(1000));
        assert_eq!(options.idle_manager_options.scroll_debounce, Some(500));
        assert_eq!(options.idle_manager_options.capture_scroll, Some(true));
    }

    #[wasm_bindgen_test]
    fn test_idle_options_builder_chaining() {
        let options = IdleOptions::builder()
            .disable_idle(true)
            .disable_default_idle_callback(true)
            .on_idle(|| {})
            .idle_timeout(1000)
            .scroll_debounce(500)
            .capture_scroll(true)
            .build();
        assert_eq!(options.disable_idle, Some(true));
        assert_eq!(options.disable_default_idle_callback, Some(true));
        assert!(options.idle_manager_options.on_idle.borrow().is_some());
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
        let private_key = SigningKey::new(thread_rng());
        let identity = IdentityType::Ed25519(Arc::new(BasicIdentity::from_signing_key(private_key)));

        let idle_options = IdleOptions::builder()
            .disable_idle(true)
            .disable_default_idle_callback(true)
            .on_idle(|| {})
            .idle_timeout(1000)
            .scroll_debounce(500)
            .capture_scroll(true)
            .build();

        let auth_client = AuthClient::builder()
            .identity(identity)
            .idle_options(idle_options)
            .build()
            .await
            .unwrap();

        assert!(!auth_client.is_authenticated());
    }

    #[wasm_bindgen_test]
    fn test_auth_client_login_options_builder() {
        let custom_values = vec![("key".to_string(), "value".into())].into_iter().collect();

        let options = AuthClientLoginOptions::builder()
            .allow_pin_authentication(true)
            .custom_values(custom_values)
            .on_error(|_| {})
            .on_success(|_| {})
            .build();

        assert_eq!(options.allow_pin_authentication, Some(true));
        assert!(options.on_error.is_some());
        assert!(options.on_success.is_some());
    }
}
