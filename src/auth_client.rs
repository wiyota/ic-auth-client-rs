use crate::{api::AuthResponseSuccess, idle_manager::IdleManagerOptions};
use futures::future::BoxFuture;
use ic_agent::identity::{AnonymousIdentity, BasicIdentity, DelegatedIdentity, Identity};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

#[cfg(not(target_family = "wasm"))]
mod native;
#[cfg(target_family = "wasm")]
#[cfg(feature = "wasm-js")]
mod wasm_js;

#[cfg(not(target_family = "wasm"))]
pub use native::*;
#[cfg(target_family = "wasm")]
#[cfg(feature = "wasm-js")]
pub use wasm_js::*;

const ED25519_KEY_LABEL: &str = "Ed25519";

// Callbacks

#[derive(Clone)]
struct OnSuccess(Arc<Mutex<Box<dyn FnMut(AuthResponseSuccess) + Send>>>);

impl<F> From<F> for OnSuccess
where
    F: FnMut(AuthResponseSuccess) + Send + 'static,
{
    fn from(f: F) -> Self {
        OnSuccess(Arc::new(Mutex::new(Box::new(f))))
    }
}

#[derive(Clone)]
struct OnSuccessAsync(
    Arc<Mutex<Box<dyn FnMut(AuthResponseSuccess) -> BoxFuture<'static, ()> + Send>>>,
);

impl<F, Fut> From<F> for OnSuccessAsync
where
    F: FnMut(AuthResponseSuccess) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn from(mut f: F) -> Self {
        use futures::future::FutureExt;
        OnSuccessAsync(Arc::new(Mutex::new(Box::new(move |arg| f(arg).boxed()))))
    }
}

#[derive(Clone)]
struct OnError(Arc<Mutex<Box<dyn FnMut(Option<String>) + Send>>>);

impl<F> From<F> for OnError
where
    F: FnMut(Option<String>) + Send + 'static,
{
    fn from(f: F) -> Self {
        OnError(Arc::new(Mutex::new(Box::new(f))))
    }
}

#[derive(Clone)]
struct OnErrorAsync(Arc<Mutex<Box<dyn FnMut(Option<String>) -> BoxFuture<'static, ()> + Send>>>);

impl<F, Fut> From<F> for OnErrorAsync
where
    F: FnMut(Option<String>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn from(mut f: F) -> Self {
        use futures::future::FutureExt;
        OnErrorAsync(Arc::new(Mutex::new(Box::new(move |arg| f(arg).boxed()))))
    }
}

// Key-related structs and enums

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

// Identity-related structs and enums

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

impl From<ic_agent::identity::BasicIdentity> for ArcIdentity {
    fn from(identity: ic_agent::identity::BasicIdentity) -> Self {
        ArcIdentity::Ed25519(Arc::new(identity))
    }
}

impl From<DelegatedIdentity> for ArcIdentity {
    fn from(identity: DelegatedIdentity) -> Self {
        ArcIdentity::Delegated(Arc::new(identity))
    }
}

// Option structs

/// Options for the [`AuthClient::login_with_options`].
#[derive(Clone, Default, bon::Builder)]
#[builder(on(String, into))]
pub struct AuthClientLoginOptions {
    /// The URL of the identity provider.
    identity_provider: Option<String>,

    /// Expiration of the authentication in nanoseconds.
    max_time_to_live: Option<u64>,

    /// If present, indicates whether or not the Identity Provider should allow the user to authenticate and/or register using a temporary key/PIN identity.
    ///
    /// Authenticating dapps may want to prevent users from using Temporary keys/PIN identities because Temporary keys/PIN identities are less secure than Passkeys (webauthn credentials) and because Temporary keys/PIN identities generally only live in a browser database (which may get cleared by the browser/OS).
    allow_pin_authentication: Option<bool>,

    /// Origin for Identity Provider to use while generating the delegated identity. For II, the derivation origin must authorize this origin by setting a record at `<derivation-origin>/.well-known/ii-alternative-origins`.
    ///
    /// See: <https://github.com/dfinity/internet-identity/blob/main/docs/ii-spec.mdx#alternative-frontend-origins>
    derivation_origin: Option<String>,

    /// Auth Window feature config string.
    ///
    /// # Example
    /// ```ignore
    /// toolbar=0,location=0,menubar=0,width=500,height=500,left=100,top=100
    /// ```
    window_opener_features: Option<String>,

    /// Callback once login has completed.
    #[builder(into)]
    on_success: Option<OnSuccess>,

    /// Async callback once login has completed.
    #[builder(into)]
    on_success_async: Option<OnSuccessAsync>,

    /// Callback in case authentication fails.
    #[builder(into)]
    on_error: Option<OnError>,

    /// Async callback in case authentication fails.
    #[builder(into)]
    on_error_async: Option<OnErrorAsync>,

    /// Extra values to be passed in the login request during the authorize-ready phase.
    custom_values: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Options for handling idle timeouts.
#[derive(Default, Clone, Debug, bon::Builder)]
pub struct IdleOptions {
    /// If set to `true`, disables the idle timeout functionality.
    pub disable_idle: Option<bool>,
    /// If set to `true`, disables the default idle timeout callback.
    pub disable_default_idle_callback: Option<bool>,
    /// Options for the [`IdleManager`] that handles idle timeouts.
    pub idle_manager_options: IdleManagerOptions,
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
