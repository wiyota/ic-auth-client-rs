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
