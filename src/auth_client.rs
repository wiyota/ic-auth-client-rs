use ic_agent::identity::{AnonymousIdentity, BasicIdentity, DelegatedIdentity, Identity};
use std::{fmt, sync::Arc};

#[cfg(feature = "native")]
mod native;
#[cfg(feature = "wasm-js")]
mod wasm_js;

#[cfg(feature = "native")]
pub use native::NativeAuthClient;
#[cfg(feature = "wasm-js")]
pub use wasm_js::AuthClient;

/// Arc-wrapped identity that can be one of several identity types.
///
/// This enum provides a way to work with different identity types in a uniform manner
/// while maintaining reference counting through [`Arc`](std::sync::Arc) for efficient cloning and sharing.
#[derive(Clone)]
pub enum ArcIdentity {
    /// An anonymous identity that provides no authentication.
    Anonymous(Arc<AnonymousIdentity>),
    /// An Ed25519-based identity using a basic cryptographic key pair.
    Ed25519(Arc<BasicIdentity>),
    /// A delegated identity that uses delegation chains for authentication.
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
    /// Returns the underlying identity as an [`Arc<dyn Identity>`](https://docs.rs/ic-agent/latest/ic_agent/identity/trait.Identity.html#impl-Identity-for-Arc%3Cdyn+Identity%3E).
    ///
    /// [`Arc<dyn Identity>`](https://docs.rs/ic-agent/latest/ic_agent/identity/trait.Identity.html#impl-Identity-for-Arc%3Cdyn+Identity%3E) implements the [`Identity`](ic_agent::identity::Identity) trait, making it directly usable for tasks like login.
    pub fn as_arc_identity(&self) -> Arc<dyn Identity> {
        match self {
            ArcIdentity::Anonymous(id) => id.clone(),
            ArcIdentity::Ed25519(id) => id.clone(),
            ArcIdentity::Delegated(id) => id.clone(),
        }
    }

    /// Returns the public key associated with this identity, if available.
    ///
    /// This method delegates to the underlying identity's [`public_key()`](ic_agent::identity::Identity::public_key) method.
    /// The availability and format of the public key depends on the specific identity type.
    pub fn public_key(&self) -> Option<Vec<u8>> {
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
