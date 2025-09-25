//! Native authentication client configuration and options.

use crate::{
    ArcIdentity, IdleOptions, key::BaseKeyType, storage::sync_storage::AuthClientStorageType,
};

/// Options for creating a new [`NativeAuthClient`].
#[derive(Clone, bon::Builder)]
pub struct NativeAuthClientCreateOptions {
    /// An optional identity to use as the base. If not provided, an `Ed25519` key pair will be used.
    pub identity: Option<ArcIdentity>,
    /// Storage with get, set, and remove methods. Currentry only `KeyringStorage` is supported.
    pub storage: AuthClientStorageType,
    /// The type of key to use for the base key. If not provided, `Ed25519` will be used by default.
    pub key_type: Option<BaseKeyType>,
    /// Options for handling idle timeouts. If not provided, default options will be used.
    pub idle_options: Option<IdleOptions>,
}
