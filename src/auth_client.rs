use crate::storage::DecodeError;
use thiserror::Error;

#[cfg(feature = "native")]
mod native;
#[cfg(feature = "wasm-js")]
mod wasm_js;

#[cfg(feature = "native")]
pub use native::{NativeAuthClient, NativeLoginError};
#[cfg(feature = "wasm-js")]
pub use wasm_js::AuthClient;

/// The error type for the auth client.
#[derive(Error, Debug)]
pub enum AuthClientError {
    /// An error from the storage.
    #[error("Storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    /// An error from the delegation.
    #[error("Delegation error: {0}")]
    Delegation(#[from] ic_agent::identity::DelegationError),
}

impl From<DecodeError> for AuthClientError {
    fn from(err: DecodeError) -> Self {
        AuthClientError::Storage(err.into())
    }
}
