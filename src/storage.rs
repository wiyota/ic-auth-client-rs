//! Storage module for managing key storage.
//!
//! This module provides utilities for storing and retrieving keys securely.
//! It includes support for both asynchronous and synchronous storage backends.

use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};
use thiserror::Error;

#[cfg(feature = "wasm-js")]
pub mod async_storage;
#[cfg(feature = "native")]
pub mod sync_storage;

/// A key for storing the identity key pair.
pub const KEY_STORAGE_KEY: &str = "identity";
/// A key for storing the delegation chain.
pub const KEY_STORAGE_DELEGATION: &str = "delegation";
pub(crate) const KEY_VECTOR: &str = "iv";

/// Enum for storing different types of keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredKey {
    /// A base64-encoded string representation of a 32-byte key.
    String(String),
    /// Raw 32-byte key data.
    Raw([u8; 32]),
}

impl StoredKey {
    /// Decodes the stored key into a 32-byte array.
    ///
    /// For `String` variants, decodes from base64. For `Raw` variants, returns the bytes directly.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError::Base64` if base64 decoding fails.
    /// Returns `DecodeError::Ed25519` if the decoded data is not exactly 32 bytes.
    pub fn decode(&self) -> Result<[u8; 32], DecodeError> {
        match self {
            StoredKey::String(s) => {
                let bytes = BASE64_STANDARD_NO_PAD
                    .decode(s)
                    .map_err(DecodeError::Base64)?;
                let bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| DecodeError::Ed25519("Invalid slice length".to_string()))?;
                Ok(bytes)
            }
            StoredKey::Raw(bytes) => Ok(*bytes),
        }
    }

    /// Encodes the stored key as a string.
    ///
    /// For `String` variants, returns the string directly. For `Raw` variants, encodes as base64.
    pub fn encode(&self) -> String {
        match self {
            StoredKey::String(s) => s.clone(),
            StoredKey::Raw(bytes) => BASE64_STANDARD_NO_PAD.encode(bytes),
        }
    }
}

impl From<[u8; 32]> for StoredKey {
    fn from(value: [u8; 32]) -> Self {
        StoredKey::Raw(value)
    }
}

impl TryFrom<Vec<u8>> for StoredKey {
    type Error = DecodeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value
            .try_into()
            .map_err(|_| DecodeError::Ed25519("Invalid slice length".to_string()))?;
        Ok(StoredKey::Raw(bytes))
    }
}

impl From<String> for StoredKey {
    fn from(value: String) -> Self {
        StoredKey::String(value)
    }
}

/// Error type for key decoding operations.
///
/// This enum represents the various errors that can occur when decoding
/// stored keys, including Ed25519-specific errors and base64 decoding errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DecodeError {
    /// An error related to Ed25519 key operations.
    ///
    /// This variant is used for Ed25519-specific errors, such as invalid
    /// key lengths or malformed key data.
    #[error("Ed25519 error: {0}")]
    Ed25519(String),
    /// An error that occurred during base64 decoding.
    ///
    /// This variant wraps base64 decoding errors that can occur when
    /// converting string-encoded keys back to binary format.
    #[error("Base64 error: {0}")]
    Base64(base64::DecodeError),
}

/// Error type for storage operations.
#[derive(Error, Debug)]
pub enum StorageError {
    /// An error from the keyring.
    #[error("Keyring error: {0}")]
    Keyring(String),
    /// An error from the web-sys storage.
    #[error("Web Sys error: {0}")]
    WebSys(String),
    /// An error that occurred during decoding.
    #[error("Decode error: {0}")]
    Decode(#[from] DecodeError),
}

#[cfg(feature = "native")]
impl From<keyring::Error> for StorageError {
    fn from(err: keyring::Error) -> Self {
        StorageError::Keyring(err.to_string())
    }
}

#[cfg(feature = "wasm-js")]
impl From<web_sys::wasm_bindgen::JsValue> for StorageError {
    fn from(err: web_sys::wasm_bindgen::JsValue) -> Self {
        StorageError::WebSys(
            err.as_string()
                .unwrap_or_else(|| "unknown websys error".to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_stored_key_encode_decode() {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let raw_key = signing_key.to_bytes();

        let encoded = StoredKey::Raw(raw_key).encode();
        let key = StoredKey::String(encoded);
        let decoded = key.decode().unwrap();
        assert_eq!(raw_key, decoded);
    }
}
