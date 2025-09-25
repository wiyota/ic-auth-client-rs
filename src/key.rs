//! Key management functionality for cryptographic operations.
//!
//! The module defines types for handling cryptographic keys that can contain both
//! raw key material and identity interfaces. This is particularly useful when working
//! with the Internet Computer (IC) agent where you need both access to raw keys
//! and the ability to use them as identities for signing operations.
//!
//! # Main Types
//!
//! - [`Key`] - An enum that can represent either a key with raw bytes or just an identity
//! - [`KeyWithRaw`] - A struct that contains both raw key bytes and the associated identity
//! - [`BaseKeyType`] - An enum representing supported key types (currently only Ed25519)
//!
//! # Examples
//!
//! ```rust
//! use ic_auth_client::key::{Key, KeyWithRaw};
//!
//! // Create a key from raw bytes
//! let raw_key = [0u8; 32]; // Your actual key bytes
//! let key_with_raw = KeyWithRaw::new(raw_key);
//! let key = Key::WithRaw(key_with_raw);
//!
//! // Use the key as an identity
//! let identity = key.as_arc_identity();
//!
//! // Get public key bytes
//! if let Some(public_key) = key.public_key() {
//!     println!("Public key: {:?}", public_key);
//! }
//! ```

use crate::ArcIdentity;
use ic_agent::identity::{BasicIdentity, Identity};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc};

const ED25519_KEY_LABEL: &str = "Ed25519";

/// A key that contains both the raw key bytes and the associated identity.
///
/// This struct wraps a 32-byte key with its corresponding identity implementation,
/// providing access to both the raw key material and the identity interface.
#[derive(Clone, Debug)]
pub struct KeyWithRaw {
    pub(crate) key: [u8; 32],
    pub(crate) identity: ArcIdentity,
}

impl KeyWithRaw {
    /// Creates a new `KeyWithRaw` from a raw 32-byte key.
    ///
    /// # Arguments
    ///
    /// * `raw_key` - A 32-byte array containing the raw key material
    ///
    /// # Returns
    ///
    /// A new `KeyWithRaw` instance with the key and its associated Ed25519 identity
    pub fn new(raw_key: [u8; 32]) -> Self {
        KeyWithRaw {
            key: raw_key,
            identity: ArcIdentity::Ed25519(Arc::new(BasicIdentity::from_raw_key(&raw_key))),
        }
    }

    /// Returns a reference to the raw key bytes.
    ///
    /// # Returns
    ///
    /// A reference to the 32-byte raw key array
    pub fn raw_key(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Represents a cryptographic key that can be either a raw key with its bytes or just an identity.
///
/// This enum allows for flexible key handling where sometimes you need access to the raw key
/// material and sometimes you only need the identity interface.
#[derive(Clone, Debug)]
pub enum Key {
    /// A key that includes both raw key bytes and the identity
    WithRaw(KeyWithRaw),
    /// A key that only provides the identity interface without raw bytes
    Identity(ArcIdentity),
}

impl Key {
    /// Returns the key as an `Arc<dyn Identity>` for use with the IC agent.
    ///
    /// # Returns
    ///
    /// An `Arc<dyn Identity>` that can be used for signing operations
    pub fn as_arc_identity(&self) -> Arc<dyn Identity> {
        match self {
            Key::WithRaw(key) => key.identity.as_arc_identity(),
            Key::Identity(identity) => identity.as_arc_identity(),
        }
    }

    /// Returns the public key bytes if available.
    ///
    /// # Returns
    ///
    /// An `Option<Vec<u8>>` containing the public key bytes, or `None` if not available
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

impl From<&Key> for ArcIdentity {
    fn from(key: &Key) -> Self {
        match key {
            Key::WithRaw(key) => key.identity.clone(),
            Key::Identity(identity) => identity.clone(),
        }
    }
}

impl From<ArcIdentity> for Key {
    fn from(identity: ArcIdentity) -> Self {
        Key::Identity(identity)
    }
}

impl From<&ArcIdentity> for Key {
    fn from(identity: &ArcIdentity) -> Self {
        Key::Identity(identity.clone())
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
