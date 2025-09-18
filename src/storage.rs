use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};

#[cfg(target_family = "wasm")]
#[cfg(feature = "wasm-js")]
pub mod async_storage;
#[cfg(not(target_family = "wasm"))]
pub mod sync_storage;

/// A key for storing the identity key pair.
pub const KEY_STORAGE_KEY: &str = "identity";
/// A key for storing the delegation chain.
pub const KEY_STORAGE_DELEGATION: &str = "delegation";
pub(crate) const KEY_VECTOR: &str = "iv";

/// Enum for storing different types of keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredKey {
    String(String),
    Raw([u8; 32]),
}

impl StoredKey {
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

    pub fn encode(key: &[u8; 32]) -> String {
        BASE64_STANDARD_NO_PAD.encode(key)
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

#[derive(Debug, Clone, thiserror::Error)]
pub enum DecodeError {
    #[error("Ed25519 error: {0}")]
    Ed25519(String),
    #[error("Base64 error: {0}")]
    Base64(base64::DecodeError),
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

        let encoded = StoredKey::encode(&raw_key);
        let key = StoredKey::String(encoded);
        let decoded = key.decode().unwrap();
        assert_eq!(raw_key, decoded);
    }
}
