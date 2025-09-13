use base64::prelude::{BASE64_STANDARD_NO_PAD, Engine as _};
use std::future::Future;
use web_sys::{Storage, wasm_bindgen::JsValue};

/// A key for storing the identity key pair.
pub const KEY_STORAGE_KEY: &str = "identity";
/// A key for storing the delegation chain.
pub const KEY_STORAGE_DELEGATION: &str = "delegation";
pub(crate) const KEY_VECTOR: &str = "iv";

const LOCAL_STORAGE_PREFIX: &str = "ic-";

/// Enum for storing different types of keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredKey {
    String(String),
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
        }
    }

    pub fn encode(key: &[u8; 32]) -> String {
        BASE64_STANDARD_NO_PAD.encode(key)
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

impl From<DecodeError> for JsValue {
    fn from(err: DecodeError) -> Self {
        JsValue::from_str(&err.to_string())
    }
}

/// Trait for persisting user authentication data.
pub trait AuthClientStorage {
    fn get<T: AsRef<str>>(&mut self, key: T) -> impl Future<Output = Option<StoredKey>>;

    fn set<S: AsRef<str>, T: AsRef<str>>(
        &mut self,
        key: S,
        value: T,
    ) -> impl Future<Output = Result<(), ()>>;

    fn remove<T: AsRef<str>>(&mut self, key: T) -> impl Future<Output = Result<(), ()>>;
}

/// Implementation of [`AuthClientStorage`].
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalStorage;

impl LocalStorage {
    pub fn new() -> Self {
        LocalStorage
    }

    fn get_local_storage(&self) -> Option<Storage> {
        match gloo_utils::window().local_storage() {
            Ok(storage) => storage,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Could not find local storage: {_e:?}");
                None
            }
        }
    }
}

impl AuthClientStorage for LocalStorage {
    async fn get<T: AsRef<str>>(&mut self, key: T) -> Option<StoredKey> {
        let local_storage = self.get_local_storage()?;
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        let value = match local_storage.get_item(&key) {
            Ok(value) => value,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Could not get item from local storage: {_e:?}");
                return None;
            }
        };
        value.map(StoredKey::String)
    }

    async fn set<S: AsRef<str>, T: AsRef<str>>(&mut self, key: S, value: T) -> Result<(), ()> {
        let local_storage = match self.get_local_storage() {
            Some(local_storage) => local_storage,
            None => return Err(()),
        };
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        match local_storage.set_item(&key, value.as_ref()) {
            Ok(_) => Ok(()),
            Err(_) => {
                #[cfg(feature = "tracing")]
                error!("Could not set item in local storage");
                Err(())
            }
        }
    }

    async fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), ()> {
        let local_storage = match self.get_local_storage() {
            Some(local_storage) => local_storage,
            None => return Err(()),
        };
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        match local_storage.remove_item(&key) {
            Ok(_) => Ok(()),
            Err(_) => {
                #[cfg(feature = "tracing")]
                error!("Could not remove item from local storage");
                Err(())
            }
        }
    }
}

/// Enum for selecting the type of storage to use for [`AuthClient`](super::AuthClient).
#[derive(Debug, Clone)]
pub enum AuthClientStorageType {
    LocalStorage(LocalStorage),
}

impl Default for AuthClientStorageType {
    fn default() -> Self {
        AuthClientStorageType::LocalStorage(LocalStorage::new())
    }
}

impl AuthClientStorage for AuthClientStorageType {
    async fn get<T: AsRef<str>>(&mut self, key: T) -> Option<StoredKey> {
        match self {
            AuthClientStorageType::LocalStorage(storage) => storage.get(key).await,
        }
    }

    async fn set<S: AsRef<str>, T: AsRef<str>>(&mut self, key: S, value: T) -> Result<(), ()> {
        match self {
            AuthClientStorageType::LocalStorage(storage) => storage.set(key, value).await,
        }
    }

    async fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), ()> {
        match self {
            AuthClientStorageType::LocalStorage(storage) => storage.remove(key).await,
        }
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use wasm_bindgen_test::*;

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

    #[wasm_bindgen_test]
    async fn test_local_storage() {
        let mut storage = LocalStorage;
        storage.set("test", "value").await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, StoredKey::String("value".to_string()));
        storage.remove("test").await.unwrap();
        let value = storage.get("test").await;
        assert_eq!(value, None);
    }

    #[wasm_bindgen_test]
    async fn test_auth_client_storage_type() {
        let mut storage = AuthClientStorageType::LocalStorage(LocalStorage);
        storage.set("test", "value").await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, StoredKey::String("value".to_string()));
        storage.remove("test").await.unwrap();
        let value = storage.get("test").await;
        assert_eq!(value, None);
    }
}
