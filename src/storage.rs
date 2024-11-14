use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
use ed25519_consensus::{SigningKey, Error as Ed25519Error};
use std::{cell::RefCell, future::Future, rc::Rc};
use web_sys::{wasm_bindgen::JsValue, Storage};

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
    pub fn decode(&self) -> Result<SigningKey, DecodeError> {
        match self {
            StoredKey::String(s) => {
                let bytes = BASE64_STANDARD_NO_PAD.decode(s).map_err(DecodeError::Base64)?;
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| DecodeError::Ed25519(Ed25519Error::InvalidSliceLength))?;
                Ok(SigningKey::from(bytes))
            },
        }
    }

    pub fn encode(key: &SigningKey) -> String {
        BASE64_STANDARD_NO_PAD.encode(key.as_bytes())
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
    Ed25519(Ed25519Error),
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

    fn set<S: AsRef<str>, T: AsRef<str>>(&mut self, key: S, value: T) -> impl Future<Output = ()>;

    fn remove<T: AsRef<str>>(&mut self, key: T) -> impl Future<Output = ()>;
}

/// Implementation of [`AuthClientStorage`].
#[derive(Debug, Default, Clone)]
pub struct LocalStorage {
    local_storage: Option<Storage>,
}

impl LocalStorage {
    pub fn new(local_storage: Option<Storage>) -> Self {
        LocalStorage { local_storage }
    }

    fn get_local_storage(&self) -> Result<Storage, JsValue> {
        if let Some(local_storage) = self.local_storage.clone() {
            return Ok(local_storage);
        }

        if let Some(window) = web_sys::window() {
            let local_storage = window.local_storage()?;
            local_storage.ok_or("Could not find local storage.".into())
        } else {
            Err("No window found".into())
        }
    }
}

impl AuthClientStorage for LocalStorage {
    async fn get<T: AsRef<str>>(&mut self, key: T) -> Option<StoredKey> {
        let local_storage = self.get_local_storage().unwrap();
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        let value = local_storage.get_item(&key).unwrap();
        value.map(StoredKey::String)
    }

    async fn set<S: AsRef<str>, T: AsRef<str>>(&mut self, key: S, value: T) {
        let local_storage = self.get_local_storage().unwrap();
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        local_storage.set_item(&key, value.as_ref()).unwrap();
    }

    async fn remove<T: AsRef<str>>(&mut self, key: T) {
        let local_storage = self.get_local_storage().unwrap();
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        local_storage.remove_item(&key).unwrap();
    }
}

/// Enum for selecting the type of storage to use for [`AuthClient`](super::AuthClient).
#[derive(Debug, Clone)]
pub enum AuthClientStorageType {
    LocalStorage(Rc<RefCell<LocalStorage>>),
}

impl Default for AuthClientStorageType {
    fn default() -> Self {
        AuthClientStorageType::LocalStorage(Rc::new(RefCell::new(LocalStorage::new(None))))
    }
}

impl AuthClientStorage for AuthClientStorageType {
    async fn get<T: AsRef<str>>(&mut self, key: T) -> Option<StoredKey> {
        match self {
            AuthClientStorageType::LocalStorage(storage) => {
                let mut storage = storage.borrow_mut().clone();
                storage.get(key).await
            }
        }
    }

    async fn set<S: AsRef<str>, T: AsRef<str>>(&mut self, key: S, value: T) {
        match self {
            AuthClientStorageType::LocalStorage(storage) => {
                let mut storage = storage.borrow_mut().clone();
                storage.set(key, value).await
            }
        }
    }

    async fn remove<T: AsRef<str>>(&mut self, key: T) {
        match self {
            AuthClientStorageType::LocalStorage(storage) => {
                let mut storage = storage.borrow_mut().clone();
                storage.remove(key).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[test]
    fn test_stored_key_encode_decode() {
        let rng = rand::thread_rng();
        let signing_key = SigningKey::new(rng);

        let encoded = StoredKey::encode(&signing_key);
        let key = StoredKey::String(encoded);
        let decoded = key.decode().unwrap();
        assert_eq!(signing_key.as_bytes(), decoded.as_bytes());
    }

    #[allow(dead_code)]
    #[wasm_bindgen_test]
    async fn test_local_storage() {
        let mut storage = LocalStorage::default();
        storage.set("test", "value").await;
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, StoredKey::String("value".to_string()));
        storage.remove("test").await;
        let value = storage.get("test").await;
        assert_eq!(value, None);
    }

    #[allow(dead_code)]
    #[wasm_bindgen_test]
    async fn test_auth_client_storage_type() {
        let mut storage = AuthClientStorageType::LocalStorage(Rc::new(RefCell::new(LocalStorage::default())));
        storage.set("test", "value").await;
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, StoredKey::String("value".to_string()));
        storage.remove("test").await;
        let value = storage.get("test").await;
        assert_eq!(value, None);
    }
}
