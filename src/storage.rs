use base64::prelude::{Engine as _, BASE64_STANDARD_NO_PAD};
use ed25519_consensus::{SigningKey, Error as Ed25519Error};
use std::{cell::RefCell, future::Future, rc::Rc};
use web_sys::{wasm_bindgen::JsValue, CryptoKeyPair, Storage};

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
    CryptoKeyPair(CryptoKeyPair),
}

impl StoredKey {
    pub fn decode(&self) -> Result<SigningKey, DecodeError> {
        match self {
            StoredKey::String(s) => {
                let bytes = BASE64_STANDARD_NO_PAD.decode(s).map_err(DecodeError::Base64)?;
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| DecodeError::Ed25519(Ed25519Error::InvalidSliceLength))?;
                Ok(SigningKey::from(bytes))
            },
            StoredKey::CryptoKeyPair(_) => Err(DecodeError::CryptoKeyPair),
        }
    }

    pub fn encode(key: SigningKey) -> String {
        let data: [u8; 32] = key.into();
        BASE64_STANDARD_NO_PAD.encode(data.as_ref())
    }
}

impl From<String> for StoredKey {
    fn from(value: String) -> Self {
        StoredKey::String(value)
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DecodeError {
    #[error("CryptoKeyPair cannot be decoded")]
    CryptoKeyPair,
    #[error("Ed25519 error: {0}")]
    Ed25519(Ed25519Error),
    #[error("Base64 error: {0}")]
    Base64(base64::DecodeError),
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

/*
/// IdbStorage is an interface for simple storage of string key-value pairs built on IdbKeyVal.
#[derive(Debug, Clone)]
pub struct IdbStorage {
    initialized_db: Rc<RefCell<Option<IdbKeyVal>>>,
    db_name: String,
    store_name: String,
    version: u32,
}

impl IdbStorage {
    pub fn new(db_name: String, store_name: String, version: u32) -> Self {
        IdbStorage {
            initialized_db: Rc::new(RefCell::new(None)),
            db_name,
            store_name,
            version,
        }
    }

    async fn init_db(&mut self) {
        if self.initialized_db.borrow().is_none() {
            let options = DbCreateOptions {
                db_name: Some(self.db_name.clone()),
                store_name: Some(self.store_name.clone()),
                version: Some(self.version),
            };
            let db = IdbKeyVal::new_with_options(options).await;
            self.initialized_db = Rc::new(RefCell::new(Some(db)));
        }
    }
}

impl AuthClientStorage for IdbStorage {
    async fn get<T: AsRef<str>>(&mut self, key: T) -> Option<StoredKey> {
        self.init_db().await;
        let db = self.initialized_db.as_ref().unwrap();
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        let result = db.get(&key).await;
        match result {
            Ok(value) => match value {
                Some(value) => value
                    .as_str()
                    .map(|value| StoredKey::String(value.to_string())),
                None => None,
            },
            Err(_) => None,
        }
    }

    async fn set<T: AsRef<str>>(&mut self, key: T, value: T) {
        self.init_db().await;
        let db = self.initialized_db.as_ref().unwrap();
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        db.set::<String, String>(key, value.as_ref().to_string())
            .await
            .unwrap();
    }

    async fn remove<T: AsRef<str>>(&mut self, key: T) {
        self.init_db().await;
        let db = self.initialized_db.as_ref().unwrap();
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        db.remove(&key).await.unwrap();
    }
}
*/

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
