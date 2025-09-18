use super::{DecodeError, StoredKey};
use web_sys::{Storage, wasm_bindgen::JsValue};

const LOCAL_STORAGE_PREFIX: &str = "ic-";

impl From<DecodeError> for JsValue {
    fn from(err: DecodeError) -> Self {
        JsValue::from_str(&err.to_string())
    }
}

/// Implementation of [`AuthClientStorage`].
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalStorage;

impl LocalStorage {
    pub fn new() -> Self {
        Self
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

    async fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), ()> {
        let local_storage = match self.get_local_storage() {
            Some(local_storage) => local_storage,
            None => return Err(()),
        };
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        let value = match value {
            StoredKey::String(value) => value,
            StoredKey::Raw(value) => StoredKey::encode(&value),
        };
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

    async fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), ()> {
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

/// Trait for persisting user authentication data.
pub trait AuthClientStorage {
    fn get<T: AsRef<str>>(&mut self, key: T) -> impl Future<Output = Option<StoredKey>>;

    fn set<T: AsRef<str>>(
        &mut self,
        key: T,
        value: StoredKey,
    ) -> impl Future<Output = Result<(), ()>>;

    fn remove<T: AsRef<str>>(&mut self, key: T) -> impl Future<Output = Result<(), ()>>;
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    async fn test_local_storage() {
        let mut storage = LocalStorage;
        let value = StoredKey::String("value".to_string());
        storage.set("test", value).await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, StoredKey::String("value".to_string()));
        storage.remove("test").await.unwrap();
        let value = storage.get("test").await;
        assert_eq!(value, None);
    }

    #[wasm_bindgen_test]
    async fn test_auth_client_storage_type() {
        let mut storage = AuthClientStorageType::LocalStorage(LocalStorage);
        let value = StoredKey::String("value".to_string());
        storage.set("test", value).await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, StoredKey::String("value".to_string()));
        storage.remove("test").await.unwrap();
        let value = storage.get("test").await;
        assert_eq!(value, None);
    }
}
