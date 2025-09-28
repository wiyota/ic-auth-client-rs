//! Storage implementations for authentication client data.
//!
//! This module provides browser-based storage for secure credential management.

use super::{StorageError, StoredKey};
use web_sys::Storage;

const LOCAL_STORAGE_PREFIX: &str = "ic-";

/// Implementation of [`AuthClientStorage`].
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalStorage;

impl LocalStorage {
    /// Creates a new instance of [`LocalStorage`].
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
    async fn get<T: AsRef<str>>(&mut self, key: T) -> Result<Option<StoredKey>, StorageError> {
        let local_storage = self
            .get_local_storage()
            .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        let value = local_storage.get_item(&key)?;
        Ok(value.map(StoredKey::String))
    }

    async fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), StorageError> {
        let local_storage = self
            .get_local_storage()
            .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        let value = value.encode();
        local_storage.set_item(&key, value.as_ref())?;
        Ok(())
    }

    async fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), StorageError> {
        let local_storage = self
            .get_local_storage()
            .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
        let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key.as_ref());
        local_storage.remove_item(&key)?;
        Ok(())
    }
}

/// Enum for selecting the type of storage to use for [`AuthClient`](crate::AuthClient).
#[derive(Debug, Clone)]
pub enum AuthClientStorageType {
    /// Local storage implementation.
    LocalStorage(LocalStorage),
}

impl Default for AuthClientStorageType {
    fn default() -> Self {
        AuthClientStorageType::LocalStorage(LocalStorage::new())
    }
}

impl AuthClientStorage for AuthClientStorageType {
    async fn get<T: AsRef<str>>(&mut self, key: T) -> Result<Option<StoredKey>, StorageError> {
        match self {
            AuthClientStorageType::LocalStorage(storage) => storage.get(key).await,
        }
    }

    async fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), StorageError> {
        match self {
            AuthClientStorageType::LocalStorage(storage) => storage.set(key, value).await,
        }
    }

    async fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), StorageError> {
        match self {
            AuthClientStorageType::LocalStorage(storage) => storage.remove(key).await,
        }
    }
}

/// Trait for persisting user authentication data.
pub trait AuthClientStorage {
    /// Retrieves a stored value by key from the storage backend.
    ///
    /// # Parameters
    /// - `key`: The key to retrieve the value for. The key will be prefixed with the storage prefix.
    ///
    /// # Returns
    /// Returns `Ok(Some(StoredKey))` if the key exists in storage, `Ok(None)` if not, or
    /// `Err(StorageError)` if there was an error accessing the storage.
    fn get<T: AsRef<str>>(
        &mut self,
        key: T,
    ) -> impl std::future::Future<Output = Result<Option<StoredKey>, StorageError>>;

    /// Stores a value with the given key in the storage backend.
    ///
    /// # Parameters
    /// - `key`: The key to store the value under. The key will be prefixed with the storage prefix.
    /// - `value`: The value to store, which will be encoded before storage.
    ///
    /// # Returns
    /// Returns `Ok(())` if the value was successfully stored, or `Err(StorageError)` if there was an
    /// error accessing the storage or storing the value.
    fn set<T: AsRef<str>>(
        &mut self,
        key: T,
        value: StoredKey,
    ) -> impl std::future::Future<Output = Result<(), StorageError>>;

    /// Removes a stored value by key from the storage backend.
    ///
    /// # Parameters
    /// - `key`: The key to remove from storage. The key will be prefixed with the storage prefix.
    ///
    /// # Returns
    /// Returns `Ok(())` if the key was successfully removed or didn't exist, or `Err(StorageError)`
    /// if there was an error accessing the storage.
    fn remove<T: AsRef<str>>(
        &mut self,
        key: T,
    ) -> impl std::future::Future<Output = Result<(), StorageError>>;
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
        assert_eq!(value, Some(StoredKey::String("value".to_string())));
        storage.remove("test").await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, None);
    }

    #[wasm_bindgen_test]
    async fn test_auth_client_storage_type() {
        let mut storage = AuthClientStorageType::LocalStorage(LocalStorage);
        let value = StoredKey::String("value".to_string());
        storage.set("test", value).await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, Some(StoredKey::String("value".to_string())));
        storage.remove("test").await.unwrap();
        let value = storage.get("test").await.unwrap();
        assert_eq!(value, None);
    }
}
