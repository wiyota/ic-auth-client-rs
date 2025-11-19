//! Storage implementations for authentication client data.
//!
//! This module provides browser-based storage for secure credential management.

use super::{StorageError, StoredKey};
use futures::future::BoxFuture;
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
    fn get<'a>(
        &'a mut self,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredKey>, StorageError>> {
        Box::pin(async move {
            let local_storage = self
                .get_local_storage()
                .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
            let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key);
            let value = local_storage.get_item(&key)?;
            Ok(value.map(StoredKey::String))
        })
    }

    fn set<'a>(
        &'a mut self,
        key: &'a str,
        value: StoredKey,
    ) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let local_storage = self
                .get_local_storage()
                .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
            let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key);
            let value = value.encode();
            local_storage.set_item(&key, value.as_ref())?;
            Ok(())
        })
    }

    fn remove<'a>(&'a mut self, key: &'a str) -> BoxFuture<'a, Result<(), StorageError>> {
        Box::pin(async move {
            let local_storage = self
                .get_local_storage()
                .ok_or_else(|| StorageError::WebSys("LocalStorage not available".to_string()))?;
            let key = format!("{}{}", LOCAL_STORAGE_PREFIX, key);
            local_storage.remove_item(&key)?;
            Ok(())
        })
    }
}

impl From<LocalStorage> for Box<dyn AuthClientStorage> {
    fn from(storage: LocalStorage) -> Self {
        Box::new(storage)
    }
}

/// Trait for persisting user authentication data.
pub trait AuthClientStorage: Send {
    /// Retrieves a stored value by key from the storage backend.
    ///
    /// # Parameters
    /// - `key`: The key to retrieve the value for. The key will be prefixed with the storage prefix.
    ///
    /// # Returns
    /// Returns `Ok(Some(StoredKey))` if the key exists in storage, `Ok(None)` if not, or
    /// `Err(StorageError)` if there was an error accessing the storage.
    fn get<'a>(
        &'a mut self,
        key: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredKey>, StorageError>>;

    /// Stores a value with the given key in the storage backend.
    ///
    /// # Parameters
    /// - `key`: The key to store the value under. The key will be prefixed with the storage prefix.
    /// - `value`: The value to store, which will be encoded before storage.
    ///
    /// # Returns
    /// Returns `Ok(())` if the value was successfully stored, or `Err(StorageError)` if there was an
    /// error accessing the storage or storing the value.
    fn set<'a>(
        &'a mut self,
        key: &'a str,
        value: StoredKey,
    ) -> BoxFuture<'a, Result<(), StorageError>>;

    /// Removes a stored value by key from the storage backend.
    ///
    /// # Parameters
    /// - `key`: The key to remove from storage. The key will be prefixed with the storage prefix.
    ///
    /// # Returns
    /// Returns `Ok(())` if the key was successfully removed or didn't exist, or `Err(StorageError)`
    /// if there was an error accessing the storage.
    fn remove<'a>(&'a mut self, key: &'a str) -> BoxFuture<'a, Result<(), StorageError>>;
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
}
