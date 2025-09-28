//! Storage implementations for authentication client data.
//!
//! This module provides keyring-based storage for secure credential management.

use super::{StorageError, StoredKey};
use keyring::Entry;

const KEYRING_STORAGE_PREFIX: &str = "ic-";

/// Implementation of [`AuthClientStorage`].
#[derive(Debug, Clone)]
pub struct KeyringStorage {
    service_name: String,
}

impl KeyringStorage {
    /// Creates a new instance of [`KeyringStorage`].
    pub fn new(service_name: String) -> Self {
        Self { service_name }
    }
}

impl AuthClientStorage for KeyringStorage {
    fn get<T: AsRef<str>>(&mut self, key: T) -> Result<Option<StoredKey>, StorageError> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, key.as_ref());
        let entry = Entry::new(&self.service_name, &key)?;
        match entry.get_secret() {
            Ok(value) => Ok(Some(value.try_into()?)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), StorageError> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, key.as_ref());
        let entry = Entry::new(&self.service_name, &key)?;
        let value = match value {
            StoredKey::String(_) => value.decode()?,
            StoredKey::Raw(value) => value,
        };
        entry.set_secret(&value)?;
        Ok(())
    }

    fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), StorageError> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, key.as_ref());
        let entry = Entry::new(&self.service_name, &key)?;
        match entry.delete_credential() {
            Ok(_) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Enum for selecting the type of storage to use for [`AuthClient`](crate::AuthClient).
#[derive(Debug, Clone)]
pub enum AuthClientStorageType {
    /// Use the system keyring for storage.
    Keyring(KeyringStorage),
}

impl AuthClientStorage for AuthClientStorageType {
    fn get<T: AsRef<str>>(&mut self, key: T) -> Result<Option<StoredKey>, StorageError> {
        match self {
            AuthClientStorageType::Keyring(storage) => storage.get(key),
        }
    }

    fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), StorageError> {
        match self {
            AuthClientStorageType::Keyring(storage) => storage.set(key, value),
        }
    }

    fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), StorageError> {
        match self {
            AuthClientStorageType::Keyring(storage) => storage.remove(key),
        }
    }
}

/// Trait for persisting user authentication data.
pub trait AuthClientStorage {
    /// Retrieves a stored value by key.
    ///
    /// # Arguments
    /// * `key` - The key to look up in storage
    ///
    /// # Returns
    /// * `Ok(Some(StoredKey))` if the key exists in storage
    /// * `Ok(None)` if the key does not exist
    /// * `Err(StorageError)` if an error occurred
    fn get<T: AsRef<str>>(&mut self, key: T) -> Result<Option<StoredKey>, StorageError>;

    /// Stores a key-value pair in the storage.
    ///
    /// # Arguments
    /// * `key` - The key to store the value under
    /// * `value` - The value to store
    ///
    /// # Returns
    /// * `Ok(())` if the value was successfully stored
    /// * `Err(StorageError)` if an error occurred during storage
    fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), StorageError>;

    /// Removes a stored value by key.
    ///
    /// # Arguments
    /// * `key` - The key to remove from storage
    ///
    /// # Returns
    /// * `Ok(())` if the key was successfully removed
    /// * `Err(StorageError)` if an error occurred during removal
    fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), StorageError>;
}
