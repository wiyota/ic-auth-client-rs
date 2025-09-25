//! Storage implementations for authentication client data.
//!
//! This module provides keyring-based storage for secure credential management.

use super::StoredKey;
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
    fn get<T: AsRef<str>>(&mut self, key: T) -> Option<StoredKey> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, key.as_ref());
        let entry = match Entry::new(&self.service_name, &key) {
            Ok(entry) => entry,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Could not create keyring entry: {_e:?}");
                return None;
            }
        };
        let value = match entry.get_secret() {
            Ok(value) => value,
            Err(_e) => return None,
        };
        match value.try_into() {
            Ok(value) => Some(value),
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Could not convert value to StoredKey: {_e:?}");
                None
            }
        }
    }

    fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), ()> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, key.as_ref());
        let entry = match Entry::new(&self.service_name, &key) {
            Ok(entry) => entry,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Could not create keyring entry: {_e:?}");
                return Err(());
            }
        };
        let value = match value {
            StoredKey::String(_) => match value.decode() {
                Ok(value) => value,
                Err(_) => {
                    #[cfg(feature = "tracing")]
                    error!("Could not decode string value");
                    return Err(());
                }
            },
            StoredKey::Raw(value) => value,
        };
        match entry.set_secret(&value) {
            Ok(_) => Ok(()),
            Err(_) => {
                #[cfg(feature = "tracing")]
                error!("Could not set item in keyring");
                Err(())
            }
        }
    }

    fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), ()> {
        let key = format!("{}{}", KEYRING_STORAGE_PREFIX, key.as_ref());
        let entry = match Entry::new(&self.service_name, &key) {
            Ok(entry) => entry,
            Err(_e) => {
                #[cfg(feature = "tracing")]
                error!("Could not create keyring entry: {_e:?}");
                return Err(());
            }
        };
        match entry.delete_credential() {
            Ok(_) => Ok(()),
            Err(_) => {
                #[cfg(feature = "tracing")]
                error!("Could not remove item from keyring");
                Err(())
            }
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
    fn get<T: AsRef<str>>(&mut self, key: T) -> Option<StoredKey> {
        match self {
            AuthClientStorageType::Keyring(storage) => storage.get(key),
        }
    }

    fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), ()> {
        match self {
            AuthClientStorageType::Keyring(storage) => storage.set(key, value),
        }
    }

    fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), ()> {
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
    /// * `Some(StoredKey)` if the key exists in storage
    /// * `None` if the key doesn't exist or an error occurred
    fn get<T: AsRef<str>>(&mut self, key: T) -> Option<StoredKey>;

    /// Stores a key-value pair in the storage.
    ///
    /// # Arguments
    /// * `key` - The key to store the value under
    /// * `value` - The value to store
    ///
    /// # Returns
    /// * `Ok(())` if the value was successfully stored
    /// * `Err(())` if an error occurred during storage
    fn set<T: AsRef<str>>(&mut self, key: T, value: StoredKey) -> Result<(), ()>;

    /// Removes a stored value by key.
    ///
    /// # Arguments
    /// * `key` - The key to remove from storage
    ///
    /// # Returns
    /// * `Ok(())` if the key was successfully removed
    /// * `Err(())` if an error occurred during removal
    fn remove<T: AsRef<str>>(&mut self, key: T) -> Result<(), ()>;
}
