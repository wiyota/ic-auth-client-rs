//! UniFFI bindings for the native auth client.

#[cfg(feature = "native")]
use crate::{AuthClientLoginOptions, NativeAuthClient};
#[cfg(all(feature = "native", feature = "keyring"))]
use crate::{
    NativeAuthClientCreateOptions, key::BaseKeyType, storage::sync_storage::KeyringStorage,
};
#[cfg(feature = "native")]
use ic_agent::identity::Identity;
#[cfg(feature = "native")]
use serde_json::Map;
#[cfg(feature = "native")]
use std::{sync::Arc, time::Duration};

#[cfg(feature = "native")]
#[derive(uniffi::Record, Clone, Default)]
pub struct LoginOptions {
    pub identity_provider: Option<String>,
    pub max_time_to_live: Option<u64>,
    pub allow_pin_authentication: Option<bool>,
    pub derivation_origin: Option<String>,
    pub window_opener_features: Option<String>,
    pub timeout_millis: Option<u64>,
    pub custom_values_json: Option<String>,
}

#[cfg(feature = "native")]
#[derive(uniffi::Enum, Debug, Clone)]
pub enum AuthError {
    Message(String),
    InvalidCustomValues(String),
    Principal(String),
    Signature(String),
    Key(String),
}

#[cfg(feature = "native")]
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Message(message) => write!(f, "{}", message),
            AuthError::InvalidCustomValues(message) => write!(f, "{}", message),
            AuthError::Principal(message) => write!(f, "{}", message),
            AuthError::Signature(message) => write!(f, "{}", message),
            AuthError::Key(message) => write!(f, "{}", message),
        }
    }
}

#[cfg(feature = "native")]
#[derive(uniffi::Object)]
pub struct AuthClient {
    inner: NativeAuthClient,
}

#[cfg(feature = "native")]
#[uniffi::export]
impl AuthClient {
    #[uniffi::constructor]
    pub fn new_keyring(service_name: String) -> Result<Arc<Self>, AuthError> {
        #[cfg(feature = "keyring")]
        {
            let options = NativeAuthClientCreateOptions::builder()
                .storage(KeyringStorage::new(service_name))
                .key_type(BaseKeyType::Secp256k1)
                .build();
            NativeAuthClient::new_with_options(options)
                .map(|inner| Arc::new(AuthClient { inner }))
                .map_err(|e| AuthError::Message(e.to_string()))
        }
        #[cfg(not(feature = "keyring"))]
        {
            NativeAuthClient::new(service_name)
                .map(|inner| Arc::new(AuthClient { inner }))
                .map_err(|e| AuthError::Message(e.to_string()))
        }
    }

    pub fn build_login_url(
        &self,
        auth_bridge_url: String,
        redirect_uri: String,
        options: LoginOptions,
    ) -> Result<String, AuthError> {
        let mut opts = AuthClientLoginOptions {
            identity_provider: options.identity_provider,
            max_time_to_live: options.max_time_to_live,
            allow_pin_authentication: options.allow_pin_authentication,
            derivation_origin: options.derivation_origin,
            window_opener_features: options.window_opener_features,
            timeout: options.timeout_millis.map(Duration::from_millis),
            ..Default::default()
        };

        if let Some(custom_json) = options.custom_values_json {
            let map: Map<String, serde_json::Value> = serde_json::from_str(&custom_json)
                .map_err(|e| AuthError::InvalidCustomValues(e.to_string()))?;
            opts.custom_values = Some(map);
        }

        self.inner
            .build_login_url(auth_bridge_url, &redirect_uri, opts)
            .map_err(|e| AuthError::Message(e.to_string()))
    }

    pub fn finish_login_from_payload(&self, payload: String) -> Result<(), AuthError> {
        self.inner
            .finish_login_from_payload(&payload)
            .map_err(|e| AuthError::Message(e.to_string()))
    }

    pub fn is_authenticated(&self) -> bool {
        self.inner.is_authenticated()
    }

    pub fn principal_text(&self) -> Result<String, AuthError> {
        self.inner
            .principal()
            .map(|principal| principal.to_text())
            .map_err(AuthError::Principal)
    }

    pub fn base_key_type(&self) -> Option<String> {
        self.inner.base_key_type().map(|k| k.to_string())
    }

    pub fn secp256k1_uncompressed_public_key(&self) -> Result<Vec<u8>, AuthError> {
        self.inner
            .secp256k1_uncompressed_public_key()
            .map_err(AuthError::Key)
    }

    pub fn secp256k1_private_key(&self) -> Result<Vec<u8>, AuthError> {
        self.inner.secp256k1_private_key().map_err(AuthError::Key)
    }

    pub fn delegation_chain_json(&self) -> Option<String> {
        self.inner.delegation_chain_json()
    }

    pub fn identity(&self) -> Arc<AuthIdentity> {
        Arc::new(AuthIdentity {
            inner: self.inner.identity(),
        })
    }

    pub fn logout(&self) {
        self.inner.logout();
    }
}

#[cfg(feature = "native")]
#[uniffi::export]
impl AuthClient {
    pub fn login(&self, auth_bridge_url: String, options: LoginOptions) -> Result<(), AuthError> {
        let mut opts = AuthClientLoginOptions {
            identity_provider: options.identity_provider,
            max_time_to_live: options.max_time_to_live,
            allow_pin_authentication: options.allow_pin_authentication,
            derivation_origin: options.derivation_origin,
            window_opener_features: options.window_opener_features,
            timeout: options.timeout_millis.map(Duration::from_millis),
            ..Default::default()
        };

        if let Some(custom_json) = options.custom_values_json {
            let map: Map<String, serde_json::Value> = serde_json::from_str(&custom_json)
                .map_err(|e| AuthError::InvalidCustomValues(e.to_string()))?;
            opts.custom_values = Some(map);
        }

        #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
        {
            self.inner.login(auth_bridge_url, opts);
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            Err(AuthError::Message(
                "login is only supported on desktop targets; use AuthSession on iOS".to_string(),
            ))
        }
    }
}

#[cfg(feature = "native")]
#[derive(uniffi::Object)]
pub struct AuthIdentity {
    inner: Arc<dyn Identity>,
}

#[cfg(feature = "native")]
#[uniffi::export]
impl AuthIdentity {
    pub fn principal_text(&self) -> Result<String, AuthError> {
        self.inner
            .sender()
            .map(|principal| principal.to_text())
            .map_err(AuthError::Principal)
    }

    pub fn public_key_der(&self) -> Option<Vec<u8>> {
        self.inner.public_key()
    }

    pub fn sign_arbitrary(&self, message: Vec<u8>) -> Result<Vec<u8>, AuthError> {
        let signature = self
            .inner
            .sign_arbitrary(&message)
            .map_err(AuthError::Signature)?;
        signature
            .signature
            .ok_or_else(|| AuthError::Signature("Signature missing".to_string()))
    }

    pub fn delegation_chain_json(&self) -> Option<String> {
        let delegations = self.inner.delegation_chain();
        if delegations.is_empty() {
            return None;
        }
        let public_key = self.inner.public_key().unwrap_or_default();
        let chain = crate::util::delegation_chain::DelegationChain::new(delegations, public_key);
        Some(chain.to_json())
    }
}
