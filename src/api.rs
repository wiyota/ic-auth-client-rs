use ic_agent::identity::SignedDelegation;
use serde::{Deserialize, Serialize};

/// Represents an Internet Identity authentication request.
///
/// This struct is used to send an authentication request to the Internet Identity Service.
/// It includes all the necessary parameters that the Internet Identity Service needs to authenticate a user.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct InternetIdentityAuthRequest {
    /// The kind of request. This is typically set to "authorize-client".
    pub kind: String,
    /// The public key of the session.
    pub session_public_key: Vec<u8>,
    /// The maximum time to live for the session, in nanoseconds. If not provided, a default value is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_time_to_live: Option<u64>,
    /// If present, indicates whether or not the Identity Provider should allow the user to authenticate and/or register using a temporary key/PIN identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_pin_authentication: Option<bool>,
    /// Origin for Identity Provider to use while generating the delegated identity. For II, the derivation origin must authorize this origin by setting a record at `<derivation-origin>/.well-known/ii-alternative-origins`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_origin: Option<String>,
}

/// Represents a successful authentication response.
///
/// This struct is used to store the details of a successful authentication response from the Internet Identity Service.
/// It includes the delegations, the user's public key, and the authentication method used.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthResponseSuccess {
    /// The delegations provided by the user during the authentication process.
    pub delegations: Vec<SignedDelegation>,
    /// The public key of the user.
    pub user_public_key: Vec<u8>,
    /// The authentication method used by the user.
    pub authn_method: String,
}

/// Represents a response message from the Identity Service.
///
/// This struct is used to store the details of a response message from the Identity Service.
/// It includes the kind of the response, the delegations, the user's public key, the authentication method used,
/// and the error message in case of failure.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityServiceResponseMessage {
    /// The kind of the response. This is typically set to "authorize-ready", "authorize-client-success", or "authorize-client-failure".
    kind: String,
    /// The delegations provided by the user during the authentication process. This is present in case of a successful authentication.
    delegations: Option<Vec<SignedDelegation>>,
    /// The public key of the user. This is present in case of a successful authentication.
    user_public_key: Option<Vec<u8>>,
    /// The authentication method used by the user. This is present in case of a successful authentication.
    authn_method: Option<String>,
    /// The error message in case of a failed authentication.
    text: Option<String>,
}

impl IdentityServiceResponseMessage {
    /// Returns the kind of the Identity Service response.
    pub fn kind(&self) -> Result<IdentityServiceResponseKind, String> {
        match self.kind.as_str() {
            "authorize-ready" => Ok(IdentityServiceResponseKind::Ready),
            "authorize-client-success" => Ok(IdentityServiceResponseKind::AuthSuccess(
                AuthResponseSuccess {
                    delegations: self.delegations.clone().unwrap_or_default(),
                    user_public_key: self.user_public_key.clone().unwrap_or_default(),
                    authn_method: self.authn_method.clone().unwrap_or_default(),
                },
            )),
            "authorize-client-failure" => Ok(IdentityServiceResponseKind::AuthFailure(
                self.text.clone().unwrap_or_default(),
            )),
            other => Err(format!("Unknown response kind: {}", other)),
        }
    }
}

/// Enum representing the kind of response from the Identity Service.
#[derive(Debug, Clone)]
pub enum IdentityServiceResponseKind {
    /// Represents a ready state.
    Ready,
    /// Represents a successful authentication response.
    AuthSuccess(AuthResponseSuccess),
    /// Represents a failed authentication response with an error message.
    AuthFailure(String),
}
