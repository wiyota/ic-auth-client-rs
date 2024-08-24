use ic_agent::{export::Principal, identity::SignedDelegation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use web_sys::js_sys::Date;

/// A chain of delegations. This is JSON Serializable.
///
/// This is the struct to serialize and pass to a DelegationIdentity. It does not keep any private keys.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DelegationChain {
    pub delegations: Vec<SignedDelegation>,
    pub public_key: Vec<u8>,
}

impl DelegationChain {
    /// Create a new [`DelegationChain`].
    pub fn new(delegations: Vec<SignedDelegation>, public_key: Vec<u8>) -> Self {
        DelegationChain {
            delegations,
            public_key,
        }
    }

    /// Deserialize a [`DelegationChain`] from a JSON string.
    pub fn from_json(json: &str) -> Self {
        serde_json::from_str(json).expect("Failed to parse delegation chain")
    }

    /// Serialize a [`DelegationChain`] to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("Failed to serialize delegation chain")
    }

    /// Analyze a [`DelegationChain`] and validate that it's valid, ie. not expired and apply to the scope.
    ///
    /// # Arguments
    ///
    /// * `checks` - Principals to validate on the chain.
    pub fn is_delegation_valid(&self, checks: Option<Vec<Principal>>) -> bool {
        // Verify that the no delegation is expired. If any are in the chain, returns false.
        let now = (Date::now() * 1_000_000.0) as u64;
        if self
            .delegations
            .iter()
            .any(|signed_delegation| signed_delegation.delegation.expiration <= now)
        {
            return false;
        }

        // Check the scopes.
        if let Some(checks) = checks {
            let checks: HashSet<_> = checks.into_iter().collect();
            for signed_delegation in self.delegations.iter() {
                let delegation = &signed_delegation.delegation;
                if let Some(targets) = delegation.targets.clone() {
                    if targets.iter().all(|target| !checks.contains(target)) {
                        return false;
                    }
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn test_delegation_chain() {
        let delegation_chain = DelegationChain {
            delegations: vec![],
            public_key: vec![1, 2, 3],
        };
        let json = delegation_chain.to_json();
        let delegation_chain2 = DelegationChain::from_json(&json);
        let json2 = delegation_chain2.to_json();
        assert_eq!(json, json2);
    }

    #[wasm_bindgen_test]
    fn test_is_delegation_valid() {
        let delegation_chain = DelegationChain {
            delegations: vec![],
            public_key: vec![1, 2, 3],
        };
        assert!(delegation_chain.is_delegation_valid(None));
    }

    #[wasm_bindgen_test]
    fn test_is_delegation_valid_expired() {
        let delegation_chain = DelegationChain {
            delegations: vec![SignedDelegation {
                delegation: ic_agent::identity::Delegation {
                    pubkey: vec![],
                    expiration: 0,
                    targets: None,
                },
                signature: vec![],
            }],
            public_key: vec![1, 2, 3],
        };
        assert!(!delegation_chain.is_delegation_valid(None));
    }
}
