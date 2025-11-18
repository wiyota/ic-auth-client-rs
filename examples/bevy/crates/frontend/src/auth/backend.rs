use bevy::log::{debug, error};
use candid::{CandidType, Decode, Encode};
use ic_agent::{Agent, Identity};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::runtime::{Builder, Runtime};
use util::{
    canister_id::BACKEND,
    dfx_network::{DFX_NETWORK, DfxNetwork, is_local_dfx},
};

const TIMEOUT: Duration = Duration::from_secs(60 * 5);

pub struct BackendActor {
    agent: Agent,
    runtime: Arc<Runtime>,
}

impl Clone for BackendActor {
    fn clone(&self) -> Self {
        Self {
            agent: self.agent.clone(),
            runtime: self.runtime.clone(),
        }
    }
}

#[allow(dead_code)]
impl BackendActor {
    pub fn new<T>(identity: T) -> Self
    where
        T: Identity + 'static,
    {
        let url = match *DFX_NETWORK {
            DfxNetwork::Local => "http://localhost:4943".to_string(),
            DfxNetwork::Ic => "https://ic0.app".to_string(),
        };

        let agent = Agent::builder()
            .with_url(url)
            .with_identity(identity)
            .with_ingress_expiry(TIMEOUT)
            .build()
            .expect("Failed to create agent");

        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");

        if is_local_dfx() {
            runtime.block_on(agent.fetch_root_key()).unwrap();
        }

        Self {
            agent,
            runtime: Arc::new(runtime),
        }
    }

    async fn query<S, T>(&self, method: &'static str, arg: S) -> T
    where
        S: CandidType + Send + 'static,
        T: CandidType + for<'de> Deserialize<'de> + Send + 'static,
    {
        // This pattern ensures the future is Send by using a oneshot channel
        let agent = self.agent.clone();
        let backend = *BACKEND;
        let arg = Encode!(&arg).unwrap();
        let handle = self.runtime.handle().clone();

        let response = handle
            .spawn(async move {
                debug!(
                    method,
                    canister = %backend,
                    arg_bytes = arg.len(),
                    "Sending backend query"
                );
                agent.query(&backend, method).with_arg(arg).await
            })
            .await
            .expect("Query task panicked")
            .unwrap_or_else(|e| {
                error!(method, canister = %backend, ?e, "Backend query failed");
                panic!(
                    "Failed to query call: canister_id: {}, method: {}, {:?}",
                    backend, method, e
                );
            });

        Decode!(response.as_slice(), T).unwrap()
    }

    async fn update<S, T>(&self, method: &'static str, arg: S) -> T
    where
        S: CandidType + Send + 'static,
        T: CandidType + for<'de> Deserialize<'de> + Send + 'static,
    {
        // Similar pattern for update calls to ensure Send
        let agent = self.agent.clone();
        let backend = *BACKEND;
        let arg = Encode!(&arg).unwrap();
        let handle = self.runtime.handle().clone();

        let response = handle
            .spawn(async move {
                debug!(
                    method,
                    canister = %backend,
                    arg_bytes = arg.len(),
                    "Sending backend update"
                );
                agent.update(&backend, method).with_arg(arg).await
            })
            .await
            .expect("Update task panicked")
            .unwrap_or_else(|e| {
                error!(method, canister = %backend, ?e, "Backend update failed");
                panic!(
                    "Failed to update call: canister_id: {}, method: {}, {:?}",
                    backend, method, e
                );
            });

        Decode!(response.as_slice(), T).unwrap()
    }
}
