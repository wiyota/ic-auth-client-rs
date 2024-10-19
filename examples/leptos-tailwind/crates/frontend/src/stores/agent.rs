use crate::stores::auth_client::get_identity;
use candid::{CandidType, Decode, Deserialize, Encode};
use dotenvy_macro::dotenv;
use ic_agent::{export::Principal, Agent};
use leptos::*;
use std::{env, time::Duration};

pub const TIMEOUT: Duration = Duration::from_secs(60 * 5);

#[component]
pub fn AgentProvider(children: Children) -> impl IntoView {
    let agent: Option<Agent> = None;
    let (agent, set_agent) = create_signal(agent);

    provide_context(agent);
    provide_context(set_agent);

    children()
}

/// Query call to the canister
pub async fn query_call<S, T>(canister_id: Principal, method: &'static str, arg: S) -> T
where
    S: CandidType,
    T: CandidType + for<'de> Deserialize<'de>,
{
    let arg = Encode!(&arg).unwrap();

    let agent = get_agent().await;

    let res = agent
        .query(&canister_id, method)
        .with_arg(arg)
        .await
        .unwrap_or_else(|e| {
            panic!("Failed to query call: canister_id: {}, method: {}, {:?}", canister_id, method, e);
        });

    let res: T = Decode!(&res.as_slice(), T).unwrap();

    res
}

/// Update call to the canister
pub async fn update_call<S, T>(canister_id: Principal, method: &'static str, arg: S) -> T
where
    S: CandidType,
    T: CandidType + for<'de> Deserialize<'de>,
{
    let arg = Encode!(&arg).unwrap();

    let agent = get_agent().await;

    let res = agent
        .update(&canister_id, method)
        .with_arg(arg)
        .await
        .unwrap_or_else(|e| {
            panic!("Failed to update call: canister_id: {}, method: {}, {:?}", canister_id, method, e);
        });

    let res: T = Decode!(&res.as_slice(), T).unwrap();

    res
}

async fn get_agent() -> Agent {
    let agent = use_context::<ReadSignal<Option<Agent>>>()
        .unwrap()
        .get_untracked();

    match agent {
        Some(agent) => agent,
        None => {
            let agent = create_agent().await;
            use_context::<WriteSignal<Option<Agent>>>()
                .unwrap()
                .set_untracked(Some(agent.clone()));
            agent
        }
    }
}

async fn create_agent() -> Agent {
    let identity = get_identity();

    let mut dfx_network = dotenv!("DFX_NETWORK").to_string();
    if dfx_network.is_empty() {
        dfx_network = env::var("DFX_NETWORK").expect("DFX_NETWORK is must be set");
    }

    let url = match dfx_network.as_str() {
        "local" => {
            let port = 4943;
            format!("http://127.0.0.1:{}", port)
        }
        "ic" => {
            "https://ic0.app".to_string()
        }
        _ => {
            panic!("Unknown dfx network: {}", dfx_network);
        }
    };

    let agent = Agent::builder()
        .with_url(url)
        .with_arc_identity(identity)
        .with_ingress_expiry(TIMEOUT)
        .build()
        .unwrap();

    if dfx_network == "local" {
        agent
            .fetch_root_key()
            .await
            .unwrap();
    }

    agent
}
