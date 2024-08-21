use candid::Principal;
use dotenvy_macro::dotenv;
use std::env;

pub fn backend() -> Principal {
    let mut canister_id = dotenv!("CANISTER_ID_IC_AUTH_CLIENT_LEPTOS_BACKEND").to_string();
    if canister_id.is_empty() {
        canister_id = env::var("CANISTER_ID_IC_AUTH_CLIENT_LEPTOS_BACKENDD")
            .expect("CANISTER_ID_IC_AUTH_CLIENT_LEPTOS_BACKEND is must be set");
    }

    parce_principal(canister_id)
}

pub fn internet_identity() -> Principal {
    let mut canister_id = dotenv!("CANISTER_ID_INTERNET_IDENTITY").to_string();
    if canister_id.is_empty() {
        canister_id = env::var("CANISTER_ID_INTERNET_IDENTITY")
            .expect("CANISTER_ID_INTERNET_IDENTITY is must be set");
    }

    parce_principal(canister_id)
}

fn parce_principal(canister_id: String) -> Principal {
    Principal::from_text(canister_id).expect("Failed to get backend canister id")
}
