use candid::{Principal, Encode};
use ic_cdk::api::{
    call::CallResult,
    management_canister::main::{
        create_canister, install_code, CanisterInstallMode, CreateCanisterArgument,
        InstallCodeArgument,
    },
};
use crate::USER_CANISTERS;

pub async fn create(caller: &Principal) -> CallResult<Principal> {
    let canister_id = create_canister(CreateCanisterArgument::default(), 200_000_000_000).await?.0.canister_id;

    let wasm_module = include_bytes!("../../../target/wasm32-unknown-unknown/release/ic_auth_client_leptos_user_canister.wasm").to_vec();

    install_code(InstallCodeArgument {
        mode: CanisterInstallMode::Install,
        canister_id,
        wasm_module,
        arg: Encode!(caller).unwrap(),
    })
    .await?;

    USER_CANISTERS.with_borrow_mut(|canisters| {
        canisters.insert(*caller, canister_id);
    });

    Ok(canister_id)
}
