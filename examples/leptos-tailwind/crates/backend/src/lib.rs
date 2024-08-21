use candid::Principal;
use ic_cdk::api::{call::CallResult, caller};
use ic_cdk_macros::*;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    {DefaultMemoryImpl, StableBTreeMap},
};
use std::cell::RefCell;

mod user_canister;

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    pub(crate) static USER_CANISTERS: RefCell<StableBTreeMap<Principal, Principal, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );
}

#[query]
fn get_user_canister_id() -> Option<Principal> {
    USER_CANISTERS.with_borrow(|m| m.get(&caller()))
}

#[update]
async fn create_user_canister() -> CallResult<Principal> {
    user_canister::create(&caller()).await
}

ic_cdk::export_candid!();
