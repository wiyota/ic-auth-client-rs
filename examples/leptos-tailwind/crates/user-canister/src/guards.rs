use ic_cdk::caller;
use crate::OWNER;

pub fn caller_is_owner() -> Result<(), String> {
    if caller() == OWNER.with(|o| *o.borrow()) {
        Ok(())
    } else {
        Err("Caller is not the owner of the canister.".to_string())
    }
}
