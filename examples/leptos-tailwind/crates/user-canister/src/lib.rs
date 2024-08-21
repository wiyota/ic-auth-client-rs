use ic_cdk_macros::*;
use ic_stable_structures::{
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    {DefaultMemoryImpl, StableBTreeMap},
};
use shared::{NoteId, Note, NoteTitle};
use std::cell::RefCell;
use candid::Principal;

mod guards;

use guards::caller_is_owner;

type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));

    pub static NOTES: RefCell<StableBTreeMap<NoteId, Note, Memory>> = RefCell::new(
        StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))),
        )
    );

    pub static OWNER: RefCell<Principal> = const { RefCell::new(Principal::anonymous()) };
}

#[init]
fn init_user_canister(owner: Principal) {
    OWNER.with(|o| *o.borrow_mut() = owner);
}

#[pre_upgrade]
fn pre_upgrade() {
    let owner = OWNER.with(|o| *o.borrow());
    ic_cdk::storage::stable_save((owner,)).unwrap();
}

#[post_upgrade]
fn post_upgrade() {
    let (owner,) = ic_cdk::storage::stable_restore().unwrap();
    OWNER.with(|o| *o.borrow_mut() = owner);
}

#[query(guard = "caller_is_owner")]
fn get_note_id_and_title_vec() -> Vec<(NoteId, NoteTitle)> {
    ic_cdk::print("Getting note id and title vec");
    NOTES.with_borrow(|m| m.iter().map(|(k, v)| (k,v.title.clone())).collect())
}

#[query(guard = "caller_is_owner")]
fn get_note(id: NoteId) -> Option<Note> {
    let res = NOTES.with_borrow(|m| m.get(&id));
    ic_cdk::print(format!("Getting note with id: {}, content: {:?}", id, res));
    res
}

#[update(guard = "caller_is_owner")]
fn set_note(arg: (NoteId, Note)) {
    ic_cdk::print(format!("Setting note with id: {}, content: {:?}", arg.0, arg.1));
    NOTES.with_borrow_mut(|m| m.insert(arg.0, arg.1));
}
