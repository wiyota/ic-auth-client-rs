use crate::log::Log;
use candid::Principal;
use domain::note::{NoteId, entity::dao::NoteDao};
use ic_stable_structures::{
    StableLog, StableBTreeMap,
    memory_manager::{MemoryId, MemoryManager, VirtualMemory},
    DefaultMemoryImpl
};
use std::cell::RefCell;

const UPGRADES: MemoryId = MemoryId::new(0);
const LOG_INDEX: MemoryId = MemoryId::new(1);
const LOG_DATA: MemoryId = MemoryId::new(2);
const NOTES: MemoryId = MemoryId::new(3);

pub(super) type Memory = VirtualMemory<DefaultMemoryImpl>;

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> =
        RefCell::new(MemoryManager::init(DefaultMemoryImpl::default()));
}

pub(super) fn get_upgrades_memory() -> Memory {
    MEMORY_MANAGER.with(|m| m.borrow().get(UPGRADES))
}

pub(super) fn init_stable_log() -> StableLog<Log, Memory, Memory> {
    let result = StableLog::init(
        MEMORY_MANAGER.with(|m| m.borrow().get(LOG_INDEX)),
        MEMORY_MANAGER.with(|m| m.borrow().get(LOG_DATA)),
    );

    match result {
        Ok(log) => log,
        Err(e) => {
            ic_cdk::api::print(format!("Failed to initialize log: {}", e));
            ic_cdk::trap("Critical error: Failed to initialize stable log");
        }
    }
}

pub(super) fn init_notes() -> StableBTreeMap<(Principal, NoteId), NoteDao, Memory> {
    StableBTreeMap::init(
        MEMORY_MANAGER.with(|m| m.borrow_mut().get(NOTES))
    )
}
