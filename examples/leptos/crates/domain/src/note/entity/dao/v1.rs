use candid::CandidType;
use serde::{Deserialize, Serialize};
use super::super::super::NoteTitle;

#[derive(CandidType, Clone, Serialize, Deserialize, Debug)]
pub struct V1 {
    pub(crate) title: NoteTitle,
    pub(crate) content: String,
}
