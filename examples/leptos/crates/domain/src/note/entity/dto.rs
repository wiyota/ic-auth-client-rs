use candid::CandidType;
use serde::{Deserialize, Serialize};
use super::super::{NoteId, NoteTitle};

#[derive(CandidType, Deserialize, Serialize, Debug, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct NoteDto {
    pub id: NoteId,
    pub title: NoteTitle,
    pub content: String,
}

#[cfg(feature = "entity")]
mod model {
    use super::{super::model, NoteDto};

    impl From<model::Note> for NoteDto {
        fn from(note: model::Note) -> Self {
            Self {
                id: note.id,
                title: note.title,
                content: note.content,
            }
        }
    }

    impl From<NoteDto> for model::Note {
        fn from(note: NoteDto) -> Self {
            Self {
                id: note.id,
                title: note.title,
                content: note.content,
            }
        }
    }
}
