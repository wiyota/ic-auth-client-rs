use candid::CandidType;
use serde::{Deserialize, Serialize};
use derive_more::{AsRef, Display, From, FromStr};

#[derive(CandidType, Serialize, Deserialize, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct GetNoteResponse {
    pub id: NoteId,
    pub note: Note,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct SetNoteRequest {
    pub id: NoteId,
    pub note: Note,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct Note {
    pub title: NoteTitle,
    pub content: String,
}

#[derive(CandidType, Serialize, Deserialize, Debug, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Copy, Clone, AsRef, Display, From, FromStr)]
pub struct NoteId(u32);

impl NoteId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn increment(&self) -> Self {
        Self(self.0 + 1)
    }
}

/// 50 characters or less
#[derive(CandidType, Serialize, Deserialize, Debug, Hash, Default, PartialEq, Eq, PartialOrd, Ord, Clone, AsRef, Display)]
pub struct NoteTitle(String);

impl NoteTitle {
    const MAX_LEN: usize = 50;

    pub fn new(name: String) -> Result<Self, NoteTitleError> {
        let len = name.chars().count();

        if len > Self::MAX_LEN {
            return Err(NoteTitleError::TooLong);
        }
        Ok(Self(name))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum NoteTitleError {
    TooLong,
}

#[cfg(feature = "frontend")]
mod frontend {
    use super::NoteTitle;
    use leptos::{IntoView, View};

    impl IntoView for NoteTitle {
        fn into_view(self) -> View {
            self.0.into_view()
        }
    }
}

#[cfg(feature = "backend")]
mod backend {
    use super::*;
    use candid::{Encode, Decode};
    use ic_stable_structures::storable::{Bound, Storable};
    use std::borrow::Cow;

    impl Storable for Note {
        fn to_bytes(&self) -> std::borrow::Cow<[u8]> {
            Encode!(self).unwrap().into()
        }

        fn from_bytes(bytes: std::borrow::Cow<[u8]>) -> Self {
            Decode!(bytes.as_ref(), Self).unwrap()
        }

        const BOUND: Bound = Bound::Unbounded;
    }

    impl Storable for NoteId {
        fn to_bytes(&self) -> Cow<[u8]> {
            self.0.to_bytes()
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            Self(u32::from_bytes(bytes))
        }

        const BOUND: Bound = Bound::Bounded { max_size: 4, is_fixed_size: true };
    }

    impl Storable for NoteTitle {
        fn to_bytes(&self) -> Cow<[u8]> {
            self.0.to_bytes()
        }

        fn from_bytes(bytes: Cow<[u8]>) -> Self {
            Self(String::from_bytes(bytes))
        }

        const BOUND: Bound = Bound::Bounded { max_size: Self::MAX_LEN as u32 * 4, is_fixed_size: false };
    }
}
