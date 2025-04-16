#[cfg(feature = "entity")]
pub mod dao;
pub mod dto;
#[cfg(feature = "entity")]
pub mod model;

pub type Note = dto::NoteDto;
