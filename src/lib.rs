//! Simple interface to get your web application authenticated with the Internet Identity Service for Rust.
//!
//! This crate is intended for use in front-end WebAssembly environments in conjunction with [ic-agent](https://docs.rs/ic-agent).

#[cfg(feature = "tracing")]
#[macro_use]
extern crate tracing;

pub mod api;
mod auth_client;
pub mod idle_manager;
pub mod storage;
mod util;

pub use api::*;
pub use auth_client::*;
pub use util::delegation_chain;
