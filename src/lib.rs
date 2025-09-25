#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![doc = document_features::document_features!()]

#[cfg(not(any(feature = "native", feature = "wasm-js")))]
compile_error!("Either feature \"native\" or \"wasm-js\" must be enabled for this crate");

#[cfg(feature = "tracing")]
#[macro_use]
extern crate tracing;

pub mod api;
mod auth_client;
pub mod idle_manager;
pub mod key;
pub mod option;
pub mod storage;
mod util;

pub use auth_client::*;
pub use idle_manager::IdleManagerOptions;
#[cfg(feature = "native")]
pub use option::native::NativeAuthClientCreateOptions;
#[cfg(feature = "wasm-js")]
pub use option::wasm_js::AuthClientCreateOptions;
pub use option::{AuthClientLoginOptions, IdleOptions};
pub use util::{callback, delegation_chain};
