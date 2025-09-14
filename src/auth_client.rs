#[cfg(not(target_family = "wasm"))]
mod native;
#[cfg(target_family = "wasm")]
#[cfg(feature = "wasm-js")]
mod wasm_js;

#[cfg(not(target_family = "wasm"))]
pub use native::*;
#[cfg(target_family = "wasm")]
#[cfg(feature = "wasm-js")]
pub use wasm_js::*;
