#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! Shared primitives for the native service and the browser WASM engine.
//!
//! The crypto module is pure Rust and is compiled unchanged for both targets,
//! so the browser and any native test/tool use the exact same code path.

pub mod config;
pub mod crypto;
pub mod error;

pub use error::Error;
