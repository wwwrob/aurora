//! AURORA: Block cipher library
//!
//! A custom block cipher family with unique diffusion operations including
//! the proprietary AuroraMix transformation. This library provides
//! block cipher implementations and secure-by-default authenticated encryption
//! wrappers.
//!
//! ## Modules
//!
//! - `aurora512`: AURORA-512 block cipher (512-bit blocks, 512-bit keys, 24 rounds)
//! - `aurora1024`: AURORA-1024 block cipher (1024-bit blocks, 1024-bit keys, 32 rounds)
//! - `aurora_seal512`: AURORA-SEAL-512 authenticated encryption wrapper (secure-by-default)
//! - `aurora_seal1024`: AURORA-SEAL-1024 authenticated encryption wrapper (secure-by-default)

pub mod internal;
pub mod output_format;
pub mod aurora512;
pub mod aurora1024;
pub mod aurora_seal512;
pub mod aurora_seal1024;

// Re-export main types
pub use aurora512::{Aurora512, BLOCK_BYTES as BLOCK_BYTES_512, KEY_BYTES as KEY_BYTES_512, ROUNDS as ROUNDS_512};
pub use aurora1024::{Aurora1024, BLOCK_BYTES as BLOCK_BYTES_1024, KEY_BYTES as KEY_BYTES_1024, ROUNDS as ROUNDS_1024};
pub use aurora_seal512::AuroraSeal512;
pub use aurora_seal1024::AuroraSeal1024;
pub use output_format::OutputFormat;

