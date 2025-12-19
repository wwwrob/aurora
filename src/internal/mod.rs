//! Internal shared utilities for AURORA ciphers

pub mod gf256;
pub mod prng;

pub use gf256::{ct_eq, gf_inv, gf_mul, gf_pow, invert_matrix_8x8_gf256};
pub use prng::XorShift64Star;


