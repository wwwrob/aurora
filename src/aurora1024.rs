//! AURORA-1024: Scaled-up block cipher
//!
//! A custom 1024-bit block cipher with 1024-bit keys and 32 rounds.
//! Features a unique 8x16 state layout with custom diffusion operations
//! including the proprietary AuroraMix transformation.
//!
//! - Block size: 1024 bits (128 bytes)
//! - Key size: 1024 bits (128 bytes)
//! - Rounds: 32

use crate::internal::{gf_mul, invert_matrix_8x8_gf256, XorShift64Star};

/// Block size in bytes (1024 bits)
pub const BLOCK_BYTES: usize = 128;

/// Key size in bytes (1024 bits)
pub const KEY_BYTES: usize = 128;

/// Number of rounds
pub const ROUNDS: usize = 32;

/// Number of round keys (ROUNDS + 1)
const ROUND_KEYS: usize = 33;

/// Row rotation offsets for rows 0..7 (for 16-byte rows)
const SHIFT1024: [usize; 8] = [0, 1, 4, 7, 10, 13, 3, 6];

/// S-box generation seed (same as Aurora512 for consistency)
const SBOX_SEED: u64 = 0xC0FFEE1234BEEF99;

/// Base seed for round key masks
const MASK_SEED_BASE_1024: u64 = 0xD1B54A32D192ED03;

/// Column mixing matrix (8x8 over GF(2^8)) - same as Aurora512
const MIX: [[u8; 8]; 8] = [
    [0x02, 0x03, 0x01, 0x01, 0x04, 0x01, 0x01, 0x05],
    [0x05, 0x02, 0x03, 0x01, 0x01, 0x04, 0x01, 0x01],
    [0x01, 0x05, 0x02, 0x03, 0x01, 0x01, 0x04, 0x01],
    [0x01, 0x01, 0x05, 0x02, 0x03, 0x01, 0x01, 0x04],
    [0x04, 0x01, 0x01, 0x05, 0x02, 0x03, 0x01, 0x01],
    [0x01, 0x04, 0x01, 0x01, 0x05, 0x02, 0x03, 0x01],
    [0x01, 0x01, 0x04, 0x01, 0x01, 0x05, 0x02, 0x03],
    [0x03, 0x01, 0x01, 0x04, 0x01, 0x01, 0x05, 0x06],  // Changed last element from 0x02 to 0x06
];

/// Rotate left by n bits (0 <= n <= 7)
fn rotl8(value: u8, n: usize) -> u8 {
    let n = n & 7;
    value.rotate_left(n as u32)
}

/// Rotate right by n bits (0 <= n <= 7)
fn rotr8(value: u8, n: usize) -> u8 {
    let n = n & 7;
    value.rotate_right(n as u32)
}

/// Generate S-box using Fisher-Yates shuffle with xorshift64*
/// Uses the same seed as Aurora512 for consistency
fn generate_sbox() -> [u8; 256] {
    let mut arr = [0u8; 256];
    for i in 0..256 {
        arr[i] = i as u8;
    }

    let mut prng = XorShift64Star::new(SBOX_SEED);

    // Fisher-Yates shuffle
    for i in (1..256).rev() {
        let j = (prng.next_u32() as usize) % (i + 1);
        arr.swap(i, j);
    }

    arr
}

/// Generate inverse S-box from S-box
fn generate_inv_sbox(sbox: &[u8; 256]) -> [u8; 256] {
    let mut inv_sbox = [0u8; 256];
    for i in 0..256 {
        inv_sbox[sbox[i] as usize] = i as u8;
    }
    inv_sbox
}

/// Compute inverse of column mixing matrix using Gauss-Jordan elimination
fn compute_inv_mix() -> [[u8; 8]; 8] {
    invert_matrix_8x8_gf256(&MIX)
}

/// Generate round keys from master key
fn generate_round_keys(key: [u8; 128]) -> [[u8; 128]; ROUND_KEYS] {
    let mut rk = [[0u8; 128]; ROUND_KEYS];
    rk[0] = key;

    let sbox = generate_sbox();

    for r in 1..=ROUNDS {
        let mut tmp = rk[r - 1];

        // Apply substitution box
        for i in 0..128 {
            tmp[i] = sbox[tmp[i] as usize];
        }

        // Rotate left by (r % 128) bytes
        let rot_bytes = r % 128;
        if rot_bytes > 0 {
            let mut rotated = [0u8; 128];
            for i in 0..128 {
                rotated[i] = tmp[(i + rot_bytes) % 128];
            }
            tmp = rotated;
        }

        // XOR with mask from PRNG
        let mut prng = XorShift64Star::new(MASK_SEED_BASE_1024 ^ (r as u64));
        for i in 0..128 {
            tmp[i] ^= prng.next_u8();
        }

        rk[r] = tmp;
    }

    rk
}

/// AURORA-1024 cipher
pub struct Aurora1024 {
    rk: [[u8; 128]; ROUND_KEYS],
    sbox: [u8; 256],
    inv_sbox: [u8; 256],
    inv_mix: [[u8; 8]; 8],
}

impl Aurora1024 {
    /// Create a new AURORA-1024 cipher instance with the given key
    pub fn new(key: [u8; 128]) -> Self {
        let sbox = generate_sbox();
        let inv_sbox = generate_inv_sbox(&sbox);
        let inv_mix = compute_inv_mix();
        let rk = generate_round_keys(key);

        Self {
            rk,
            sbox,
            inv_sbox,
            inv_mix,
        }
    }

    /// Apply round key: XOR state with round key
    fn add_round_key(&self, state: &mut [u8; 128], round: usize) {
        for i in 0..128 {
            state[i] ^= self.rk[round][i];
        }
    }

    /// Apply substitution box to each byte
    fn sub_bytes(&self, state: &mut [u8; 128]) {
        for i in 0..128 {
            state[i] = self.sbox[state[i] as usize];
        }
    }

    /// Apply inverse substitution box to each byte
    fn inv_sub_bytes(&self, state: &mut [u8; 128]) {
        for i in 0..128 {
            state[i] = self.inv_sbox[state[i] as usize];
        }
    }

    /// Rotate each row left by SHIFT1024[row] bytes
    fn shift_rows(&self, state: &mut [u8; 128]) {
        let mut new_state = [0u8; 128];
        for row in 0..8 {
            let shift = SHIFT1024[row];
            for col in 0..16 {
                let new_col = (col + shift) % 16;
                new_state[row * 16 + new_col] = state[row * 16 + col];
            }
        }
        *state = new_state;
    }

    /// Rotate each row right by SHIFT1024[row] bytes (inverse operation)
    fn inv_shift_rows(&self, state: &mut [u8; 128]) {
        let mut new_state = [0u8; 128];
        for row in 0..8 {
            let shift = SHIFT1024[row];
            for col in 0..16 {
                let new_col = (col + 16 - shift) % 16;
                new_state[row * 16 + new_col] = state[row * 16 + col];
            }
        }
        *state = new_state;
    }

    /// Apply column mixing matrix to each column (16 columns, each 8 bytes)
    /// Optimized: unrolled inner loops and direct state access
    fn mix_columns16(&self, state: &mut [u8; 128]) {
        let mut new_state = [0u8; 128];
        for col in 0..16 {
            // Extract column directly
            let v0 = state[0 * 16 + col];
            let v1 = state[1 * 16 + col];
            let v2 = state[2 * 16 + col];
            let v3 = state[3 * 16 + col];
            let v4 = state[4 * 16 + col];
            let v5 = state[5 * 16 + col];
            let v6 = state[6 * 16 + col];
            let v7 = state[7 * 16 + col];

            // Multiply by MIX matrix - unrolled for performance
            new_state[0 * 16 + col] = gf_mul(MIX[0][0], v0) ^ gf_mul(MIX[0][1], v1) ^ gf_mul(MIX[0][2], v2) ^ gf_mul(MIX[0][3], v3) ^ gf_mul(MIX[0][4], v4) ^ gf_mul(MIX[0][5], v5) ^ gf_mul(MIX[0][6], v6) ^ gf_mul(MIX[0][7], v7);
            new_state[1 * 16 + col] = gf_mul(MIX[1][0], v0) ^ gf_mul(MIX[1][1], v1) ^ gf_mul(MIX[1][2], v2) ^ gf_mul(MIX[1][3], v3) ^ gf_mul(MIX[1][4], v4) ^ gf_mul(MIX[1][5], v5) ^ gf_mul(MIX[1][6], v6) ^ gf_mul(MIX[1][7], v7);
            new_state[2 * 16 + col] = gf_mul(MIX[2][0], v0) ^ gf_mul(MIX[2][1], v1) ^ gf_mul(MIX[2][2], v2) ^ gf_mul(MIX[2][3], v3) ^ gf_mul(MIX[2][4], v4) ^ gf_mul(MIX[2][5], v5) ^ gf_mul(MIX[2][6], v6) ^ gf_mul(MIX[2][7], v7);
            new_state[3 * 16 + col] = gf_mul(MIX[3][0], v0) ^ gf_mul(MIX[3][1], v1) ^ gf_mul(MIX[3][2], v2) ^ gf_mul(MIX[3][3], v3) ^ gf_mul(MIX[3][4], v4) ^ gf_mul(MIX[3][5], v5) ^ gf_mul(MIX[3][6], v6) ^ gf_mul(MIX[3][7], v7);
            new_state[4 * 16 + col] = gf_mul(MIX[4][0], v0) ^ gf_mul(MIX[4][1], v1) ^ gf_mul(MIX[4][2], v2) ^ gf_mul(MIX[4][3], v3) ^ gf_mul(MIX[4][4], v4) ^ gf_mul(MIX[4][5], v5) ^ gf_mul(MIX[4][6], v6) ^ gf_mul(MIX[4][7], v7);
            new_state[5 * 16 + col] = gf_mul(MIX[5][0], v0) ^ gf_mul(MIX[5][1], v1) ^ gf_mul(MIX[5][2], v2) ^ gf_mul(MIX[5][3], v3) ^ gf_mul(MIX[5][4], v4) ^ gf_mul(MIX[5][5], v5) ^ gf_mul(MIX[5][6], v6) ^ gf_mul(MIX[5][7], v7);
            new_state[6 * 16 + col] = gf_mul(MIX[6][0], v0) ^ gf_mul(MIX[6][1], v1) ^ gf_mul(MIX[6][2], v2) ^ gf_mul(MIX[6][3], v3) ^ gf_mul(MIX[6][4], v4) ^ gf_mul(MIX[6][5], v5) ^ gf_mul(MIX[6][6], v6) ^ gf_mul(MIX[6][7], v7);
            new_state[7 * 16 + col] = gf_mul(MIX[7][0], v0) ^ gf_mul(MIX[7][1], v1) ^ gf_mul(MIX[7][2], v2) ^ gf_mul(MIX[7][3], v3) ^ gf_mul(MIX[7][4], v4) ^ gf_mul(MIX[7][5], v5) ^ gf_mul(MIX[7][6], v6) ^ gf_mul(MIX[7][7], v7);
        }
        *state = new_state;
    }

    /// Apply inverse column mixing matrix to each column
    /// Optimized: unrolled inner loops and direct state access
    fn inv_mix_columns16(&self, state: &mut [u8; 128]) {
        let mut new_state = [0u8; 128];
        for col in 0..16 {
            // Extract column directly
            let v0 = state[0 * 16 + col];
            let v1 = state[1 * 16 + col];
            let v2 = state[2 * 16 + col];
            let v3 = state[3 * 16 + col];
            let v4 = state[4 * 16 + col];
            let v5 = state[5 * 16 + col];
            let v6 = state[6 * 16 + col];
            let v7 = state[7 * 16 + col];

            // Multiply by INV_MIX matrix - unrolled for performance
            new_state[0 * 16 + col] = gf_mul(self.inv_mix[0][0], v0) ^ gf_mul(self.inv_mix[0][1], v1) ^ gf_mul(self.inv_mix[0][2], v2) ^ gf_mul(self.inv_mix[0][3], v3) ^ gf_mul(self.inv_mix[0][4], v4) ^ gf_mul(self.inv_mix[0][5], v5) ^ gf_mul(self.inv_mix[0][6], v6) ^ gf_mul(self.inv_mix[0][7], v7);
            new_state[1 * 16 + col] = gf_mul(self.inv_mix[1][0], v0) ^ gf_mul(self.inv_mix[1][1], v1) ^ gf_mul(self.inv_mix[1][2], v2) ^ gf_mul(self.inv_mix[1][3], v3) ^ gf_mul(self.inv_mix[1][4], v4) ^ gf_mul(self.inv_mix[1][5], v5) ^ gf_mul(self.inv_mix[1][6], v6) ^ gf_mul(self.inv_mix[1][7], v7);
            new_state[2 * 16 + col] = gf_mul(self.inv_mix[2][0], v0) ^ gf_mul(self.inv_mix[2][1], v1) ^ gf_mul(self.inv_mix[2][2], v2) ^ gf_mul(self.inv_mix[2][3], v3) ^ gf_mul(self.inv_mix[2][4], v4) ^ gf_mul(self.inv_mix[2][5], v5) ^ gf_mul(self.inv_mix[2][6], v6) ^ gf_mul(self.inv_mix[2][7], v7);
            new_state[3 * 16 + col] = gf_mul(self.inv_mix[3][0], v0) ^ gf_mul(self.inv_mix[3][1], v1) ^ gf_mul(self.inv_mix[3][2], v2) ^ gf_mul(self.inv_mix[3][3], v3) ^ gf_mul(self.inv_mix[3][4], v4) ^ gf_mul(self.inv_mix[3][5], v5) ^ gf_mul(self.inv_mix[3][6], v6) ^ gf_mul(self.inv_mix[3][7], v7);
            new_state[4 * 16 + col] = gf_mul(self.inv_mix[4][0], v0) ^ gf_mul(self.inv_mix[4][1], v1) ^ gf_mul(self.inv_mix[4][2], v2) ^ gf_mul(self.inv_mix[4][3], v3) ^ gf_mul(self.inv_mix[4][4], v4) ^ gf_mul(self.inv_mix[4][5], v5) ^ gf_mul(self.inv_mix[4][6], v6) ^ gf_mul(self.inv_mix[4][7], v7);
            new_state[5 * 16 + col] = gf_mul(self.inv_mix[5][0], v0) ^ gf_mul(self.inv_mix[5][1], v1) ^ gf_mul(self.inv_mix[5][2], v2) ^ gf_mul(self.inv_mix[5][3], v3) ^ gf_mul(self.inv_mix[5][4], v4) ^ gf_mul(self.inv_mix[5][5], v5) ^ gf_mul(self.inv_mix[5][6], v6) ^ gf_mul(self.inv_mix[5][7], v7);
            new_state[6 * 16 + col] = gf_mul(self.inv_mix[6][0], v0) ^ gf_mul(self.inv_mix[6][1], v1) ^ gf_mul(self.inv_mix[6][2], v2) ^ gf_mul(self.inv_mix[6][3], v3) ^ gf_mul(self.inv_mix[6][4], v4) ^ gf_mul(self.inv_mix[6][5], v5) ^ gf_mul(self.inv_mix[6][6], v6) ^ gf_mul(self.inv_mix[6][7], v7);
            new_state[7 * 16 + col] = gf_mul(self.inv_mix[7][0], v0) ^ gf_mul(self.inv_mix[7][1], v1) ^ gf_mul(self.inv_mix[7][2], v2) ^ gf_mul(self.inv_mix[7][3], v3) ^ gf_mul(self.inv_mix[7][4], v4) ^ gf_mul(self.inv_mix[7][5], v5) ^ gf_mul(self.inv_mix[7][6], v6) ^ gf_mul(self.inv_mix[7][7], v7);
        }
        *state = new_state;
    }

    /// AuroraMix1024: extra diffusion step
    fn aurora_mix(&self, state: &mut [u8; 128], round: usize) {
        let mut l = [0u8; 64];
        let mut r = [0u8; 64];

        // Split state into L and R
        for i in 0..64 {
            l[i] = state[i];
            r[i] = state[i + 64];
        }

        // Four passes
        for p in 0..4 {
            let k = (11 * p + round) % 64;
            let a = (1 + round + p) % 8;
            let b = (3 + round + 2 * p) % 8;

            // Update L
            for i in 0..64 {
                l[i] ^= rotl8(r[(i + k) % 64], a);
            }

            let k2 = (k + 29) % 64;

            // Update R
            for i in 0..64 {
                r[i] ^= rotr8(l[(i + k2) % 64], b);
            }
        }

        // Swap halves
        for i in 0..64 {
            state[i] = r[i];
            state[i + 64] = l[i];
        }
    }

    /// Inverse AuroraMix1024: undo the diffusion step
    fn inv_aurora_mix(&self, state: &mut [u8; 128], round: usize) {
        let mut l = [0u8; 64];
        let mut r = [0u8; 64];

        // Undo swap first (recover original L and R)
        for i in 0..64 {
            r[i] = state[i];
            l[i] = state[i + 64];
        }

        // Undo four passes in reverse order
        for p in (0..4).rev() {
            let k = (11 * p + round) % 64;
            let a = (1 + round + p) % 8;
            let b = (3 + round + 2 * p) % 8;
            let k2 = (k + 29) % 64;

            // Undo R update first
            for i in 0..64 {
                r[i] ^= rotr8(l[(i + k2) % 64], b);
            }

            // Undo L update
            for i in 0..64 {
                l[i] ^= rotl8(r[(i + k) % 64], a);
            }
        }

        // Write back as L||R
        for i in 0..64 {
            state[i] = l[i];
            state[i + 64] = r[i];
        }
    }

    /// Encrypt a 128-byte block
    pub fn encrypt_block(&self, block: &mut [u8; 128]) {
        // Initial whitening
        self.add_round_key(block, 0);

        // Rounds 1..32
        for r in 1..=ROUNDS {
            self.sub_bytes(block);
            self.shift_rows(block);
            self.mix_columns16(block);
            self.aurora_mix(block, r);
            self.add_round_key(block, r);
        }
    }

    /// Decrypt a 128-byte block
    pub fn decrypt_block(&self, block: &mut [u8; 128]) {
        // Rounds 32..1 (reverse order)
        for r in (1..=ROUNDS).rev() {
            self.add_round_key(block, r);
            self.inv_aurora_mix(block, r);
            self.inv_mix_columns16(block);
            self.inv_shift_rows(block);
            self.inv_sub_bytes(block);
        }

        // Final whitening
        self.add_round_key(block, 0);
    }

    /// Encrypt a block and return as raw bytes
    pub fn encrypt_block_bytes(&self, block: &[u8; 128]) -> Vec<u8> {
        let mut result = *block;
        self.encrypt_block(&mut result);
        result.to_vec()
    }

    /// Encrypt a block and return in the specified format
    pub fn encrypt_block_formatted(&self, block: &[u8; 128], format: crate::output_format::OutputFormat) -> String {
        let bytes = self.encrypt_block_bytes(block);
        format.encode(&bytes)
    }

    /// Encrypt a block and return as base64
    pub fn encrypt_block_as_base64(&self, block: &[u8; 128]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::Base64)
    }

    /// Encrypt a block and return as hex (lowercase)
    pub fn encrypt_block_as_hex_lowercase(&self, block: &[u8; 128]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::HexLowercase)
    }

    /// Encrypt a block and return as hex (uppercase)
    pub fn encrypt_block_as_hex_uppercase(&self, block: &[u8; 128]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::HexUppercase)
    }

    /// Encrypt a block and return as base32
    pub fn encrypt_block_as_base32(&self, block: &[u8; 128]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::Base32)
    }

    /// Encrypt a block and return as Azonine (base-62: azAZ09)
    pub fn encrypt_block_as_azonine(&self, block: &[u8; 128]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::Azonine)
    }

    /// Decrypt a block from raw bytes
    pub fn decrypt_block_bytes(&self, block: &[u8]) -> Result<Vec<u8>, String> {
        if block.len() != 128 {
            return Err(format!("Block must be exactly 128 bytes, got {}", block.len()));
        }
        let mut result = [0u8; 128];
        result.copy_from_slice(block);
        self.decrypt_block(&mut result);
        Ok(result.to_vec())
    }

    /// Decrypt a block from encoded string in the specified format
    pub fn decrypt_block_formatted(&self, encoded: &str, format: crate::output_format::OutputFormat) -> Result<Vec<u8>, String> {
        let bytes = format.decode(encoded)?;
        self.decrypt_block_bytes(&bytes)
    }

    /// Decrypt a block from base64 string
    pub fn decrypt_block_from_base64(&self, encoded: &str) -> Result<Vec<u8>, String> {
        self.decrypt_block_formatted(encoded, crate::output_format::OutputFormat::Base64)
    }

    /// Decrypt a block from hex string (lowercase or uppercase)
    pub fn decrypt_block_from_hex(&self, encoded: &str) -> Result<Vec<u8>, String> {
        self.decrypt_block_formatted(encoded, crate::output_format::OutputFormat::HexLowercase)
    }

    /// Decrypt a block from base32 string
    pub fn decrypt_block_from_base32(&self, encoded: &str) -> Result<Vec<u8>, String> {
        self.decrypt_block_formatted(encoded, crate::output_format::OutputFormat::Base32)
    }

    /// Decrypt a block from Azonine string (base-62: azAZ09)
    pub fn decrypt_block_from_azonine(&self, encoded: &str) -> Result<Vec<u8>, String> {
        self.decrypt_block_formatted(encoded, crate::output_format::OutputFormat::Azonine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::XorShift64Star;

    #[test]
    fn test_sbox_inverse() {
        let sbox = generate_sbox();
        let inv_sbox = generate_inv_sbox(&sbox);

        // Test that S-box and inverse S-box are inverses
        for i in 0..256 {
            assert_eq!(inv_sbox[sbox[i] as usize], i as u8);
            assert_eq!(sbox[inv_sbox[i] as usize], i as u8);
        }
    }

    #[test]
    fn test_mix_inverse() {
        let inv_mix = compute_inv_mix();

        // Test that MIX * INV_MIX = I
        for i in 0..8 {
            for j in 0..8 {
                let mut sum = 0u8;
                for k in 0..8 {
                    sum ^= gf_mul(MIX[i][k], inv_mix[k][j]);
                }
                if i == j {
                    assert_eq!(sum, 1, "MIX * INV_MIX should be identity at ({}, {})", i, j);
                } else {
                    assert_eq!(sum, 0, "MIX * INV_MIX should be identity at ({}, {})", i, j);
                }
            }
        }
    }

    #[test]
    fn test_roundtrip_deterministic() {
        // Generate 200 random blocks using PRNG
        let mut prng = XorShift64Star::new(0xDEADBEEFCAFEBABE);
        let mut key = [0u8; 128];
        for i in 0..128 {
            key[i] = prng.next_u8();
        }

        let cipher = Aurora1024::new(key);

        for _ in 0..200 {
            let mut block = [0u8; 128];
            for i in 0..128 {
                block[i] = prng.next_u8();
            }

            let original = block;
            cipher.encrypt_block(&mut block);
            cipher.decrypt_block(&mut block);

            assert_eq!(block, original, "Roundtrip test failed");
        }
    }

    #[test]
    fn test_regression_zero_block_zero_key() {
        let key = [0u8; 128];
        let cipher = Aurora1024::new(key);

        let mut block = [0u8; 128];
        cipher.encrypt_block(&mut block);

        // Ciphertext should not be all zeros
        let is_all_zero = block.iter().all(|&b| b == 0);
        assert!(!is_all_zero, "Encryption of zero block should not produce zero block");
    }

    #[test]
    fn test_shift_rows_inverse() {
        let cipher = Aurora1024::new([0u8; 128]);

        let mut block = [0u8; 128];
        for i in 0..128 {
            block[i] = i as u8;
        }

        let original = block;
        cipher.shift_rows(&mut block);
        cipher.inv_shift_rows(&mut block);

        assert_eq!(block, original, "ShiftRows and InvShiftRows should be inverses");
    }

    #[test]
    fn test_aurora_mix_inverse() {
        let cipher = Aurora1024::new([0u8; 128]);

        for round in 1..=ROUNDS {
            let mut block = [0u8; 128];
            for i in 0..128 {
                block[i] = i as u8;
            }

            let original = block;
            cipher.aurora_mix(&mut block, round);
            cipher.inv_aurora_mix(&mut block, round);

            assert_eq!(block, original, "AuroraMix and InvAuroraMix should be inverses at round {}", round);
        }
    }
}


