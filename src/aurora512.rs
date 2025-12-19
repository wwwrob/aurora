//! AURORA-512: Block cipher
//!
//! A custom 512-bit block cipher with 512-bit keys and 24 rounds.
//! Features a unique 8x8 state layout with custom diffusion operations
//! including the proprietary AuroraMix transformation.
//!
//! - Block size: 512 bits (64 bytes)
//! - Key size: 512 bits (64 bytes)
//! - Rounds: 24

use crate::internal::{gf_mul, invert_matrix_8x8_gf256, XorShift64Star};

/// Block size in bytes (512 bits)
pub const BLOCK_BYTES: usize = 64;

/// Key size in bytes (512 bits)
pub const KEY_BYTES: usize = 64;

/// Number of rounds
pub const ROUNDS: usize = 24;

/// Number of round keys (ROUNDS + 1)
const ROUND_KEYS: usize = 25;

/// Row rotation offsets for rows 0..7
const SHIFT: [usize; 8] = [0, 1, 3, 4, 6, 7, 2, 5];

/// S-box generation seed
const SBOX_SEED: u64 = 0xC0FFEE1234BEEF99;

/// Base seed for round key masks
const MASK_SEED_BASE: u64 = 0x9E3779B97F4A7C15;

/// Column mixing matrix (8x8 over GF(2^8))
/// This matrix is designed to be invertible (MDS-like structure)
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
fn generate_round_keys(key: [u8; 64]) -> [[u8; 64]; ROUND_KEYS] {
    let mut rk = [[0u8; 64]; ROUND_KEYS];
    rk[0] = key;

    let sbox = generate_sbox();

    for r in 1..=ROUNDS {
        let mut tmp = rk[r - 1];

        // Apply substitution box
        for i in 0..64 {
            tmp[i] = sbox[tmp[i] as usize];
        }

        // Rotate left by (r % 64) bytes
        let rot_bytes = r % 64;
        if rot_bytes > 0 {
            let mut rotated = [0u8; 64];
            for i in 0..64 {
                rotated[i] = tmp[(i + rot_bytes) % 64];
            }
            tmp = rotated;
        }

        // XOR with mask from PRNG
        let mut prng = XorShift64Star::new(MASK_SEED_BASE ^ (r as u64));
        for i in 0..64 {
            tmp[i] ^= prng.next_u8();
        }

        rk[r] = tmp;
    }

    rk
}

/// AURORA-512 cipher
pub struct Aurora512 {
    rk: [[u8; 64]; ROUND_KEYS],
    sbox: [u8; 256],
    inv_sbox: [u8; 256],
    inv_mix: [[u8; 8]; 8],
}

impl Aurora512 {
    /// Create a new AURORA-512 cipher instance with the given key
    pub fn new(key: [u8; 64]) -> Self {
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
    fn add_round_key(&self, state: &mut [u8; 64], round: usize) {
        for i in 0..64 {
            state[i] ^= self.rk[round][i];
        }
    }

    /// Apply substitution box to each byte
    fn sub_bytes(&self, state: &mut [u8; 64]) {
        for i in 0..64 {
            state[i] = self.sbox[state[i] as usize];
        }
    }

    /// Apply inverse substitution box to each byte
    fn inv_sub_bytes(&self, state: &mut [u8; 64]) {
        for i in 0..64 {
            state[i] = self.inv_sbox[state[i] as usize];
        }
    }

    /// Rotate each row left by SHIFT[row] bytes
    fn shift_rows(&self, state: &mut [u8; 64]) {
        let mut new_state = [0u8; 64];
        for row in 0..8 {
            let shift = SHIFT[row];
            for col in 0..8 {
                let new_col = (col + shift) % 8;
                new_state[row * 8 + new_col] = state[row * 8 + col];
            }
        }
        *state = new_state;
    }

    /// Rotate each row right by SHIFT[row] bytes (inverse operation)
    fn inv_shift_rows(&self, state: &mut [u8; 64]) {
        let mut new_state = [0u8; 64];
        for row in 0..8 {
            let shift = SHIFT[row];
            for col in 0..8 {
                let new_col = (col + 8 - shift) % 8;
                new_state[row * 8 + new_col] = state[row * 8 + col];
            }
        }
        *state = new_state;
    }

    /// Apply column mixing matrix to each column
    /// Optimized: unrolled inner loops and direct state access
    fn mix_columns8(&self, state: &mut [u8; 64]) {
        let mut new_state = [0u8; 64];
        for col in 0..8 {
            // Extract column directly
            let v0 = state[0 * 8 + col];
            let v1 = state[1 * 8 + col];
            let v2 = state[2 * 8 + col];
            let v3 = state[3 * 8 + col];
            let v4 = state[4 * 8 + col];
            let v5 = state[5 * 8 + col];
            let v6 = state[6 * 8 + col];
            let v7 = state[7 * 8 + col];

            // Multiply by MIX matrix - unrolled for performance
            new_state[0 * 8 + col] = gf_mul(MIX[0][0], v0) ^ gf_mul(MIX[0][1], v1) ^ gf_mul(MIX[0][2], v2) ^ gf_mul(MIX[0][3], v3) ^ gf_mul(MIX[0][4], v4) ^ gf_mul(MIX[0][5], v5) ^ gf_mul(MIX[0][6], v6) ^ gf_mul(MIX[0][7], v7);
            new_state[1 * 8 + col] = gf_mul(MIX[1][0], v0) ^ gf_mul(MIX[1][1], v1) ^ gf_mul(MIX[1][2], v2) ^ gf_mul(MIX[1][3], v3) ^ gf_mul(MIX[1][4], v4) ^ gf_mul(MIX[1][5], v5) ^ gf_mul(MIX[1][6], v6) ^ gf_mul(MIX[1][7], v7);
            new_state[2 * 8 + col] = gf_mul(MIX[2][0], v0) ^ gf_mul(MIX[2][1], v1) ^ gf_mul(MIX[2][2], v2) ^ gf_mul(MIX[2][3], v3) ^ gf_mul(MIX[2][4], v4) ^ gf_mul(MIX[2][5], v5) ^ gf_mul(MIX[2][6], v6) ^ gf_mul(MIX[2][7], v7);
            new_state[3 * 8 + col] = gf_mul(MIX[3][0], v0) ^ gf_mul(MIX[3][1], v1) ^ gf_mul(MIX[3][2], v2) ^ gf_mul(MIX[3][3], v3) ^ gf_mul(MIX[3][4], v4) ^ gf_mul(MIX[3][5], v5) ^ gf_mul(MIX[3][6], v6) ^ gf_mul(MIX[3][7], v7);
            new_state[4 * 8 + col] = gf_mul(MIX[4][0], v0) ^ gf_mul(MIX[4][1], v1) ^ gf_mul(MIX[4][2], v2) ^ gf_mul(MIX[4][3], v3) ^ gf_mul(MIX[4][4], v4) ^ gf_mul(MIX[4][5], v5) ^ gf_mul(MIX[4][6], v6) ^ gf_mul(MIX[4][7], v7);
            new_state[5 * 8 + col] = gf_mul(MIX[5][0], v0) ^ gf_mul(MIX[5][1], v1) ^ gf_mul(MIX[5][2], v2) ^ gf_mul(MIX[5][3], v3) ^ gf_mul(MIX[5][4], v4) ^ gf_mul(MIX[5][5], v5) ^ gf_mul(MIX[5][6], v6) ^ gf_mul(MIX[5][7], v7);
            new_state[6 * 8 + col] = gf_mul(MIX[6][0], v0) ^ gf_mul(MIX[6][1], v1) ^ gf_mul(MIX[6][2], v2) ^ gf_mul(MIX[6][3], v3) ^ gf_mul(MIX[6][4], v4) ^ gf_mul(MIX[6][5], v5) ^ gf_mul(MIX[6][6], v6) ^ gf_mul(MIX[6][7], v7);
            new_state[7 * 8 + col] = gf_mul(MIX[7][0], v0) ^ gf_mul(MIX[7][1], v1) ^ gf_mul(MIX[7][2], v2) ^ gf_mul(MIX[7][3], v3) ^ gf_mul(MIX[7][4], v4) ^ gf_mul(MIX[7][5], v5) ^ gf_mul(MIX[7][6], v6) ^ gf_mul(MIX[7][7], v7);
        }
        *state = new_state;
    }

    /// Apply inverse column mixing matrix to each column
    /// Optimized: unrolled inner loops and direct state access
    fn inv_mix_columns8(&self, state: &mut [u8; 64]) {
        let mut new_state = [0u8; 64];
        for col in 0..8 {
            // Extract column directly
            let v0 = state[0 * 8 + col];
            let v1 = state[1 * 8 + col];
            let v2 = state[2 * 8 + col];
            let v3 = state[3 * 8 + col];
            let v4 = state[4 * 8 + col];
            let v5 = state[5 * 8 + col];
            let v6 = state[6 * 8 + col];
            let v7 = state[7 * 8 + col];

            // Multiply by INV_MIX matrix - unrolled for performance
            new_state[0 * 8 + col] = gf_mul(self.inv_mix[0][0], v0) ^ gf_mul(self.inv_mix[0][1], v1) ^ gf_mul(self.inv_mix[0][2], v2) ^ gf_mul(self.inv_mix[0][3], v3) ^ gf_mul(self.inv_mix[0][4], v4) ^ gf_mul(self.inv_mix[0][5], v5) ^ gf_mul(self.inv_mix[0][6], v6) ^ gf_mul(self.inv_mix[0][7], v7);
            new_state[1 * 8 + col] = gf_mul(self.inv_mix[1][0], v0) ^ gf_mul(self.inv_mix[1][1], v1) ^ gf_mul(self.inv_mix[1][2], v2) ^ gf_mul(self.inv_mix[1][3], v3) ^ gf_mul(self.inv_mix[1][4], v4) ^ gf_mul(self.inv_mix[1][5], v5) ^ gf_mul(self.inv_mix[1][6], v6) ^ gf_mul(self.inv_mix[1][7], v7);
            new_state[2 * 8 + col] = gf_mul(self.inv_mix[2][0], v0) ^ gf_mul(self.inv_mix[2][1], v1) ^ gf_mul(self.inv_mix[2][2], v2) ^ gf_mul(self.inv_mix[2][3], v3) ^ gf_mul(self.inv_mix[2][4], v4) ^ gf_mul(self.inv_mix[2][5], v5) ^ gf_mul(self.inv_mix[2][6], v6) ^ gf_mul(self.inv_mix[2][7], v7);
            new_state[3 * 8 + col] = gf_mul(self.inv_mix[3][0], v0) ^ gf_mul(self.inv_mix[3][1], v1) ^ gf_mul(self.inv_mix[3][2], v2) ^ gf_mul(self.inv_mix[3][3], v3) ^ gf_mul(self.inv_mix[3][4], v4) ^ gf_mul(self.inv_mix[3][5], v5) ^ gf_mul(self.inv_mix[3][6], v6) ^ gf_mul(self.inv_mix[3][7], v7);
            new_state[4 * 8 + col] = gf_mul(self.inv_mix[4][0], v0) ^ gf_mul(self.inv_mix[4][1], v1) ^ gf_mul(self.inv_mix[4][2], v2) ^ gf_mul(self.inv_mix[4][3], v3) ^ gf_mul(self.inv_mix[4][4], v4) ^ gf_mul(self.inv_mix[4][5], v5) ^ gf_mul(self.inv_mix[4][6], v6) ^ gf_mul(self.inv_mix[4][7], v7);
            new_state[5 * 8 + col] = gf_mul(self.inv_mix[5][0], v0) ^ gf_mul(self.inv_mix[5][1], v1) ^ gf_mul(self.inv_mix[5][2], v2) ^ gf_mul(self.inv_mix[5][3], v3) ^ gf_mul(self.inv_mix[5][4], v4) ^ gf_mul(self.inv_mix[5][5], v5) ^ gf_mul(self.inv_mix[5][6], v6) ^ gf_mul(self.inv_mix[5][7], v7);
            new_state[6 * 8 + col] = gf_mul(self.inv_mix[6][0], v0) ^ gf_mul(self.inv_mix[6][1], v1) ^ gf_mul(self.inv_mix[6][2], v2) ^ gf_mul(self.inv_mix[6][3], v3) ^ gf_mul(self.inv_mix[6][4], v4) ^ gf_mul(self.inv_mix[6][5], v5) ^ gf_mul(self.inv_mix[6][6], v6) ^ gf_mul(self.inv_mix[6][7], v7);
            new_state[7 * 8 + col] = gf_mul(self.inv_mix[7][0], v0) ^ gf_mul(self.inv_mix[7][1], v1) ^ gf_mul(self.inv_mix[7][2], v2) ^ gf_mul(self.inv_mix[7][3], v3) ^ gf_mul(self.inv_mix[7][4], v4) ^ gf_mul(self.inv_mix[7][5], v5) ^ gf_mul(self.inv_mix[7][6], v6) ^ gf_mul(self.inv_mix[7][7], v7);
        }
        *state = new_state;
    }

    /// AuroraMix: extra diffusion step
    fn aurora_mix(&self, state: &mut [u8; 64], round: usize) {
        let mut l = [0u8; 32];
        let mut r = [0u8; 32];

        // Split state into L and R
        for i in 0..32 {
            l[i] = state[i];
            r[i] = state[i + 32];
        }

        // Three passes
        for p in 0..3 {
            let k = (7 * p + round) % 32;
            let a = (1 + round + p) % 8;
            let b = (3 + round + 2 * p) % 8;

            // Update L
            for i in 0..32 {
                l[i] ^= rotl8(r[(i + k) % 32], a);
            }

            let k2 = (k + 11) % 32;

            // Update R
            for i in 0..32 {
                r[i] ^= rotr8(l[(i + k2) % 32], b);
            }
        }

        // Swap halves
        for i in 0..32 {
            state[i] = r[i];
            state[i + 32] = l[i];
        }
    }

    /// Inverse AuroraMix: undo the diffusion step
    fn inv_aurora_mix(&self, state: &mut [u8; 64], round: usize) {
        let mut l = [0u8; 32];
        let mut r = [0u8; 32];

        // Undo swap first (recover original L and R)
        for i in 0..32 {
            r[i] = state[i];
            l[i] = state[i + 32];
        }

        // Undo three passes in reverse order
        for p in (0..3).rev() {
            let k = (7 * p + round) % 32;
            let a = (1 + round + p) % 8;
            let b = (3 + round + 2 * p) % 8;
            let k2 = (k + 11) % 32;

            // Undo R update first
            for i in 0..32 {
                r[i] ^= rotr8(l[(i + k2) % 32], b);
            }

            // Undo L update
            for i in 0..32 {
                l[i] ^= rotl8(r[(i + k) % 32], a);
            }
        }

        // Write back as L||R
        for i in 0..32 {
            state[i] = l[i];
            state[i + 32] = r[i];
        }
    }

    /// Encrypt a 64-byte block
    pub fn encrypt_block(&self, block: &mut [u8; 64]) {
        // Initial whitening
        self.add_round_key(block, 0);

        // Rounds 1..24
        for r in 1..=ROUNDS {
            self.sub_bytes(block);
            self.shift_rows(block);
            self.mix_columns8(block);
            self.aurora_mix(block, r);
            self.add_round_key(block, r);
        }
    }

    /// Decrypt a 64-byte block
    pub fn decrypt_block(&self, block: &mut [u8; 64]) {
        // Rounds 24..1 (reverse order)
        for r in (1..=ROUNDS).rev() {
            self.add_round_key(block, r);
            self.inv_aurora_mix(block, r);
            self.inv_mix_columns8(block);
            self.inv_shift_rows(block);
            self.inv_sub_bytes(block);
        }

        // Final whitening
        self.add_round_key(block, 0);
    }

    /// Encrypt a block and return as raw bytes
    pub fn encrypt_block_bytes(&self, block: &[u8; 64]) -> Vec<u8> {
        let mut result = *block;
        self.encrypt_block(&mut result);
        result.to_vec()
    }

    /// Encrypt a block and return in the specified format
    pub fn encrypt_block_formatted(&self, block: &[u8; 64], format: crate::output_format::OutputFormat) -> String {
        let bytes = self.encrypt_block_bytes(block);
        format.encode(&bytes)
    }

    /// Encrypt a block and return as base64
    pub fn encrypt_block_as_base64(&self, block: &[u8; 64]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::Base64)
    }

    /// Encrypt a block and return as hex (lowercase)
    pub fn encrypt_block_as_hex_lowercase(&self, block: &[u8; 64]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::HexLowercase)
    }

    /// Encrypt a block and return as hex (uppercase)
    pub fn encrypt_block_as_hex_uppercase(&self, block: &[u8; 64]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::HexUppercase)
    }

    /// Encrypt a block and return as base32
    pub fn encrypt_block_as_base32(&self, block: &[u8; 64]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::Base32)
    }

    /// Encrypt a block and return as Azonine (base-62: azAZ09)
    pub fn encrypt_block_as_azonine(&self, block: &[u8; 64]) -> String {
        self.encrypt_block_formatted(block, crate::output_format::OutputFormat::Azonine)
    }

    /// Decrypt a block from raw bytes
    pub fn decrypt_block_bytes(&self, block: &[u8]) -> Result<Vec<u8>, String> {
        if block.len() != 64 {
            return Err(format!("Block must be exactly 64 bytes, got {}", block.len()));
        }
        let mut result = [0u8; 64];
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
        use crate::internal::XorShift64Star;
        let mut prng = XorShift64Star::new(0xDEADBEEFCAFEBABE);
        let mut key = [0u8; 64];
        for i in 0..64 {
            key[i] = prng.next_u8();
        }

        let cipher = Aurora512::new(key);

        for _ in 0..200 {
            let mut block = [0u8; 64];
            for i in 0..64 {
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
        let key = [0u8; 64];
        let cipher = Aurora512::new(key);

        let mut block = [0u8; 64];
        cipher.encrypt_block(&mut block);

        // Ciphertext should not be all zeros
        let is_all_zero = block.iter().all(|&b| b == 0);
        assert!(!is_all_zero, "Encryption of zero block should not produce zero block");

        #[cfg(feature = "print_vectors")]
        {
            println!("Zero block encryption result:");
            for (i, byte) in block.iter().enumerate() {
                if i % 16 == 0 {
                    println!();
                }
                print!("{:02x} ", byte);
            }
            println!();
        }
    }

    #[test]
    fn test_roundtrip_various_keys() {
        // Test with various key patterns
        let test_keys = vec![
            [0u8; 64],                    // All zeros
            [0xFFu8; 64],                 // All ones
            [0xAAu8; 64],                 // Alternating pattern
            [0x55u8; 64],                 // Alternating pattern
        ];

        for key in test_keys {
            let cipher = Aurora512::new(key);

            // Test with various block patterns
            let test_blocks = vec![
                [0u8; 64],
                [0xFFu8; 64],
                [0xAAu8; 64],
                [0x55u8; 64],
            ];

            for mut block in test_blocks {
                let original = block;
                cipher.encrypt_block(&mut block);
                cipher.decrypt_block(&mut block);
                assert_eq!(block, original, "Roundtrip failed for key pattern and block pattern");
            }
        }
    }

    #[test]
    fn test_shift_rows_inverse() {
        let cipher = Aurora512::new([0u8; 64]);

        let mut block = [0u8; 64];
        for i in 0..64 {
            block[i] = i as u8;
        }

        let original = block;
        cipher.shift_rows(&mut block);
        cipher.inv_shift_rows(&mut block);

        assert_eq!(block, original, "ShiftRows and InvShiftRows should be inverses");
    }

    #[test]
    fn test_aurora_mix_inverse() {
        let cipher = Aurora512::new([0u8; 64]);

        for round in 1..=ROUNDS {
            let mut block = [0u8; 64];
            for i in 0..64 {
                block[i] = i as u8;
            }

            let original = block;
            cipher.aurora_mix(&mut block, round);
            cipher.inv_aurora_mix(&mut block, round);

            assert_eq!(block, original, "AuroraMix and InvAuroraMix should be inverses at round {}", round);
        }
    }
}

