//! Galois field GF(2^8) arithmetic operations

/// Slow but correct GF multiplication (used for table generation and fallback)
fn gf_mul_slow(a: u8, b: u8) -> u8 {
    let mut result = 0u16;
    let mut a_val = a as u16;
    let mut b_val = b as u16;

    for _ in 0..8 {
        if b_val & 1 != 0 {
            result ^= a_val;
        }
        b_val >>= 1;
        a_val <<= 1;
        if a_val & 0x100 != 0 {
            a_val ^= 0x11B;
        }
    }

    result as u8
}

/// Generate a lookup table for multiplying by a constant in GF(2^8) at compile time
const fn generate_gf_mul_table(constant: u8) -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = gf_mul_slow_const(constant, i as u8);
        i += 1;
    }
    table
}

/// Const version of GF multiplication for compile-time table generation
const fn gf_mul_slow_const(a: u8, b: u8) -> u8 {
    let mut result = 0u16;
    let mut a_val = a as u16;
    let mut b_val = b as u16;
    let mut bit = 0;
    
    while bit < 8 {
        if b_val & 1 != 0 {
            result ^= a_val;
        }
        b_val >>= 1;
        a_val <<= 1;
        if a_val & 0x100 != 0 {
            a_val ^= 0x11B;
        }
        bit += 1;
    }

    result as u8
}

/// Lookup table for multiplying by 2 in GF(2^8)
const GF_MUL_2: [u8; 256] = generate_gf_mul_table(2);

/// Lookup table for multiplying by 3 in GF(2^8)
const GF_MUL_3: [u8; 256] = generate_gf_mul_table(3);

/// Lookup table for multiplying by 4 in GF(2^8)
const GF_MUL_4: [u8; 256] = generate_gf_mul_table(4);

/// Lookup table for multiplying by 5 in GF(2^8)
const GF_MUL_5: [u8; 256] = generate_gf_mul_table(5);

/// Lookup table for multiplying by 6 in GF(2^8)
const GF_MUL_6: [u8; 256] = generate_gf_mul_table(6);

/// Galois field multiplication in GF(2^8) with reduction polynomial 0x11B
/// Optimized using lookup tables for common multipliers (1-6) used in the MIX matrix
pub fn gf_mul(a: u8, b: u8) -> u8 {
    // Fast path for common multipliers used in MIX matrix
    match a {
        0x01 => b,
        0x02 => GF_MUL_2[b as usize],
        0x03 => GF_MUL_3[b as usize],
        0x04 => GF_MUL_4[b as usize],
        0x05 => GF_MUL_5[b as usize],
        0x06 => GF_MUL_6[b as usize],
        _ => {
            // Fallback to slow method for other multipliers
            // This should rarely happen in practice since MIX matrix only uses 1-6
            gf_mul_slow(a, b)
        }
    }
}

/// Galois field exponentiation using square-and-multiply algorithm
pub fn gf_pow(a: u8, exp: u8) -> u8 {
    if exp == 0 {
        return 1;
    }
    if a == 0 {
        return 0;
    }

    let mut result = 1u8;
    let mut base = a;
    let mut e = exp;

    while e > 0 {
        if e & 1 != 0 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }

    result
}

/// Galois field multiplicative inverse using Fermat's little theorem: a^254
pub fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    gf_pow(a, 254)
}

/// Compute inverse of a 8x8 matrix over GF(256) using Gauss-Jordan elimination
pub fn invert_matrix_8x8_gf256(matrix: &[[u8; 8]; 8]) -> [[u8; 8]; 8] {
    // Build augmented matrix [M | I]
    let mut aug = [[0u8; 16]; 8];
    for i in 0..8 {
        for j in 0..8 {
            aug[i][j] = matrix[i][j];
        }
        aug[i][8 + i] = 1; // Identity matrix
    }

    // Forward elimination
    for col in 0..8 {
        // Find pivot
        let mut pivot_row = None;
        for row in col..8 {
            if aug[row][col] != 0 {
                pivot_row = Some(row);
                break;
            }
        }

        // If no pivot found, matrix is singular
        let pivot_row = match pivot_row {
            Some(row) => row,
            None => {
                panic!("Matrix is not invertible: column {} has no non-zero pivot", col);
            }
        };

        // Swap rows
        if pivot_row != col {
            aug.swap(col, pivot_row);
        }

        // Normalize pivot row
        let pivot_val = aug[col][col];
        if pivot_val == 0 {
            panic!("Matrix is not invertible: pivot is zero after swap");
        }
        let inv_pivot = gf_inv(pivot_val);
        for j in 0..16 {
            aug[col][j] = gf_mul(aug[col][j], inv_pivot);
        }

        // Eliminate other rows
        for row in 0..8 {
            if row != col && aug[row][col] != 0 {
                let factor = aug[row][col];
                for j in 0..16 {
                    aug[row][j] ^= gf_mul(aug[col][j], factor);
                }
            }
        }
    }

    // Extract inverse matrix from right half
    let mut inv_matrix = [[0u8; 8]; 8];
    for i in 0..8 {
        for j in 0..8 {
            inv_matrix[i][j] = aug[i][8 + j];
        }
    }

    inv_matrix
}

/// Constant-time comparison of two byte slices
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (ai, bi) in a.iter().zip(b.iter()) {
        diff |= ai ^ bi;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul() {
        // Test some known Galois field multiplications
        assert_eq!(gf_mul(0x02, 0x03), 0x06);
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        assert_eq!(gf_mul(0x00, 0xFF), 0x00);
        assert_eq!(gf_mul(0xFF, 0x00), 0x00);
    }

    #[test]
    fn test_gf_inv() {
        // Test multiplicative inverse
        for i in 1..=255 {
            let inv = gf_inv(i);
            let product = gf_mul(i, inv);
            assert_eq!(product, 1, "gf_inv({}) * {} should equal 1", i, i);
        }
    }

    #[test]
    fn test_matrix_inversion() {
        // Test with identity matrix
        let identity = [
            [1, 0, 0, 0, 0, 0, 0, 0],
            [0, 1, 0, 0, 0, 0, 0, 0],
            [0, 0, 1, 0, 0, 0, 0, 0],
            [0, 0, 0, 1, 0, 0, 0, 0],
            [0, 0, 0, 0, 1, 0, 0, 0],
            [0, 0, 0, 0, 0, 1, 0, 0],
            [0, 0, 0, 0, 0, 0, 1, 0],
            [0, 0, 0, 0, 0, 0, 0, 1],
        ];
        let inv = invert_matrix_8x8_gf256(&identity);
        assert_eq!(inv, identity);
    }

    #[test]
    fn test_ct_eq() {
        assert!(ct_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!ct_eq(&[1, 2, 3], &[1, 2]));
        assert!(!ct_eq(&[1, 2], &[1, 2, 3]));
    }
}


