//! xorshift64* PRNG for deterministic random number generation

/// xorshift64* PRNG
pub struct XorShift64Star {
    state: u64,
}

impl XorShift64Star {
    /// Create a new PRNG with the given seed
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generate next u64 value
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Generate next u32 value (upper 32 bits of next_u64)
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Generate next u8 value (low 8 bits of next_u64)
    pub fn next_u8(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prng_deterministic() {
        let mut prng1 = XorShift64Star::new(0x1234567890ABCDEF);
        let mut prng2 = XorShift64Star::new(0x1234567890ABCDEF);

        for _ in 0..100 {
            assert_eq!(prng1.next_u64(), prng2.next_u64());
            assert_eq!(prng1.next_u32(), prng2.next_u32());
            assert_eq!(prng1.next_u8(), prng2.next_u8());
        }
    }
}


