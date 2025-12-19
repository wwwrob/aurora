//! AURORA-SEAL-1024: Secure-by-default authenticated encryption wrapper
//!
//! Provides authenticated encryption with associated data (AEAD) functionality
//! built on top of the AURORA-1024 block cipher. This is the recommended
//! "secure-by-default" API for encrypting arbitrary-length data.

use crate::aurora1024::Aurora1024;
use crate::internal::ct_eq;

const BLOCK_SIZE: usize = 128;
const KEY_SIZE: usize = 128;

/// Derive a subkey from master key using label
fn derive_subkey_1024(master_key: [u8; KEY_SIZE], label: [u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    let aur = Aurora1024::new(master_key);
    let mut block = label;
    aur.encrypt_block(&mut block);
    block
}

/// AURORA-SEAL-1024 authenticated encryption wrapper
pub struct AuroraSeal1024 {
    aurora_mac: Aurora1024,
    aurora_enc: Aurora1024,
}

impl AuroraSeal1024 {
    /// Create a new AURORA-SEAL-1024 instance with the given master key
    pub fn new(master_key: [u8; KEY_SIZE]) -> Self {
        // Derive MAC and encryption subkeys
        let mut l_mac = [0u8; KEY_SIZE];
        let mac_label = b"AURORA1024:MAC";
        l_mac[..mac_label.len()].copy_from_slice(mac_label);
        // Rest is already zero

        let mut l_enc = [0u8; KEY_SIZE];
        let enc_label = b"AURORA1024:ENC";
        l_enc[..enc_label.len()].copy_from_slice(enc_label);
        // Rest is already zero

        let k_mac = derive_subkey_1024(master_key, l_mac);
        let k_enc = derive_subkey_1024(master_key, l_enc);

        Self {
            aurora_mac: Aurora1024::new(k_mac),
            aurora_enc: Aurora1024::new(k_enc),
        }
    }

    /// Compute MAC tag for AAD, nonce, and plaintext
    fn mac_tag(&self, aad: &[u8], nonce: &[u8], plaintext: &[u8]) -> [u8; BLOCK_SIZE] {
        // Pre-allocate with estimated capacity to reduce reallocations
        let estimated_len = aad.len() + nonce.len() + plaintext.len() + BLOCK_SIZE + BLOCK_SIZE;
        let mut input = Vec::with_capacity(estimated_len);
        input.extend_from_slice(aad);
        input.extend_from_slice(nonce);
        input.extend_from_slice(plaintext);

        // Length block: aad_len (u64 LE), nonce_len (u64 LE), pt_len (u64 LE), rest zeros
        let mut length_block = [0u8; BLOCK_SIZE];
        length_block[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        length_block[8..16].copy_from_slice(&(nonce.len() as u64).to_le_bytes());
        length_block[16..24].copy_from_slice(&(plaintext.len() as u64).to_le_bytes());
        input.extend_from_slice(&length_block);

        // Padding: process in full blocks, final partial block gets 0x80 then zeros
        let total_len = input.len();
        let blocks_needed = (total_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
        let padded_len = blocks_needed * BLOCK_SIZE;
        input.resize(padded_len, 0);
        if total_len % BLOCK_SIZE == 0 {
            // Already exact multiple, append extra padding block
            input.resize(padded_len + BLOCK_SIZE, 0);
            input[total_len] = 0x80;
        } else {
            // Add padding to last block
            input[total_len] = 0x80;
        }

        // Compression: start with IV_TAG
        let mut iv_tag = [0u8; BLOCK_SIZE];
        let iv_label = b"AURORA:TAG";
        iv_tag[..iv_label.len()].copy_from_slice(iv_label);

        let mut s = iv_tag;

        // Process each block - optimized XOR loop
        for chunk in input.chunks_exact(BLOCK_SIZE) {
            // XOR chunk into s - compiler will optimize this simple loop well
            for i in 0..BLOCK_SIZE {
                s[i] ^= chunk[i];
            }
            // Encrypt s
            self.aurora_mac.encrypt_block(&mut s);
        }

        s
    }

    /// Stream encryption using CTR-like mode with synthetic IV = tag
    fn stream_xor(&self, tag: &[u8; BLOCK_SIZE], input: &[u8]) -> Vec<u8> {
        let mut output = Vec::with_capacity(input.len());
        let mut counter = 0u64;

        for chunk in input.chunks(BLOCK_SIZE) {
            // Build counter block: first 8 bytes = counter as u64 LE, rest zeros
            // Optimized: directly XOR counter into tag's first 8 bytes
            let mut stream_block = *tag;
            let counter_bytes = counter.to_le_bytes();
            // XOR only the first 8 bytes (counter affects only first 8 bytes)
            for i in 0..8 {
                stream_block[i] ^= counter_bytes[i];
            }

            // Encrypt to get keystream
            self.aurora_enc.encrypt_block(&mut stream_block);

            // XOR with input chunk
            if chunk.len() == BLOCK_SIZE {
                // Full block
                for (i, &b) in chunk.iter().enumerate() {
                    output.push(b ^ stream_block[i]);
                }
            } else {
                // Partial block
                for (i, &b) in chunk.iter().enumerate() {
                    output.push(b ^ stream_block[i]);
                }
            }

            counter += 1;
        }

        output
    }

    /// Seal (encrypt and authenticate) plaintext with AAD and nonce
    ///
    /// Returns a packet with format: [version][nonce_len][nonce...][tag...][ciphertext...]
    pub fn seal(&self, aad: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
        // Compute tag
        let tag = self.mac_tag(aad, nonce, plaintext);

        // Encrypt plaintext
        let ciphertext = self.stream_xor(&tag, plaintext);

        // Build packet
        let mut packet = Vec::new();
        packet.push(1u8); // version
        packet.push(nonce.len() as u8); // nonce_len
        packet.extend_from_slice(nonce);
        packet.extend_from_slice(&tag);
        packet.extend_from_slice(&ciphertext);

        packet
    }

    /// Open (decrypt and verify) a packet with AAD
    ///
    /// Returns Some(plaintext) if authentication succeeds, None otherwise
    pub fn open(&self, aad: &[u8], packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 2 {
            return None;
        }

        let version = packet[0];
        if version != 1 {
            return None;
        }

        let nonce_len = packet[1] as usize;
        if packet.len() < 2 + nonce_len + BLOCK_SIZE {
            return None;
        }

        let nonce = &packet[2..2 + nonce_len];
        let tag_start = 2 + nonce_len;
        let tag_end = tag_start + BLOCK_SIZE;
        let tag = &packet[tag_start..tag_end];
        let ciphertext = &packet[tag_end..];

        // Decrypt ciphertext
        let tag_array: [u8; BLOCK_SIZE] = tag.try_into().unwrap();
        let plaintext = self.stream_xor(&tag_array, ciphertext);

        // Verify tag
        let computed_tag = self.mac_tag(aad, nonce, &plaintext);
        if ct_eq(&computed_tag, tag) {
            Some(plaintext)
        } else {
            None
        }
    }

    /// Seal and return in the specified format
    pub fn seal_formatted(&self, aad: &[u8], nonce: &[u8], plaintext: &[u8], format: crate::output_format::OutputFormat) -> String {
        let packet = self.seal(aad, nonce, plaintext);
        format.encode(&packet)
    }

    /// Seal and return as base64
    pub fn seal_as_base64(&self, aad: &[u8], nonce: &[u8], plaintext: &[u8]) -> String {
        self.seal_formatted(aad, nonce, plaintext, crate::output_format::OutputFormat::Base64)
    }

    /// Seal and return as hex (lowercase)
    pub fn seal_as_hex_lowercase(&self, aad: &[u8], nonce: &[u8], plaintext: &[u8]) -> String {
        self.seal_formatted(aad, nonce, plaintext, crate::output_format::OutputFormat::HexLowercase)
    }

    /// Seal and return as hex (uppercase)
    pub fn seal_as_hex_uppercase(&self, aad: &[u8], nonce: &[u8], plaintext: &[u8]) -> String {
        self.seal_formatted(aad, nonce, plaintext, crate::output_format::OutputFormat::HexUppercase)
    }

    /// Seal and return as base32
    pub fn seal_as_base32(&self, aad: &[u8], nonce: &[u8], plaintext: &[u8]) -> String {
        self.seal_formatted(aad, nonce, plaintext, crate::output_format::OutputFormat::Base32)
    }

    /// Seal and return as Azonine (base-62: azAZ09)
    pub fn seal_as_azonine(&self, aad: &[u8], nonce: &[u8], plaintext: &[u8]) -> String {
        self.seal_formatted(aad, nonce, plaintext, crate::output_format::OutputFormat::Azonine)
    }

    /// Open from encoded string in the specified format
    pub fn open_formatted(&self, aad: &[u8], encoded: &str, format: crate::output_format::OutputFormat) -> Option<Vec<u8>> {
        let packet = format.decode(encoded).ok()?;
        self.open(aad, &packet)
    }

    /// Open from base64 string
    pub fn open_from_base64(&self, aad: &[u8], encoded: &str) -> Option<Vec<u8>> {
        self.open_formatted(aad, encoded, crate::output_format::OutputFormat::Base64)
    }

    /// Open from hex string (lowercase or uppercase)
    pub fn open_from_hex(&self, aad: &[u8], encoded: &str) -> Option<Vec<u8>> {
        self.open_formatted(aad, encoded, crate::output_format::OutputFormat::HexLowercase)
    }

    /// Open from base32 string
    pub fn open_from_base32(&self, aad: &[u8], encoded: &str) -> Option<Vec<u8>> {
        self.open_formatted(aad, encoded, crate::output_format::OutputFormat::Base32)
    }

    /// Open from Azonine string (base-62: azAZ09)
    pub fn open_from_azonine(&self, aad: &[u8], encoded: &str) -> Option<Vec<u8>> {
        self.open_formatted(aad, encoded, crate::output_format::OutputFormat::Azonine)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::XorShift64Star;

    #[test]
    fn test_roundtrip_various_lengths() {
        let mut prng = XorShift64Star::new(0x1234567890ABCDEF);
        let mut master_key = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            master_key[i] = prng.next_u8();
        }

        let mut nonce = [0u8; 16];
        for i in 0..16 {
            nonce[i] = prng.next_u8();
        }

        let mut aad = vec![0u8; 32];
        for i in 0..32 {
            aad[i] = prng.next_u8();
        }

        let seal = AuroraSeal1024::new(master_key);

        // Test various plaintext lengths
        let lengths = vec![0, 1, BLOCK_SIZE - 1, BLOCK_SIZE, BLOCK_SIZE + 1, 1000, 4096];

        for len in lengths {
            let mut plaintext = vec![0u8; len];
            for i in 0..len {
                plaintext[i] = prng.next_u8();
            }

            let packet = seal.seal(&aad, &nonce, &plaintext);
            let decrypted = seal.open(&aad, &packet);

            assert!(decrypted.is_some(), "Decryption failed for length {}", len);
            assert_eq!(decrypted.unwrap(), plaintext, "Roundtrip failed for length {}", len);
        }
    }

    #[test]
    fn test_tamper_ciphertext() {
        let mut prng = XorShift64Star::new(0xABCDEF1234567890);
        let mut master_key = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            master_key[i] = prng.next_u8();
        }

        let mut nonce = [0u8; 16];
        for i in 0..16 {
            nonce[i] = prng.next_u8();
        }

        let aad = b"test aad";

        let seal = AuroraSeal1024::new(master_key);
        let plaintext = b"Hello, world!";
        let mut packet = seal.seal(aad, &nonce, plaintext);

        // Tamper with ciphertext
        let tag_start = 2 + nonce.len() + BLOCK_SIZE;
        if tag_start < packet.len() {
            packet[tag_start] ^= 1;
        }

        let result = seal.open(aad, &packet);
        assert!(result.is_none(), "Tampered ciphertext should be rejected");
    }

    #[test]
    fn test_tamper_tag() {
        let mut prng = XorShift64Star::new(0xFEDCBA0987654321);
        let mut master_key = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            master_key[i] = prng.next_u8();
        }

        let mut nonce = [0u8; 16];
        for i in 0..16 {
            nonce[i] = prng.next_u8();
        }

        let aad = b"test aad";

        let seal = AuroraSeal1024::new(master_key);
        let plaintext = b"Hello, world!";
        let mut packet = seal.seal(aad, &nonce, plaintext);

        // Tamper with tag
        let tag_start = 2 + nonce.len();
        packet[tag_start] ^= 1;

        let result = seal.open(aad, &packet);
        assert!(result.is_none(), "Tampered tag should be rejected");
    }

    #[test]
    fn test_tamper_aad() {
        let mut prng = XorShift64Star::new(0x1111222233334444);
        let mut master_key = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            master_key[i] = prng.next_u8();
        }

        let mut nonce = [0u8; 16];
        for i in 0..16 {
            nonce[i] = prng.next_u8();
        }

        let aad = b"test aad";

        let seal = AuroraSeal1024::new(master_key);
        let plaintext = b"Hello, world!";
        let packet = seal.seal(aad, &nonce, plaintext);

        // Try to open with different AAD
        let wrong_aad = b"wrong aad";
        let result = seal.open(wrong_aad, &packet);
        assert!(result.is_none(), "Different AAD should be rejected");
    }

    #[test]
    fn test_tamper_nonce() {
        let mut prng = XorShift64Star::new(0x5555666677778888);
        let mut master_key = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            master_key[i] = prng.next_u8();
        }

        let mut nonce = [0u8; 16];
        for i in 0..16 {
            nonce[i] = prng.next_u8();
        }

        let aad = b"test aad";

        let seal = AuroraSeal1024::new(master_key);
        let plaintext = b"Hello, world!";
        let mut packet = seal.seal(aad, &nonce, plaintext);

        // Tamper with nonce in packet
        packet[2] ^= 1;

        let result = seal.open(aad, &packet);
        assert!(result.is_none(), "Tampered nonce should be rejected");
    }
}


