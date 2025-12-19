//! Output format utilities for encryption/decryption results

use base64::{engine::general_purpose::STANDARD, Engine};
use hex;
use base32::Alphabet;

/// Output format for encryption/decryption results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Raw bytes (Vec<u8>)
    RawBytes,
    /// Base64 encoding
    Base64,
    /// Hexadecimal encoding (lowercase)
    HexLowercase,
    /// Hexadecimal encoding (uppercase)
    HexUppercase,
    /// Base32 encoding
    Base32,
    /// Azonine encoding (base-62: azAZ09)
    Azonine,
}

/// Azonine alphabet: azAZ09 (lowercase a-z, uppercase A-Z, digits 0-9)
const AZONINE_ALPHABET: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Encode bytes to Azonine (base-62) format
/// To preserve leading zeros, we prepend the original length encoded in base-62
fn encode_azonine(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    // First, encode the length (number of bytes) in base-62
    let mut length_digits = Vec::new();
    let mut len = data.len();
    if len == 0 {
        length_digits.push(0);
    } else {
        while len > 0 {
            length_digits.push(len % 62);
            len /= 62;
        }
    }
    let length_str: String = length_digits.iter().rev().map(|&d| AZONINE_ALPHABET[d] as char).collect();
    
    // Then encode the actual data
    let mut digits = Vec::new();
    let mut bytes = data.to_vec();
    
    // Convert from base-256 to base-62
    while !bytes.is_empty() && bytes.iter().any(|&b| b != 0) {
        let mut remainder = 0u16;
        let mut new_bytes = Vec::new();
        
        for &byte in &bytes {
            let value = (remainder << 8) | byte as u16;
            new_bytes.push((value / 62) as u8);
            remainder = value % 62;
        }
        
        digits.push(remainder as usize);
        
        // Remove leading zeros
        bytes = new_bytes;
        while let Some(&0) = bytes.first() {
            bytes.remove(0);
        }
    }
    
    // If all bytes were zero, we need at least one digit
    if digits.is_empty() {
        digits.push(0);
    }
    
    // Convert digits to characters (reverse because we collected them in reverse order)
    let data_str: String = digits.iter().rev().map(|&d| AZONINE_ALPHABET[d] as char).collect();
    
    // Prepend length with fixed 2-character width (padded with 'a' which is 0)
    // This allows us to know exactly where the length ends
    let length_encoded = if length_str.len() < 2 {
        format!("{}{}", "a".repeat(2 - length_str.len()), length_str)
    } else if length_str.len() == 2 {
        length_str
    } else {
        // If length is > 62*62 = 3844 bytes, we need more characters
        // For now, truncate to 2 chars (max 3843 bytes)
        length_str[length_str.len()-2..].to_string()
    };
    
    format!("{}{}", length_encoded, data_str)
}

/// Decode Azonine (base-62) format to bytes
/// The format is: [2-char length][data], where length is encoded in base-62
fn decode_azonine(encoded: &str) -> Result<Vec<u8>, String> {
    if encoded.is_empty() {
        return Ok(Vec::new());
    }

    if encoded.len() < 2 {
        return Err("Azonine encoded string too short (must include length prefix)".to_string());
    }

    // Build reverse lookup table
    let mut char_to_value = [None; 256];
    for (i, &ch) in AZONINE_ALPHABET.iter().enumerate() {
        char_to_value[ch as usize] = Some(i as u8);
    }

    // First 2 characters encode the length (fixed width, padded with 'a' = 0)
    let length_str = &encoded[..2.min(encoded.len())];
    let mut expected_len = 0usize;
    for ch in length_str.chars() {
        let ch_byte = ch as u8;
        let digit = char_to_value[ch_byte as usize]
            .ok_or_else(|| format!("Invalid Azonine character in length: {}", ch))?;
        expected_len = expected_len * 62 + digit as usize;
    }

    // Decode the data part (everything after the 2-char length prefix)
    let data_str = &encoded[2..];
    let mut bytes = Vec::new();
    
    for ch in data_str.chars() {
        let ch_byte = ch as u8;
        let digit = char_to_value[ch_byte as usize]
            .ok_or_else(|| format!("Invalid Azonine character: {}", ch))?;
        
        // Multiply current bytes by 62 and add new digit
        let mut carry = digit as u16;
        for byte in &mut bytes {
            let value = (*byte as u16) * 62 + carry;
            *byte = (value & 0xFF) as u8;
            carry = value >> 8;
        }
        
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    
    // Reverse to get big-endian representation
    bytes.reverse();
    
    // Pad or truncate to expected length
    if bytes.len() < expected_len {
        // Pad with leading zeros
        let mut padded = vec![0u8; expected_len - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    } else if bytes.len() > expected_len {
        // Remove excess leading zeros
        while bytes.len() > expected_len && bytes[0] == 0 {
            bytes.remove(0);
        }
        // If still too long, truncate
        if bytes.len() > expected_len {
            bytes.truncate(expected_len);
        }
    }
    
    // Ensure we have at least the expected length
    while bytes.len() < expected_len {
        bytes.insert(0, 0);
    }
    
    Ok(bytes)
}

impl OutputFormat {
    /// Encode bytes to the specified format
    pub fn encode(&self, data: &[u8]) -> String {
        match self {
            OutputFormat::RawBytes => {
                // For raw bytes, return as hex representation since String can't hold raw bytes
                // Users can use the raw bytes methods directly
                hex::encode(data)
            }
            OutputFormat::Base64 => STANDARD.encode(data),
            OutputFormat::HexLowercase => hex::encode(data),
            OutputFormat::HexUppercase => hex::encode_upper(data),
            OutputFormat::Base32 => base32::encode(Alphabet::RFC4648 { padding: true }, data),
            OutputFormat::Azonine => encode_azonine(data),
        }
    }

    /// Decode from the specified format
    pub fn decode(&self, encoded: &str) -> Result<Vec<u8>, String> {
        match self {
            OutputFormat::RawBytes => {
                // For raw bytes, try to decode as hex
                hex::decode(encoded).map_err(|e| format!("Failed to decode hex: {}", e))
            }
            OutputFormat::Base64 => {
                STANDARD.decode(encoded).map_err(|e| format!("Failed to decode base64: {}", e))
            }
            OutputFormat::HexLowercase | OutputFormat::HexUppercase => {
                hex::decode(encoded).map_err(|e| format!("Failed to decode hex: {}", e))
            }
            OutputFormat::Base32 => {
                base32::decode(Alphabet::RFC4648 { padding: true }, encoded)
                    .ok_or_else(|| "Failed to decode base32".to_string())
            }
            OutputFormat::Azonine => decode_azonine(encoded),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azonine_roundtrip() {
        let test_cases = vec![
            vec![],
            vec![0],
            vec![0, 1, 2, 3],
            vec![0xFF, 0xAA, 0x55, 0x00],
            vec![0x42; 64],
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            (0u8..=255u8).collect::<Vec<u8>>(),
        ];

        for data in test_cases {
            let encoded = OutputFormat::Azonine.encode(&data);
            let decoded = OutputFormat::Azonine.decode(&encoded).unwrap();
            assert_eq!(decoded, data, "Azonine roundtrip failed for data: {:?}", data);
        }
    }

    #[test]
    fn test_azonine_character_set() {
        let data = vec![0x00, 0x01, 0xFF, 0x42, 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let encoded = OutputFormat::Azonine.encode(&data);
        
        // Verify all characters are in azAZ09 range
        for ch in encoded.chars() {
            assert!(
                (ch >= 'a' && ch <= 'z') || 
                (ch >= 'A' && ch <= 'Z') || 
                (ch >= '0' && ch <= '9'),
                "Invalid Azonine character: {}",
                ch
            );
        }
    }

    #[test]
    fn test_azonine_empty() {
        let empty = vec![];
        let encoded = OutputFormat::Azonine.encode(&empty);
        assert_eq!(encoded, "");
        let decoded = OutputFormat::Azonine.decode(&encoded).unwrap();
        assert_eq!(decoded, empty);
    }
}

