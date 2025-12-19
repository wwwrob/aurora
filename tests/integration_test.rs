use aurora::{AuroraSeal512, AuroraSeal1024, Aurora512, Aurora1024, OutputFormat, BLOCK_BYTES_512, BLOCK_BYTES_1024};
use std::time::Instant;
use hex;

/// Generate a random hex key
fn generate_key() -> [u8; 64] {
    use aurora::internal::XorShift64Star;
    let mut prng = XorShift64Star::new(0xDEADBEEFCAFEBABE);
    let mut key = [0u8; 64];
    for i in 0..64 {
        key[i] = prng.next_u8();
    }
    key
}

/// Generate a random nonce
fn generate_nonce(size: usize) -> Vec<u8> {
    use aurora::internal::XorShift64Star;
    let mut prng = XorShift64Star::new(0x1234567890ABCDEF);
    let mut nonce = vec![0u8; size];
    for i in 0..size {
        nonce[i] = prng.next_u8();
    }
    nonce
}

/// Test encryption/decryption for a given payload with all modes and variants (parallelized)
fn test_payload_all_modes(payload_name: &str, payload: &[u8]) {
    use rayon::prelude::*;
    
    println!("\n=== Testing: {} ({} bytes) ===", payload_name, payload.len());
    
    let key_512 = generate_key();
    let key_1024 = {
        let mut k = [0u8; 128];
        let k512 = generate_key();
        k[..64].copy_from_slice(&k512);
        k[64..].copy_from_slice(&generate_key());
        k
    };
    let nonce = generate_nonce(16);
    let payload = payload.to_vec(); // Clone for parallel processing
    
    // Run all 4 tests in parallel
    let results: Vec<_> = [
        ("SEAL-512", 0usize),
        ("SEAL-1024", 1usize),
        ("Block-512", 2usize),
        ("Block-1024", 3usize),
    ].par_iter().map(|(mode_name, mode_id)| {
        // Clone keys and nonce for each parallel task
        let key_512 = key_512;
        let key_1024 = key_1024;
        let nonce = nonce.clone();
        let payload = payload.clone();
        
        match mode_id {
            0 => {
                // SEAL-512
                let seal512 = AuroraSeal512::new(key_512);
                let start = Instant::now();
                let encrypted = seal512.seal(&[], &nonce, &payload);
                let encrypt_time = start.elapsed();
                let start = Instant::now();
                let decrypted = seal512.open(&[], &encrypted);
                let decrypt_time = start.elapsed();
                assert!(decrypted.is_some(), "SEAL-512 decryption failed");
                assert_eq!(decrypted.as_ref().unwrap(), &payload, "SEAL-512 roundtrip failed");
                (*mode_name, encrypt_time, decrypt_time, Some(encrypted.len()))
            },
            1 => {
                // SEAL-1024
                let seal1024 = AuroraSeal1024::new(key_1024);
                let start = Instant::now();
                let encrypted = seal1024.seal(&[], &nonce, &payload);
                let encrypt_time = start.elapsed();
                let start = Instant::now();
                let decrypted = seal1024.open(&[], &encrypted);
                let decrypt_time = start.elapsed();
                assert!(decrypted.is_some(), "SEAL-1024 decryption failed");
                assert_eq!(decrypted.as_ref().unwrap(), &payload, "SEAL-1024 roundtrip failed");
                (*mode_name, encrypt_time, decrypt_time, Some(encrypted.len()))
            },
            2 => {
                // Block-512
                let mut block_512 = [0u8; BLOCK_BYTES_512];
                let copy_len = payload.len().min(BLOCK_BYTES_512);
                block_512[..copy_len].copy_from_slice(&payload[..copy_len]);
                let cipher512 = Aurora512::new(key_512);
                let start = Instant::now();
                let encrypted_block = cipher512.encrypt_block_bytes(&block_512);
                let encrypt_time = start.elapsed();
                let start = Instant::now();
                let decrypted_block = cipher512.decrypt_block_bytes(&encrypted_block);
                let decrypt_time = start.elapsed();
                assert!(decrypted_block.is_ok(), "Block-512 decryption failed");
                assert_eq!(decrypted_block.as_ref().unwrap(), &block_512, "Block-512 roundtrip failed");
                (*mode_name, encrypt_time, decrypt_time, None)
            },
            3 => {
                // Block-1024
                let mut block_1024 = [0u8; BLOCK_BYTES_1024];
                let copy_len = payload.len().min(BLOCK_BYTES_1024);
                block_1024[..copy_len].copy_from_slice(&payload[..copy_len]);
                let cipher1024 = Aurora1024::new(key_1024);
                let start = Instant::now();
                let encrypted_block = cipher1024.encrypt_block_bytes(&block_1024);
                let encrypt_time = start.elapsed();
                let start = Instant::now();
                let decrypted_block = cipher1024.decrypt_block_bytes(&encrypted_block);
                let decrypt_time = start.elapsed();
                assert!(decrypted_block.is_ok(), "Block-1024 decryption failed");
                assert_eq!(decrypted_block.as_ref().unwrap(), &block_1024, "Block-1024 roundtrip failed");
                (*mode_name, encrypt_time, decrypt_time, None)
            },
            _ => unreachable!(),
        }
    }).collect();
    
    // Print results in order
    for (mode_name, encrypt_time, decrypt_time, encrypted_len) in results {
        println!("  [{}]", mode_name);
        if let Some(len) = encrypted_len {
            println!("    ✓ Encrypt: {:?}, Decrypt: {:?}, Encrypted: {} bytes", 
                     encrypt_time, decrypt_time, len);
        } else {
            println!("    ✓ Encrypt: {:?}, Decrypt: {:?}", encrypt_time, decrypt_time);
        }
    }
}

#[test]
fn test_string_encryption_decryption() {
    println!("\n=== Testing String Encryption/Decryption ===");
    
    let repeated_a = "A".repeat(100);
    let test_strings: Vec<(&str, &str)> = vec![
        ("Short", "Hello, World!"),
        ("Very Short", "TEST"),
        ("Medium", "The quick brown fox jumps over the lazy dog"),
        ("Long", &repeated_a),
        ("Special Chars", "Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?/~`"),
        ("Unicode", "Unicode: 🚀 🔒 💻 🌟"),
        ("Multi-line", "Multi-line\nstring\nwith\nnewlines"),
    ];
    
    for (name, plaintext) in test_strings.iter() {
        test_payload_all_modes(name, plaintext.as_bytes());
    }
    
    println!("✓ All string tests passed!\n");
}

#[test]
fn test_small_json_encryption_decryption() {
    println!("\n=== Testing Small JSON Encryption/Decryption ===");
    
    let json_examples = vec![
        ("Simple", r#"{"name": "Alice", "age": 30, "city": "New York"}"#),
        ("Array", r#"{"users": [{"id": 1, "name": "Bob"}, {"id": 2, "name": "Charlie"}]}"#),
        ("Nested", r#"{"config": {"timeout": 5000, "retries": 3, "enabled": true}}"#),
        ("Deep Nested", r#"{"nested": {"deep": {"very": {"deep": {"value": 42}}}}}"#),
    ];
    
    for (name, json_str) in json_examples.iter() {
        test_payload_all_modes(name, json_str.as_bytes());
    }
    
    println!("✓ All small JSON tests passed!\n");
}

#[test]
fn test_large_json_encryption_decryption() {
    println!("\n=== Testing Large JSON (1MB) Encryption/Decryption ===");
    
    // Generate a large JSON structure (~1MB)
    let mut large_json = String::from(r#"{"data": ["#);
    let target_size = 1_000_000; // 1MB
    
    let mut current_size = large_json.len();
    let mut item_count = 0;
    
    while current_size < target_size {
        if item_count > 0 {
            large_json.push_str(", ");
        }
        let item = format!(r#"{{"id": {}, "name": "Item{}", "value": {}, "description": "This is item number {} with some additional text to make it larger"}}"#, 
                          item_count, item_count, item_count * 10, item_count);
        large_json.push_str(&item);
        current_size = large_json.len();
        item_count += 1;
    }
    
    large_json.push_str("]}");
    
    println!("Generated JSON: {} bytes ({} items)", large_json.len(), item_count);
    
    let json_bytes = large_json.as_bytes();
    
    // Test with all modes
    test_payload_all_modes("Large JSON (1MB)", json_bytes);
    
    println!("✓ Large JSON test passed!\n");
}

#[test]
fn test_different_output_formats() {
    println!("\n=== Testing Different Output Formats ===");
    
    let key = generate_key();
    let nonce = generate_nonce(16);
    let seal = AuroraSeal512::new(key);
    let plaintext = b"Test data for format testing";
    
    let formats = vec![
        OutputFormat::Base64,
        OutputFormat::HexLowercase,
        OutputFormat::HexUppercase,
        OutputFormat::Base32,
        OutputFormat::Azonine,
    ];
    
    for format in formats {
        println!("Testing format: {:?}", format);
        
        let start = Instant::now();
        let encrypted_str = seal.seal_formatted(&[], &nonce, plaintext, format);
        let encrypt_time = start.elapsed();
        
        let start = Instant::now();
        let decrypted = seal.open_formatted(&[], &encrypted_str, format);
        let decrypt_time = start.elapsed();
        
        assert!(decrypted.is_some(), "Decryption failed for format {:?}", format);
        assert_eq!(decrypted.unwrap(), plaintext, "Roundtrip failed for format {:?}", format);
        
        println!("  ✓ Encrypt: {:?}, Decrypt: {:?}, Output length: {} chars", 
                 encrypt_time, decrypt_time, encrypted_str.len());
    }
    
    println!("✓ All format tests passed!\n");
}

#[test]
fn test_aad_functionality() {
    println!("\n=== Testing AAD (Additional Authenticated Data) ===");
    
    let key = generate_key();
    let nonce = generate_nonce(16);
    let seal = AuroraSeal512::new(key);
    let plaintext = b"Secret message";
    let aad = b"Metadata: user123, timestamp: 1234567890";
    
    // Encrypt with AAD
    let encrypted = seal.seal(aad, &nonce, plaintext);
    
    // Decrypt with correct AAD
    let decrypted = seal.open(aad, &encrypted);
    assert!(decrypted.is_some(), "Decryption with correct AAD failed");
    assert_eq!(decrypted.unwrap(), plaintext, "Roundtrip with AAD failed");
    
    // Decrypt with wrong AAD should fail
    let wrong_aad = b"Wrong metadata";
    let decrypted_wrong = seal.open(wrong_aad, &encrypted);
    assert!(decrypted_wrong.is_none(), "Decryption with wrong AAD should fail");
    
    println!("✓ AAD tests passed!\n");
}

#[test]
fn test_benchmark_different_sizes() {
    use rayon::prelude::*;
    
    println!("\n=== Benchmarking Different Data Sizes (Parallel) ===");
    
    let sizes = vec![
        (100, "100 bytes"),
        (1_000, "1 KB"),
        (10_000, "10 KB"),
        (100_000, "100 KB"),
        (1_000_000, "1 MB"),
    ];
    
    // Process all sizes in parallel
    let results: Vec<_> = sizes.par_iter().map(|(size, label)| {
        let key = generate_key();
        let nonce = generate_nonce(16);
        let seal = AuroraSeal512::new(key);
        let data = vec![0x42u8; *size];
        
        // Warm up (single iteration)
        let _ = seal.seal(&[], &nonce, &data);
        
        // Reduced iterations for faster benchmarking while maintaining accuracy
        // Smaller sizes: more iterations for accuracy, larger sizes: fewer iterations for speed
        let iterations = match *size {
            s if s < 1_000 => 50,           // 100 bytes: 50 iterations
            s if s < 10_000 => 30,          // 1 KB: 30 iterations
            s if s < 100_000 => 20,         // 10 KB: 20 iterations
            s if s < 1_000_000 => 10,       // 100 KB: 10 iterations
            _ => 3,                         // 1 MB: 3 iterations (sufficient for large data)
        };
        
        // Benchmark encryption
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = seal.seal(&[], &nonce, &data);
        }
        let encrypt_time = start.elapsed() / iterations;
        
        // Benchmark decryption
        let encrypted = seal.seal(&[], &nonce, &data);
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = seal.open(&[], &encrypted);
        }
        let decrypt_time = start.elapsed() / iterations;
        
        let mb_per_sec_encrypt = (*size as f64 / 1_000_000.0) / encrypt_time.as_secs_f64();
        let mb_per_sec_decrypt = (*size as f64 / 1_000_000.0) / decrypt_time.as_secs_f64();
        
        (*label, encrypt_time, decrypt_time, mb_per_sec_encrypt, mb_per_sec_decrypt)
    }).collect();
    
    // Print results in order
    for (label, encrypt_time, decrypt_time, mb_per_sec_encrypt, mb_per_sec_decrypt) in results {
        println!("{}: Encrypt: {:?} ({:.2} MB/s), Decrypt: {:?} ({:.2} MB/s)", 
                 label, encrypt_time, mb_per_sec_encrypt, decrypt_time, mb_per_sec_decrypt);
    }
    
    println!("✓ Benchmarking complete!\n");
}

#[test]
fn test_unicode_and_utf16_json() {
    println!("\n=== Testing Unicode and UTF-16 JSON ===");
    
    let key = generate_key();
    let nonce = generate_nonce(16);
    let seal = AuroraSeal512::new(key);
    
    // Test 1: Chinese characters
    let chinese_json = r#"{
        "name": "张三",
        "city": "北京",
        "message": "你好世界！这是一个测试。",
        "items": ["苹果", "香蕉", "橙子"],
        "description": "包含中文的JSON数据"
    }"#;
    
    println!("Test 1: Chinese characters JSON ({} bytes)...", chinese_json.len());
    let start = Instant::now();
    let encrypted = seal.seal(&[], &nonce, chinese_json.as_bytes());
    let encrypt_time = start.elapsed();
    
    let start = Instant::now();
    let decrypted = seal.open(&[], &encrypted);
    let decrypt_time = start.elapsed();
    
    assert!(decrypted.is_some(), "Decryption failed for Chinese JSON");
    let decrypted_str = String::from_utf8(decrypted.unwrap()).unwrap();
    assert_eq!(decrypted_str, chinese_json, "Roundtrip failed for Chinese JSON");
    println!("  ✓ Encrypt: {:?}, Decrypt: {:?}", encrypt_time, decrypt_time);
    
    // Test 2: Mixed Unicode characters (Chinese, Japanese, Korean, Arabic, Emoji)
    let mixed_unicode_json = format!(r#"{{
        "chinese": "中文测试",
        "japanese": "こんにちは世界",
        "korean": "안녕하세요 세계",
        "arabic": "مرحبا بالعالم",
        "russian": "Привет мир",
        "greek": "Γεια σας κόσμε",
        "emoji": "🚀 🔒 💻 🌟 🎉",
        "mixed": "Hello 世界 🌍 こんにちは 안녕",
        "numbers": [1, 2, 3, 4, 5],
        "special": "Special chars: !@#$%^&*()_+-=[]{{}}|;:,.<>?/~`"
    }}"#);
    
    test_payload_all_modes("Mixed Unicode JSON", mixed_unicode_json.as_bytes());
    
    // Test 3: UTF-16 encoded JSON (simulated by creating UTF-16 bytes)
    let utf16_text = "测试数据：包含中文和特殊字符 🎉";
    let utf16_bytes: Vec<u8> = utf16_text
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    
    // Create JSON that contains UTF-16 encoded data as base64 or hex
    let utf16_json = format!(r#"{{
        "encoding": "UTF-16",
        "data_hex": "{}",
        "original": "{}",
        "size_bytes": {},
        "description": "JSON containing UTF-16 encoded data"
    }}"#, 
        hex::encode(&utf16_bytes),
        utf16_text,
        utf16_bytes.len()
    );
    
    test_payload_all_modes("UTF-16 JSON", utf16_json.as_bytes());
    
    // Test 4: Large Unicode JSON with various scripts
    let mut large_unicode_json = String::from(r#"{"unicode_data": ["#);
    let unicode_samples = vec![
        ("Chinese", "这是中文测试数据"),
        ("Japanese", "これは日本語のテストデータです"),
        ("Korean", "이것은 한국어 테스트 데이터입니다"),
        ("Arabic", "هذه بيانات اختبار عربية"),
        ("Hebrew", "זהו נתון בדיקה בעברית"),
        ("Thai", "นี่คือข้อมูลทดสอบภาษาไทย"),
        ("Devanagari", "यह हिंदी परीक्षण डेटा है"),
        ("Cyrillic", "Это тестовые данные на кириллице"),
        ("Greek", "Αυτά είναι δεδομένα δοκιμής στα ελληνικά"),
        ("Emoji", "🚀🔒💻🌟🎉🎊🎈🎁🎀🎂"),
    ];
    
    for (i, (script, text)) in unicode_samples.iter().enumerate() {
        if i > 0 {
            large_unicode_json.push_str(", ");
        }
        large_unicode_json.push_str(&format!(
            r#"{{"script": "{}", "text": "{}", "length": {}}}"#,
            script, text, text.len()
        ));
    }
    
    // Add more entries to make it larger
    for i in 0..100 {
        large_unicode_json.push_str(&format!(
            r#", {{"id": {}, "chinese": "项目{}", "japanese": "項目{}", "korean": "항목{}"}}"#,
            i, i, i, i
        ));
    }
    
    large_unicode_json.push_str("]}");
    
    test_payload_all_modes("Large Unicode JSON", large_unicode_json.as_bytes());
    
    // Test 5: Edge cases with Unicode
    let zero_width = format!(r#"{{"name": "Zero-width characters", "text": "test{}test"}}"#, 
                             "\u{200B}\u{200C}\u{200D}");
    let emoji = r#"{"name": "Emoji", "text": "test😀test"}"#;
    let combining = format!(r#"{{"name": "Combining characters", "text": "c{}"}}"#, "\u{0327}");
    let bidirectional = format!(r#"{{"name": "Bidirectional text", "text": "Hello {}world{}"}}"#, 
                                "\u{202E}", "\u{202C}");
    let variation = format!(r#"{{"name": "Variation selectors", "text": "漢{}"}}"#, "\u{FE00}");
    
    let edge_cases = vec![
        ("Zero-width", zero_width),
        ("Emoji", emoji.to_string()),
        ("Combining", combining),
        ("Bidirectional", bidirectional),
        ("Variation", variation),
    ];
    
    for (name, json) in edge_cases {
        test_payload_all_modes(name, json.as_bytes());
    }
    
    println!("✓ All Unicode and UTF-16 tests passed!\n");
}

#[test]
fn test_tamper_detection() {
    println!("\n=== Testing Tamper Detection ===");
    
    let key = generate_key();
    let nonce = generate_nonce(16);
    let seal = AuroraSeal512::new(key);
    let plaintext = b"Important data";
    
    let encrypted = seal.seal(&[], &nonce, plaintext);
    
    // Tamper with ciphertext
    // Packet structure: [version][nonce_len][nonce...][tag...][ciphertext...]
    // For "Important data" (14 bytes): packet is ~96 bytes
    // Let's tamper with a byte in the ciphertext area (after tag)
    let mut tampered = encrypted.clone();
    let tag_start = 2 + nonce.len() + BLOCK_BYTES_512; // version + nonce_len + nonce + tag
    if tampered.len() > tag_start + 10 {
        // Tamper with a byte in the ciphertext area
        tampered[tag_start + 10] ^= 1; // Flip a bit in ciphertext
    } else {
        // If packet is too small, tamper with the last byte
        let last_idx = tampered.len() - 1;
        if last_idx >= tag_start {
            tampered[last_idx] ^= 1;
        } else {
            // Fallback: tamper with tag
            tampered[2 + nonce.len()] ^= 1;
        }
    }
    
    let result = seal.open(&[], &tampered);
    assert!(result.is_none(), "Tampered ciphertext should be rejected");
    
    // Tamper with tag (if we can identify it)
    // The tag is embedded in the packet, so tampering anywhere should be detected
    
    println!("✓ Tamper detection tests passed!\n");
}

#[test]
fn test_azonine_format() {
    println!("\n=== Testing Azonine Format (base-62: azAZ09) ===");
    
    let key_512 = generate_key();
    let key_1024 = {
        let mut k = [0u8; 128];
        let k512 = generate_key();
        k[..64].copy_from_slice(&k512);
        k[64..].copy_from_slice(&generate_key());
        k
    };
    let nonce = generate_nonce(16);
    let plaintext = b"Test data for Azonine format testing!";
    
    // Test 1: SEAL-512 with Azonine
    println!("  [SEAL-512 with Azonine]");
    let seal512 = AuroraSeal512::new(key_512);
    let encrypted_azonine = seal512.seal_as_azonine(&[], &nonce, plaintext);
    println!("    Encrypted (Azonine): {}", encrypted_azonine);
    
    let decrypted = seal512.open_from_azonine(&[], &encrypted_azonine);
    assert!(decrypted.is_some(), "SEAL-512 Azonine decryption failed");
    assert_eq!(decrypted.unwrap(), plaintext, "SEAL-512 Azonine roundtrip failed");
    println!("    ✓ SEAL-512 Azonine roundtrip successful");
    
    // Test 2: SEAL-1024 with Azonine
    println!("  [SEAL-1024 with Azonine]");
    let seal1024 = AuroraSeal1024::new(key_1024);
    let encrypted_azonine = seal1024.seal_as_azonine(&[], &nonce, plaintext);
    println!("    Encrypted (Azonine): {}", encrypted_azonine);
    
    let decrypted = seal1024.open_from_azonine(&[], &encrypted_azonine);
    assert!(decrypted.is_some(), "SEAL-1024 Azonine decryption failed");
    assert_eq!(decrypted.unwrap(), plaintext, "SEAL-1024 Azonine roundtrip failed");
    println!("    ✓ SEAL-1024 Azonine roundtrip successful");
    
    // Test 3: Block-512 with Azonine
    println!("  [Block-512 with Azonine]");
    let mut block_512 = [0u8; BLOCK_BYTES_512];
    let copy_len = plaintext.len().min(BLOCK_BYTES_512);
    block_512[..copy_len].copy_from_slice(&plaintext[..copy_len]);
    let cipher512 = Aurora512::new(key_512);
    let encrypted_azonine = cipher512.encrypt_block_as_azonine(&block_512);
    println!("    Encrypted (Azonine): {}", encrypted_azonine);
    
    let decrypted = cipher512.decrypt_block_from_azonine(&encrypted_azonine);
    assert!(decrypted.is_ok(), "Block-512 Azonine decryption failed");
    assert_eq!(decrypted.unwrap(), block_512, "Block-512 Azonine roundtrip failed");
    println!("    ✓ Block-512 Azonine roundtrip successful");
    
    // Test 4: Block-1024 with Azonine
    println!("  [Block-1024 with Azonine]");
    let mut block_1024 = [0u8; BLOCK_BYTES_1024];
    let copy_len = plaintext.len().min(BLOCK_BYTES_1024);
    block_1024[..copy_len].copy_from_slice(&plaintext[..copy_len]);
    let cipher1024 = Aurora1024::new(key_1024);
    let encrypted_azonine = cipher1024.encrypt_block_as_azonine(&block_1024);
    println!("    Encrypted (Azonine): {}", encrypted_azonine);
    
    let decrypted = cipher1024.decrypt_block_from_azonine(&encrypted_azonine);
    assert!(decrypted.is_ok(), "Block-1024 Azonine decryption failed");
    assert_eq!(decrypted.unwrap(), block_1024, "Block-1024 Azonine roundtrip failed");
    println!("    ✓ Block-1024 Azonine roundtrip successful");
    
    // Test 5: Verify Azonine format uses correct character set (azAZ09)
    println!("  [Azonine Character Set Verification]");
    let test_bytes = vec![0x00, 0x01, 0xFF, 0x42, 0xAA, 0x55];
    let encoded = OutputFormat::Azonine.encode(&test_bytes);
    println!("    Test bytes: {:?}", test_bytes);
    println!("    Encoded: {}", encoded);
    
    // Verify all characters are in azAZ09 range
    for ch in encoded.chars() {
        let is_valid = (ch >= 'a' && ch <= 'z') || 
                       (ch >= 'A' && ch <= 'Z') || 
                       (ch >= '0' && ch <= '9');
        assert!(is_valid, "Invalid Azonine character: {}", ch);
    }
    
    // Verify roundtrip
    let decoded = OutputFormat::Azonine.decode(&encoded);
    assert!(decoded.is_ok(), "Azonine decode failed");
    assert_eq!(decoded.unwrap(), test_bytes, "Azonine roundtrip failed");
    println!("    ✓ Azonine character set and roundtrip verified");
    
    // Test 6: Test with various data sizes
    println!("  [Azonine with Various Data Sizes]");
    let sizes = vec![0, 1, 16, 64, 128, 256, 1024];
    for size in sizes {
        let data = vec![0x42u8; size];
        let encoded = OutputFormat::Azonine.encode(&data);
        let decoded = OutputFormat::Azonine.decode(&encoded);
        assert!(decoded.is_ok(), "Azonine decode failed for size {}", size);
        assert_eq!(decoded.unwrap(), data, "Azonine roundtrip failed for size {}", size);
    }
    println!("    ✓ Azonine works with various data sizes");
    
    println!("✓ All Azonine format tests passed!\n");
}

