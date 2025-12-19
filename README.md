# Aurora

**Aurora** is a modern block cipher family featuring large block sizes and unique diffusion operations, designed for applications requiring high-security encryption with enhanced resistance to certain cryptanalytic techniques.

## Overview

Aurora provides two block cipher variants optimized for different security and performance requirements:

- **Aurora-512**: 512-bit blocks, 512-bit keys, 24 rounds
- **Aurora-1024**: 1024-bit blocks, 1024-bit keys, 32 rounds

Both variants feature a proprietary **AuroraMix** transformation that provides enhanced diffusion properties beyond traditional block cipher designs.

## Key Features

### Large Block Sizes
- **512-bit blocks** (Aurora-512) or **1024-bit blocks** (Aurora-1024) vs. AES's 128-bit blocks
- Reduces the impact of block collisions and provides better security margins
- Ideal for encrypting larger data structures without mode-of-operation overhead

### Unique Diffusion Architecture
- **AuroraMix**: Proprietary diffusion step combining Feistel-like operations with byte rotations
- **8×8 state layout** (Aurora-512) or **8×16 state layout** (Aurora-1024) for optimal diffusion
- Custom column mixing using GF(2⁸) arithmetic with MDS-like properties

### Secure-by-Default API
- **Aurora-SEAL**: Authenticated encryption (AEAD) wrappers built on top of the block ciphers
- Automatic key derivation separating MAC and encryption keys
- Built-in protection against tampering and chosen-ciphertext attacks
- Support for Associated Authenticated Data (AAD)

### Performance Optimized
- Unrolled inner loops for maximum performance
- Efficient GF(2⁸) multiplication using lookup tables
- Optimized state transformations minimizing memory allocations

## How Aurora Differs from AES

| Feature | AES | Aurora-512 | Aurora-1024 |
|---------|-----|------------|-------------|
| **Block Size** | 128 bits | 512 bits | 1024 bits |
| **Key Size** | 128/192/256 bits | 512 bits | 1024 bits |
| **Rounds** | 10/12/14 | 24 | 32 |
| **State Layout** | 4×4 bytes | 8×8 bytes | 8×16 bytes |
| **Diffusion** | MixColumns + ShiftRows | MixColumns + ShiftRows + **AuroraMix** | MixColumns + ShiftRows + **AuroraMix** |
| **S-box** | Fixed (Rijndael) | Generated (Fisher-Yates) | Generated (Fisher-Yates) |

### Architectural Differences

1. **Larger Block Sizes**: Aurora's 512/1024-bit blocks provide:
   - Better security margins against birthday attacks
   - Reduced need for complex mode-of-operation schemes
   - More efficient encryption of large data structures

2. **AuroraMix Transformation**: 
   - Unique Feistel-like diffusion step not found in AES
   - Combines byte rotations with XOR operations
   - Provides additional diffusion layer beyond standard SPN operations

3. **Custom S-box Generation**:
   - Dynamically generated using cryptographically secure PRNG
   - Maintains bijective properties while providing unique substitution layer

4. **Enhanced Key Schedule**:
   - Round keys derived through S-box application and rotation
   - PRNG-based masking for additional key material mixing

## Applications

### When to Use Aurora

- **High-Security Applications**: Systems requiring encryption beyond standard 128-bit block sizes
- **Large Data Structures**: Encrypting database records, files, or structured data that fit naturally in 512/1024-bit blocks
- **Research & Development**: Cryptographic research, custom protocols, and academic applications
- **Production Systems**: Enterprise applications requiring large-block encryption
- **Post-Quantum Preparation**: Larger block sizes provide better resistance to certain quantum cryptanalytic techniques
- **Custom Security Protocols**: Building domain-specific encryption schemes requiring unique properties

### Use Cases

- **Database Encryption**: Encrypting database rows or records as single blocks
- **File System Encryption**: Block-level encryption for file systems
- **Secure Messaging**: Custom messaging protocols requiring large block sizes
- **Blockchain & Cryptocurrency**: Custom cryptographic primitives for blockchain applications
- **IoT Security**: Embedded systems requiring efficient large-block encryption

## Installation

### Requirements

- Rust 1.70+ (or latest stable)
- Cargo package manager

### Building from Source

```bash
git clone https://github.com/wwwrob/aurora.git
cd aurora
cargo build --release
```

### Using as a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
aurora = { path = "." }
```

## Usage

### Block Cipher API

```rust
use aurora::{Aurora512, BLOCK_BYTES_512, KEY_BYTES_512};

// Create cipher instance
let key = [0u8; KEY_BYTES_512]; // Use a secure random key in production!
let cipher = Aurora512::new(key);

// Encrypt a 64-byte block
let mut block = [0u8; BLOCK_BYTES_512];
cipher.encrypt_block(&mut block);

// Decrypt
cipher.decrypt_block(&mut block);
```

### Authenticated Encryption (Aurora-SEAL)

```rust
use aurora::{AuroraSeal512, KEY_BYTES_512};

// Create SEAL instance
let key = [0u8; KEY_BYTES_512]; // Use a secure random key in production!
let seal = AuroraSeal512::new(key);

// Encrypt with AAD and nonce
let plaintext = b"Hello, world!";
let aad = b"metadata";
let nonce = b"unique-nonce-1234";
let packet = seal.seal(aad, nonce, plaintext);

// Decrypt and verify
let decrypted = seal.open(aad, &packet);
assert_eq!(decrypted, Some(plaintext.to_vec()));
```

### Command-Line Interface

```bash
# Encrypt a file using Aurora-512
aurora encrypt --variant 512 --key <hex-key> --input file.txt --output file.enc --seal --nonce <hex-nonce>

# Decrypt a file
aurora decrypt --variant 512 --key <hex-key> --input file.enc --output file.txt --seal --aad <hex-aad>

# Encrypt a single block (64 bytes for 512, 128 bytes for 1024)
echo -n "0123456789abcdef..." | aurora encrypt --variant 512 --key <hex-key> --format hex
```

## Security Considerations

### Key Management

Always use cryptographically secure random keys. Never use predictable or weak keys. Keys should be generated using a cryptographically secure random number generator and stored securely.

### Nonce Requirements

When using Aurora-SEAL, ensure nonces are unique for each encryption operation. Reusing nonces compromises security. Nonces do not need to be secret but must be unique per encryption with the same key.

### AAD Integrity

The AAD (Associated Authenticated Data) must match between encryption and decryption. Any modification will cause authentication to fail, providing protection against tampering.

### Block Size Requirements

The block cipher API requires exact block sizes (64 bytes for Aurora-512, 128 bytes for Aurora-1024). Use Aurora-SEAL for arbitrary-length data encryption.

### Recommended Practices

- Use Aurora-SEAL for authenticated encryption (secure-by-default)
- Generate keys using cryptographically secure random number generators
- Use unique nonces for each encryption operation
- Verify authentication tags before using decrypted data
- Keep keys secure and never commit them to version control

## Performance

Aurora is optimized for performance with:

- Unrolled inner loops for column mixing
- Lookup-table-based GF(2⁸) multiplication
- Minimal memory allocations
- Efficient state transformations

### Block Cipher Performance

Benchmark results (measured on modern x86_64 CPU):

| Variant | Operation | Time per Block | Throughput |
|---------|-----------|----------------|------------|
| **Aurora-512** | Encrypt | ~160-250 µs | ~2.5-4 MB/s |
| **Aurora-512** | Decrypt | ~1.0-1.4 ms | ~0.7-1 MB/s |
| **Aurora-1024** | Encrypt | ~440-710 µs | ~1.4-2.3 MB/s |
| **Aurora-1024** | Decrypt | ~2.6-4.2 ms | ~0.24-0.38 MB/s |

*Note: Block cipher operations are optimized for single-block encryption. For arbitrary-length data, use Aurora-SEAL.*

### Aurora-SEAL Performance

Authenticated encryption performance for various data sizes:

| Data Size | Variant | Encrypt | Decrypt | Throughput |
|-----------|---------|---------|---------|------------|
| 100 bytes | SEAL-512 | ~830 µs | ~780 µs | ~0.12-0.13 MB/s |
| 1 KB | SEAL-512 | ~5.3 ms | ~5.6 ms | ~0.18-0.19 MB/s |
| 10 KB | SEAL-512 | ~50 ms | ~49 ms | ~0.20 MB/s |
| 100 KB | SEAL-512 | ~489 ms | ~485 ms | ~0.20-0.21 MB/s |
| 1 MB | SEAL-512 | ~4.8 s | ~4.7 s | ~0.21 MB/s |
| 1 MB | SEAL-1024 | ~6.8 s | ~6.8 s | ~0.15 MB/s |

### Small Data Performance

For typical small messages (10-100 bytes):

| Variant | Encrypt | Decrypt | Typical Use Case |
|---------|---------|---------|-----------------|
| **SEAL-512** | ~460-800 µs | ~450-800 µs | General-purpose encryption |
| **SEAL-1024** | ~1.3-1.4 ms | ~1.3-1.4 ms | Higher security requirements |

### Performance Characteristics

- **Block Ciphers**: Optimized for single-block operations with minimal overhead
- **Aurora-SEAL**: Includes authentication overhead (~64 bytes tag + nonce)
- **Throughput**: Scales linearly with data size for SEAL operations
- **Memory**: Minimal allocations, efficient in-place operations for block ciphers

*Benchmarks measured on release builds with optimizations enabled. Actual performance may vary based on CPU architecture and workload.*

## Architecture

### Round Structure

Each round of Aurora consists of:

1. **SubBytes**: Apply S-box substitution to each byte
2. **ShiftRows**: Rotate each row by a round-dependent offset
3. **MixColumns**: Multiply each column by an 8×8 GF(2⁸) matrix
4. **AuroraMix**: Apply proprietary Feistel-like diffusion step
5. **AddRoundKey**: XOR with round key

### AuroraMix Details

AuroraMix provides additional diffusion by:

- Splitting the state into left and right halves
- Performing multiple passes of rotation and XOR operations
- Swapping halves to ensure full state diffusion
- Using round-dependent rotation amounts

This unique step distinguishes Aurora from other block cipher designs and provides enhanced security properties.

## Contributing

Contributions are welcome! Areas of particular interest:

- Cryptanalysis and security review
- Performance optimizations
- Additional mode-of-operation implementations
- Documentation improvements
- Test vector generation

Please read our contributing guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

- [AES Specification](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
- [Block Cipher Design Principles](https://en.wikipedia.org/wiki/Block_cipher)
- [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)

## Acknowledgments

Aurora draws inspiration from modern block cipher design principles with a unique approach to diffusion and state management.


