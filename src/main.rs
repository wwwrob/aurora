use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::io::{self, Read, Write};
use aurora::{
    Aurora512, Aurora1024, AuroraSeal512, AuroraSeal1024,
    OutputFormat, BLOCK_BYTES_512, BLOCK_BYTES_1024,
    KEY_BYTES_512, KEY_BYTES_1024,
};

#[derive(Parser)]
#[command(name = "aurora")]
#[command(about = "AURORA block cipher CLI tool", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt data using block cipher
    Encrypt {
        /// Cipher variant: 512 or 1024
        #[arg(short, long, default_value = "512")]
        variant: CipherVariant,
        
        /// Key in hex format (required length: 64 bytes for 512, 128 bytes for 1024)
        #[arg(short, long)]
        key: String,
        
        /// Input file (default: stdin)
        #[arg(short, long)]
        input: Option<String>,
        
        /// Direct string data to encrypt (alternative to --input)
        #[arg(short = 'd', long)]
        data: Option<String>,
        
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
        
        /// Output format
        #[arg(short, long, default_value = "base64")]
        format: OutputFormatEnum,
        
        /// Use SEAL (authenticated encryption) mode
        #[arg(short, long)]
        seal: bool,
        
        /// Nonce for SEAL mode (hex format)
        #[arg(short, long)]
        nonce: Option<String>,
        
        /// Additional authenticated data (AAD) for SEAL mode (hex format)
        #[arg(short, long)]
        aad: Option<String>,
    },
    
    /// Decrypt data using block cipher
    Decrypt {
        /// Cipher variant: 512 or 1024
        #[arg(short, long, default_value = "512")]
        variant: CipherVariant,
        
        /// Key in hex format (required length: 64 bytes for 512, 128 bytes for 1024)
        #[arg(short, long)]
        key: String,
        
        /// Input file (default: stdin)
        #[arg(short, long)]
        input: Option<String>,
        
        /// Direct string data to decrypt (alternative to --input)
        #[arg(short = 'd', long)]
        data: Option<String>,
        
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
        
        /// Input format
        #[arg(short, long, default_value = "base64")]
        format: OutputFormatEnum,
        
        /// Use SEAL (authenticated encryption) mode
        #[arg(short, long)]
        seal: bool,
        
        /// Additional authenticated data (AAD) for SEAL mode (hex format)
        #[arg(short, long)]
        aad: Option<String>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CipherVariant {
    #[value(name = "512")]
    V512,
    #[value(name = "1024")]
    V1024,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormatEnum {
    Raw,
    Base64,
    HexLowercase,
    HexUppercase,
    Base32,
}

impl From<OutputFormatEnum> for OutputFormat {
    fn from(val: OutputFormatEnum) -> Self {
        match val {
            OutputFormatEnum::Raw => OutputFormat::RawBytes,
            OutputFormatEnum::Base64 => OutputFormat::Base64,
            OutputFormatEnum::HexLowercase => OutputFormat::HexLowercase,
            OutputFormatEnum::HexUppercase => OutputFormat::HexUppercase,
            OutputFormatEnum::Base32 => OutputFormat::Base32,
        }
    }
}

fn read_input(input: Option<&String>, data: Option<&String>) -> Result<Vec<u8>, String> {
    // If --data is provided, use it directly
    if let Some(d) = data {
        return Ok(d.as_bytes().to_vec());
    }
    
    // Otherwise, read from file or stdin
    match input {
        Some(path) => {
            // Check if file exists and is actually a file (not a directory)
            match fs::metadata(path) {
                Ok(metadata) => {
                    if metadata.is_file() {
                        fs::read(path).map_err(|e| format!("Failed to read input file: {}", e))
                    } else {
                        // Path exists but is not a file, treat as data string
                        Ok(path.as_bytes().to_vec())
                    }
                }
                Err(_) => {
                    // File doesn't exist, treat as data string
                    Ok(path.as_bytes().to_vec())
                }
            }
        }
        None => {
            let mut buffer = Vec::new();
            io::stdin()
                .read_to_end(&mut buffer)
                .map_err(|e| format!("Failed to read from stdin: {}", e))?;
            Ok(buffer)
        }
    }
}

fn write_output(output: Option<&String>, data: &[u8]) -> Result<(), String> {
    match output {
        Some(path) => fs::write(path, data).map_err(|e| format!("Failed to write output file: {}", e)),
        None => {
            io::stdout()
                .write_all(data)
                .map_err(|e| format!("Failed to write to stdout: {}", e))?;
            Ok(())
        }
    }
}

fn parse_hex_key(hex_str: &str, expected_len: usize) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| format!("Invalid hex key: {}", e))?;
    if bytes.len() != expected_len {
        return Err(format!(
            "Key must be exactly {} bytes ({} hex chars), got {} bytes",
            expected_len,
            expected_len * 2,
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn encrypt_block_cipher(
    variant: CipherVariant,
    key: &[u8],
    input: &[u8],
    format: OutputFormat,
) -> Result<String, String> {
    match variant {
        CipherVariant::V512 => {
            if input.len() != BLOCK_BYTES_512 {
                return Err(format!(
                    "Input must be exactly {} bytes for Aurora512",
                    BLOCK_BYTES_512
                ));
            }
            let key_array: [u8; KEY_BYTES_512] = key.try_into()
                .map_err(|_| "Invalid key length".to_string())?;
            let block: [u8; BLOCK_BYTES_512] = input.try_into()
                .map_err(|_| "Invalid input length".to_string())?;
            let cipher = Aurora512::new(key_array);
            Ok(cipher.encrypt_block_formatted(&block, format))
        }
        CipherVariant::V1024 => {
            if input.len() != BLOCK_BYTES_1024 {
                return Err(format!(
                    "Input must be exactly {} bytes for Aurora1024",
                    BLOCK_BYTES_1024
                ));
            }
            let key_array: [u8; KEY_BYTES_1024] = key.try_into()
                .map_err(|_| "Invalid key length".to_string())?;
            let block: [u8; BLOCK_BYTES_1024] = input.try_into()
                .map_err(|_| "Invalid input length".to_string())?;
            let cipher = Aurora1024::new(key_array);
            Ok(cipher.encrypt_block_formatted(&block, format))
        }
    }
}

fn decrypt_block_cipher(
    variant: CipherVariant,
    key: &[u8],
    encoded: &str,
    format: OutputFormat,
) -> Result<Vec<u8>, String> {
    match variant {
        CipherVariant::V512 => {
            let key_array: [u8; KEY_BYTES_512] = key.try_into()
                .map_err(|_| "Invalid key length".to_string())?;
            let cipher = Aurora512::new(key_array);
            cipher.decrypt_block_formatted(encoded, format)
        }
        CipherVariant::V1024 => {
            let key_array: [u8; KEY_BYTES_1024] = key.try_into()
                .map_err(|_| "Invalid key length".to_string())?;
            let cipher = Aurora1024::new(key_array);
            cipher.decrypt_block_formatted(encoded, format)
        }
    }
}

fn encrypt_seal(
    variant: CipherVariant,
    key: &[u8],
    input: &[u8],
    nonce: &[u8],
    aad: &[u8],
    format: OutputFormat,
) -> Result<String, String> {
    match variant {
        CipherVariant::V512 => {
            let key_array: [u8; KEY_BYTES_512] = key.try_into()
                .map_err(|_| "Invalid key length".to_string())?;
            let seal = AuroraSeal512::new(key_array);
            let packet = seal.seal(aad, nonce, input);
            Ok(format.encode(&packet))
        }
        CipherVariant::V1024 => {
            let key_array: [u8; KEY_BYTES_1024] = key.try_into()
                .map_err(|_| "Invalid key length".to_string())?;
            let seal = AuroraSeal1024::new(key_array);
            let packet = seal.seal(aad, nonce, input);
            Ok(format.encode(&packet))
        }
    }
}

fn decrypt_seal(
    variant: CipherVariant,
    key: &[u8],
    encoded: &str,
    aad: &[u8],
    format: OutputFormat,
) -> Result<Vec<u8>, String> {
    match variant {
        CipherVariant::V512 => {
            let key_array: [u8; KEY_BYTES_512] = key.try_into()
                .map_err(|_| "Invalid key length".to_string())?;
            let seal = AuroraSeal512::new(key_array);
            seal.open_formatted(aad, encoded, format)
                .ok_or_else(|| "Authentication failed or decryption error".to_string())
        }
        CipherVariant::V1024 => {
            let key_array: [u8; KEY_BYTES_1024] = key.try_into()
                .map_err(|_| "Invalid key length".to_string())?;
            let seal = AuroraSeal1024::new(key_array);
            seal.open_formatted(aad, encoded, format)
                .ok_or_else(|| "Authentication failed or decryption error".to_string())
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt {
            variant,
            key,
            input,
            data,
            output,
            format,
            seal,
            nonce,
            aad,
        } => {
            // Parse key
            let expected_key_len = match variant {
                CipherVariant::V512 => KEY_BYTES_512,
                CipherVariant::V1024 => KEY_BYTES_1024,
            };
            let key_bytes = match parse_hex_key(&key, expected_key_len) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            // Read input
            let input_data = match read_input(input.as_ref(), data.as_ref()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            
            // Check block size for non-SEAL mode
            if !seal {
                let expected_block_size = match variant {
                    CipherVariant::V512 => BLOCK_BYTES_512,
                    CipherVariant::V1024 => BLOCK_BYTES_1024,
                };
                if input_data.len() != expected_block_size {
                    eprintln!("Error: Block cipher mode requires exactly {} bytes of input (got {} bytes)", expected_block_size, input_data.len());
                    eprintln!("Hint: Use --seal flag for arbitrary-length data encryption");
                    std::process::exit(1);
                }
            }

            let output_format: OutputFormat = format.into();
            let result = if seal {
                // SEAL mode
                let nonce_bytes = match nonce {
                    Some(n) => {
                        let trimmed = n.trim();
                        if trimmed.is_empty() {
                            eprintln!("Error: Nonce cannot be empty");
                            std::process::exit(1);
                        }
                        if trimmed.len() % 2 != 0 {
                            eprintln!("Error: Nonce must have an even number of hex digits (each byte = 2 hex chars)");
                            eprintln!("Example: --nonce 0123456789abcdef (16 hex chars = 8 bytes)");
                            std::process::exit(1);
                        }
                        hex::decode(trimmed)
                            .map_err(|e| format!("Invalid hex nonce: {}. Nonce must be hexadecimal (0-9, a-f)", e))
                            .unwrap_or_else(|e| {
                                eprintln!("Error: {}", e);
                                std::process::exit(1);
                            })
                    },
                    None => {
                        eprintln!("Error: --nonce is required for SEAL mode");
                        eprintln!("Example: --nonce 0123456789abcdef0123456789abcdef");
                        std::process::exit(1);
                    }
                };
                if nonce_bytes.is_empty() {
                    eprintln!("Error: Nonce cannot be empty");
                    std::process::exit(1);
                }
                let aad_bytes = match aad {
                    Some(a) => {
                        let trimmed = a.trim();
                        if trimmed.is_empty() {
                            Vec::new()
                        } else if trimmed.len() % 2 != 0 {
                            eprintln!("Warning: AAD has odd number of hex digits, padding with leading zero");
                            hex::decode(format!("0{}", trimmed)).unwrap_or_default()
                        } else {
                            hex::decode(trimmed).unwrap_or_default()
                        }
                    },
                    None => Vec::new(),
                };
                encrypt_seal(variant, &key_bytes, &input_data, &nonce_bytes, &aad_bytes, output_format)
            } else {
                // Block cipher mode
                encrypt_block_cipher(variant, &key_bytes, &input_data, output_format)
            };

            match result {
                Ok(encoded) => {
                    let output_bytes = if matches!(output_format, OutputFormat::RawBytes) {
                        // For raw bytes format, we encoded as hex, so decode it back
                        match hex::decode(&encoded) {
                            Ok(bytes) => bytes,
                            Err(_) => {
                                eprintln!("Warning: Failed to decode hex output");
                                encoded.as_bytes().to_vec()
                            }
                        }
                    } else {
                        // For text formats, add newline when writing to stdout
                        if output.is_none() {
                            format!("{}\n", encoded).into_bytes()
                        } else {
                            encoded.into_bytes()
                        }
                    };
                    if let Err(e) = write_output(output.as_ref(), &output_bytes) {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Decrypt {
            variant,
            key,
            input,
            data,
            output,
            format,
            seal,
            aad,
        } => {
            // Parse key
            let expected_key_len = match variant {
                CipherVariant::V512 => KEY_BYTES_512,
                CipherVariant::V1024 => KEY_BYTES_1024,
            };
            let key_bytes = match parse_hex_key(&key, expected_key_len) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            // Read input
            let input_data = match read_input(input.as_ref(), data.as_ref()) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };

            let input_format: OutputFormat = format.into();
            let result = if seal {
                // SEAL mode
                let encoded = if matches!(input_format, OutputFormat::RawBytes) {
                    // For raw bytes input, treat as hex-encoded
                    hex::encode(&input_data)
                } else {
                    // For text formats, decode as UTF-8 string
                    String::from_utf8_lossy(&input_data).trim().to_string()
                };
                let aad_bytes = aad
                    .map(|a| hex::decode(a.trim()).unwrap_or_default())
                    .unwrap_or_default();
                decrypt_seal(variant, &key_bytes, &encoded, &aad_bytes, input_format)
            } else {
                // Block cipher mode
                let encoded = if matches!(input_format, OutputFormat::RawBytes) {
                    // For raw bytes input, treat as hex-encoded
                    hex::encode(&input_data)
                } else {
                    // For text formats, decode as UTF-8 string
                    String::from_utf8_lossy(&input_data).trim().to_string()
                };
                decrypt_block_cipher(variant, &key_bytes, &encoded, input_format)
            };

            match result {
                Ok(decrypted) => {
                    if let Err(e) = write_output(output.as_ref(), &decrypted) {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
