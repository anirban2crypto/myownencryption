use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{password_hash::{PasswordHasher, SaltString}, Argon2};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

// key_buf is Zeroizing so the 32-byte key material is scrubbed from the stack on drop.
// aes-gcm's "zeroize" feature ensures Key<Aes256Gcm> is also scrubbed when it drops.
fn derive_key(password: &str, salt: &SaltString, buf: &mut Zeroizing<[u8; 32]>) -> Key<Aes256Gcm> {
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), salt)
        .expect("Argon2 failed");
    buf.copy_from_slice(&hash.hash.unwrap().as_bytes()[..32]);
    *Key::<Aes256Gcm>::from_slice(buf.as_ref())
}

fn read_password(prompt: &str) -> Zeroizing<String> {
    Zeroizing::new(rpassword::prompt_password(prompt).expect("Failed to read password"))
}

fn encrypt(input_path: &str) {
    let plaintext = std::fs::read(input_path)
        .unwrap_or_else(|e| { eprintln!("Cannot read '{}': {}", input_path, e); std::process::exit(1); });

    // Prompt twice to catch typos
    let password = read_password("Password: ");
    let confirm  = read_password("Confirm  : ");
    if *password != *confirm {
        eprintln!("Passwords do not match."); std::process::exit(1);
    }

    // Fresh random salt — same password → different key every run
    let salt = SaltString::generate(&mut OsRng);
    let mut key_buf = Zeroizing::new([0u8; 32]);
    let key = derive_key(&password, &salt, &mut key_buf);

    // Fresh random 96-bit nonce — standard for AES-256-GCM
    let cipher = Aes256Gcm::new(&key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("Encryption failed");

    // Layout: [salt_len: 4B BE] [salt: UTF-8] [nonce: 12B] [ciphertext + 16B GCM tag]
    let salt_bytes = salt.as_str().as_bytes();
    let mut payload = Vec::with_capacity(4 + salt_bytes.len() + 12 + ciphertext.len());
    payload.extend_from_slice(&(salt_bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(salt_bytes);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    let encoded = STANDARD.encode(&payload);

    // Copy 1: next to the input file
    let output_path = format!("{}.enc", input_path);
    std::fs::write(&output_path, &encoded)
        .unwrap_or_else(|e| { eprintln!("Cannot write '{}': {}", output_path, e); std::process::exit(1); });

    // Copy 2: current working directory
    let file_name = std::path::Path::new(input_path)
        .file_name().unwrap().to_string_lossy();
    let local_path = format!("{}.enc", file_name);
    std::fs::write(&local_path, &encoded)
        .unwrap_or_else(|e| { eprintln!("Cannot write '{}': {}", local_path, e); std::process::exit(1); });

    println!("Encrypted  '{}' -> '{}'", input_path, output_path);
    println!("Also saved -> './{}'", local_path);
    println!("{} bytes in, {} bytes out (encrypted + base64)", plaintext.len(), encoded.len());
}

fn decrypt(input_path: &str) {
    let encoded = std::fs::read_to_string(input_path)
        .unwrap_or_else(|e| { eprintln!("Cannot read '{}': {}", input_path, e); std::process::exit(1); });

    let payload = STANDARD.decode(encoded.trim())
        .unwrap_or_else(|e| { eprintln!("Base64 decode failed: {}", e); std::process::exit(1); });

    // Parse layout
    if payload.len() < 4 { eprintln!("File too short"); std::process::exit(1); }
    let salt_len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
    let salt_end = 4 + salt_len;
    if payload.len() < salt_end + 12 { eprintln!("Corrupted .enc file (truncated)"); std::process::exit(1); }

    let salt_str = std::str::from_utf8(&payload[4..salt_end])
        .unwrap_or_else(|_| { eprintln!("Corrupted salt"); std::process::exit(1); });
    let salt = SaltString::from_b64(salt_str)
        .unwrap_or_else(|_| { eprintln!("Invalid salt encoding"); std::process::exit(1); });

    let nonce = Nonce::from_slice(&payload[salt_end..salt_end + 12]);
    let ciphertext = &payload[salt_end + 12..];

    let password = read_password("Password: ");
    let mut key_buf = Zeroizing::new([0u8; 32]);
    let key = derive_key(&password, &salt, &mut key_buf);
    let cipher = Aes256Gcm::new(&key);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .unwrap_or_else(|_| {
            eprintln!("Decryption failed — wrong password or corrupted file");
            std::process::exit(1);
        });

    let output_path = if input_path.ends_with(".enc") {
        input_path.trim_end_matches(".enc").to_string()
    } else {
        format!("{}.dec", input_path)
    };

    std::fs::write(&output_path, &plaintext)
        .unwrap_or_else(|e| { eprintln!("Cannot write '{}': {}", output_path, e); std::process::exit(1); });

    println!("Decrypted '{}' -> '{}'", input_path, output_path);
    println!("{} bytes restored", plaintext.len());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage:");
        eprintln!("  {} encrypt <input_file>", args[0]);
        eprintln!("  {} decrypt <file.enc>", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "encrypt" => encrypt(&args[2]),
        "decrypt" => decrypt(&args[2]),
        cmd => {
            eprintln!("Unknown command '{}'. Use 'encrypt' or 'decrypt'.", cmd);
            std::process::exit(1);
        }
    }
}
