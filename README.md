# enmf — Encrypt My Files

A command-line tool to encrypt files before uploading them to GitHub or any public storage. Uses **AES-256-GCM** authenticated encryption with **Argon2id** key derivation.

## Features

- AES-256-GCM — authenticated encryption (detects tampering)
- Argon2id — brute-force resistant key derivation (OWASP 2023 compliant)
- Password prompted at runtime with no echo — never appears in shell history or `ps` output
- Key material zeroized from memory after use
- Output is base64 text — clean for git diffs and GitHub commits
- Produces two copies on encrypt: one beside the source file, one in the current directory

## Build

```bash
cargo build --release
```

The binary is at `target/release/enmf`.

## Usage

### Encrypt

```bash
cargo run --release -- encrypt <file>
```

Prompts for a password (twice, to confirm). Produces `<file>.enc`.

Example:

```
$ cargo run --release -- encrypt secrets.txt
Password:
Confirm  :
Encrypted  'secrets.txt' -> 'secrets.txt.enc'
Also saved -> './secrets.txt.enc'
42 bytes in, 132 bytes out (encrypted + base64)
```

### Decrypt

```bash
cargo run --release -- decrypt <file.enc>
```

Prompts for the password. Restores the original file by stripping the `.enc` extension.

Example:

```
$ cargo run --release -- decrypt secrets.txt.enc
Password:
Decrypted 'secrets.txt.enc' -> 'secrets.txt'
42 bytes restored
```

## On-disk format

The `.enc` file is base64-encoded. Decoded, the binary layout is:

```
[ salt_len : 4 bytes, big-endian ]
[ salt     : salt_len bytes, UTF-8 ]
[ nonce    : 12 bytes ]
[ ciphertext + GCM authentication tag : remaining bytes ]
```

Everything needed to decrypt is stored in the file. The password is the only secret.

## Cryptography

| Component | Choice | Why |
|---|---|---|
| Cipher | AES-256-GCM | Authenticated encryption — wrong password fails loudly, not silently |
| KDF | Argon2id | Resistant to GPU and side-channel attacks; OWASP 2023 Config 2 (m=19 MiB, t=2, p=1) |
| Randomness | `OsRng` → `getrandom(2)` | Kernel CSPRNG; used for both salt and nonce |
| Nonce | 96-bit random, per-file | Standard for AES-GCM; new salt per file makes key unique, so nonce space is never exhausted |
| Key size | 256-bit | First 32 bytes of Argon2 output |
| Memory safety | `zeroize` | Key buffer and AES key scrubbed from memory on drop |

## GitHub workflow

```bash
# Encrypt before committing
cargo run --release -- encrypt my_secrets.txt

# Commit only the .enc file
git add my_secrets.txt.enc
git commit -m "add encrypted secrets"
git push

# Decrypt after cloning
cargo run --release -- decrypt my_secrets.txt.enc
```

Never commit the unencrypted file or the password.

## Dependencies

- [`aes-gcm`](https://crates.io/crates/aes-gcm) — AES-256-GCM encryption
- [`argon2`](https://crates.io/crates/argon2) — Argon2id key derivation
- [`rand`](https://crates.io/crates/rand) — `OsRng` for nonce generation
- [`base64`](https://crates.io/crates/base64) — text-safe output encoding
- [`zeroize`](https://crates.io/crates/zeroize) — secure key erasure
- [`rpassword`](https://crates.io/crates/rpassword) — password prompt with no echo
