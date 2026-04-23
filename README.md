# enmf — Encrypt My Files

> Encrypt files with AES-256-GCM + Argon2id before pushing them to GitHub — safe, simple, available in Rust and Python.

A command-line tool to encrypt files before uploading them to GitHub or any public storage. Uses **AES-256-GCM** authenticated encryption with **Argon2id** key derivation. Both implementations share the same on-disk format, so `.enc` files are fully cross-compatible.

## Features

- AES-256-GCM — authenticated encryption (detects tampering)
- Argon2id — brute-force resistant key derivation (OWASP 2023 compliant)
- Password prompted at runtime with no echo — never appears in shell history or `ps` output
- Key material zeroized from memory after use (Rust)
- Output is base64 text — clean for git diffs and GitHub commits
- Produces two copies on encrypt: one beside the source file, one in the current directory
- Rust and Python implementations are fully cross-compatible

## Rust

### Build

```bash
cargo build --release
```

The binary is at `target/release/enmf`.

### Encrypt

```bash
cargo run --release -- encrypt <file>
```

Prompts for a password (twice, to confirm). Produces `<file>.enc`.

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

```
$ cargo run --release -- decrypt secrets.txt.enc
Password:
Decrypted 'secrets.txt.enc' -> 'secrets.txt'
42 bytes restored
```

### Dependencies

- [`aes-gcm`](https://crates.io/crates/aes-gcm) — AES-256-GCM encryption
- [`argon2`](https://crates.io/crates/argon2) — Argon2id key derivation
- [`rand`](https://crates.io/crates/rand) — `OsRng` for nonce generation
- [`base64`](https://crates.io/crates/base64) — text-safe output encoding
- [`zeroize`](https://crates.io/crates/zeroize) — secure key erasure
- [`rpassword`](https://crates.io/crates/rpassword) — password prompt with no echo

## Python

Requires Python 3.9+.

### Install

```bash
pip install -r python/requirements.txt
```

### Encrypt

```bash
python3 python/enmf.py encrypt <file>
```

### Decrypt

```bash
python3 python/enmf.py decrypt <file.enc>
```

### Use as a module

```python
from enmf import encrypt, decrypt

encrypt("secrets.txt")       # prompts for password, writes secrets.txt.enc
decrypt("secrets.txt.enc")   # prompts for password, writes secrets.txt
```

### Dependencies

- [`cryptography`](https://pypi.org/project/cryptography/) — AES-256-GCM encryption
- [`argon2-cffi`](https://pypi.org/project/argon2-cffi/) — Argon2id key derivation

## On-disk format

The `.enc` file is base64-encoded. Decoded, the binary layout is:

```
[ salt_len : 4 bytes, big-endian uint32 ]
[ salt     : salt_len bytes, UTF-8      ]
[ nonce    : 12 bytes                   ]
[ ciphertext + 16-byte GCM tag          ]
```

Everything needed to decrypt is stored in the file. The password is the only secret.

## Cryptography

| Component | Choice | Why |
|---|---|---|
| Cipher | AES-256-GCM | Authenticated encryption — wrong password fails loudly, not silently |
| KDF | Argon2id | Resistant to GPU and side-channel attacks; OWASP 2023 Config 2 (m=19 MiB, t=2, p=1) |
| Randomness | OS CSPRNG | `getrandom(2)` on Linux; used for both salt and nonce |
| Nonce | 96-bit random, per-file | Standard for AES-GCM; new salt per file makes key unique, so nonce space is never exhausted |
| Key size | 256-bit | First 32 bytes of Argon2 output |
| Memory safety | `zeroize` (Rust) | Key buffer and AES key scrubbed from memory on drop |

## GitHub workflow

```bash
# Encrypt before committing (Rust or Python)
cargo run --release -- encrypt my_secrets.txt
# or
python3 python/enmf.py encrypt my_secrets.txt

# Commit only the .enc file
git add my_secrets.txt.enc
git commit -m "add encrypted secrets"
git push

# Decrypt after cloning (Rust or Python)
cargo run --release -- decrypt my_secrets.txt.enc
# or
python3 python/enmf.py decrypt my_secrets.txt.enc
```

Never commit the unencrypted file or the password.
