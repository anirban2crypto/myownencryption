"""
enmf.py — encrypt/decrypt files using AES-256-GCM + Argon2id.

On-disk format (base64-encoded):
    [ salt_len : 4 bytes, big-endian uint32 ]
    [ salt     : salt_len bytes, UTF-8      ]
    [ nonce    : 12 bytes                   ]
    [ ciphertext + 16-byte GCM tag          ]

Fully cross-compatible with the Rust enmf binary.

Dependencies:
    pip install cryptography argon2-cffi
"""

import base64
import getpass
import os
import struct
import sys
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Match Rust Argon2::default() parameters exactly
_M_COST = 19 * 1024   # 19 MiB in KiB
_T_COST = 2
_P_COST = 1
_KEY_LEN = 32
_NONCE_LEN = 12
_SALT_LEN = 16


def _derive_key(password: str, salt_raw: bytes) -> bytes:
    return hash_secret_raw(
        password.encode(),
        salt_raw,
        time_cost=_T_COST,
        memory_cost=_M_COST,
        parallelism=_P_COST,
        hash_len=_KEY_LEN,
        type=Type.ID,
    )


def _salt_encode(raw: bytes) -> bytes:
    """Encode raw salt as unpadded base64, matching Rust SaltString::as_str()."""
    return base64.b64encode(raw).rstrip(b'=')


def _salt_decode(encoded: bytes) -> bytes:
    """Decode unpadded base64 salt string back to raw bytes."""
    padding = (-len(encoded)) % 4
    return base64.b64decode(encoded + b'=' * padding)


def encrypt(input_path: str) -> None:
    plaintext = Path(input_path).read_bytes()

    password = getpass.getpass("Password: ")
    confirm  = getpass.getpass("Confirm  : ")
    if password != confirm:
        sys.exit("Passwords do not match.")

    salt_raw   = os.urandom(_SALT_LEN)
    salt       = _salt_encode(salt_raw)   # store as base64 string, like Rust
    nonce      = os.urandom(_NONCE_LEN)
    key        = _derive_key(password, salt_raw)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    # Build payload: [salt_len BE][salt as base64 string][nonce][ciphertext+tag]
    salt_len_bytes = struct.pack(">I", len(salt))
    payload = salt_len_bytes + salt + nonce + ciphertext
    encoded = base64.b64encode(payload)

    # Copy 1: beside the input file
    output_path = input_path + ".enc"
    Path(output_path).write_bytes(encoded)

    # Copy 2: current working directory
    local_path = Path(input_path).name + ".enc"
    Path(local_path).write_bytes(encoded)

    print(f"Encrypted  '{input_path}' -> '{output_path}'")
    print(f"Also saved -> './{local_path}'")
    print(f"{len(plaintext)} bytes in, {len(encoded)} bytes out (encrypted + base64)")


def decrypt(input_path: str) -> None:
    encoded = Path(input_path).read_bytes()
    payload = base64.b64decode(encoded.strip())

    if len(payload) < 4:
        sys.exit("File too short to be a valid .enc file.")

    salt_len = struct.unpack(">I", payload[:4])[0]
    salt_end = 4 + salt_len

    if len(payload) < salt_end + _NONCE_LEN:
        sys.exit("Corrupted .enc file (truncated).")

    salt_raw   = _salt_decode(payload[4:salt_end])
    nonce      = payload[salt_end:salt_end + _NONCE_LEN]
    ciphertext = payload[salt_end + _NONCE_LEN:]

    password = getpass.getpass("Password: ")
    key = _derive_key(password, salt_raw)

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception:
        sys.exit("Decryption failed — wrong password or corrupted file.")

    output_path = input_path.removesuffix(".enc") if input_path.endswith(".enc") else input_path + ".dec"
    Path(output_path).write_bytes(plaintext)

    print(f"Decrypted '{input_path}' -> '{output_path}'")
    print(f"{len(plaintext)} bytes restored")


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage:")
        print(f"  python {sys.argv[0]} encrypt <input_file>")
        print(f"  python {sys.argv[0]} decrypt <file.enc>")
        sys.exit(1)

    cmd, path = sys.argv[1], sys.argv[2]
    if cmd == "encrypt":
        encrypt(path)
    elif cmd == "decrypt":
        decrypt(path)
    else:
        sys.exit(f"Unknown command '{cmd}'. Use 'encrypt' or 'decrypt'.")


if __name__ == "__main__":
    main()
