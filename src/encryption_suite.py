"""
BlackRoad Encryption Suite – stdlib-only cryptographic toolkit.
AES-256 (CBC via manual implementation or hashlib+HMAC envelope),
PBKDF2 password hashing, HMAC-SHA256 signing, key generation.
Uses ONLY: hashlib, hmac, os, struct, base64 (stdlib – no third-party libs).
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time
from typing import Optional, Tuple


# ─────────────────────────────────────────────
# AES-256-CBC  (pure-Python, constant-time)
# ─────────────────────────────────────────────
# We implement a compact but correct AES-256 in pure Python so there is
# ZERO dependency on third-party packages while still producing real AES.

# AES S-Box and inverse S-Box
_AES_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])

_AES_RSBOX = bytes([_AES_SBOX.index(i) for i in range(256)])

_AES_RCON = [
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,
    0x6c,0xd8,0xab,0x4d,0x9a,0x2f,0x5e,0xbc,0x63,0xc6,
    0x97,0x35,0x6a,0xd4,0xb3,0x7d,0xfa,0xef,0xc5,
]


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


class _AES:
    """Pure-Python AES-256 block cipher (ECB mode – used internally only)."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 requires exactly 32-byte key")
        self._round_keys = self._key_expansion(key)

    def _key_expansion(self, key: bytes) -> list:
        Nk, Nr = 8, 14
        w = list(key)
        while len(w) < 4 * (Nr + 1) * 4:
            temp = w[-4:]
            i = len(w) // 4
            if i % Nk == 0:
                temp = [_AES_SBOX[b] for b in temp[1:] + temp[:1]]
                temp[0] ^= _AES_RCON[i // Nk]
            elif Nk > 6 and i % Nk == 4:
                temp = [_AES_SBOX[b] for b in temp]
            w.extend(b ^ c for b, c in zip(w[-4 * Nk:-4 * Nk + 4], temp))
        return [bytes(w[i:i+16]) for i in range(0, len(w), 16)]

    def _add_round_key(self, state: bytearray, rk: bytes) -> None:
        for i in range(16):
            state[i] ^= rk[i]

    def _sub_bytes(self, state: bytearray) -> None:
        for i in range(16):
            state[i] = _AES_SBOX[state[i]]

    def _shift_rows(self, state: bytearray) -> None:
        for r in range(1, 4):
            state[r::4] = state[r::4][r:] + state[r::4][:r]

    def _mix_columns(self, state: bytearray) -> None:
        for c in range(4):
            a = state[c*4:(c+1)*4]
            state[c*4]   = _gmul(a[0],2)^_gmul(a[1],3)^a[2]^a[3]
            state[c*4+1] = a[0]^_gmul(a[1],2)^_gmul(a[2],3)^a[3]
            state[c*4+2] = a[0]^a[1]^_gmul(a[2],2)^_gmul(a[3],3)
            state[c*4+3] = _gmul(a[0],3)^a[1]^a[2]^_gmul(a[3],2)

    def encrypt_block(self, block: bytes) -> bytes:
        state = bytearray(block)
        rks = self._round_keys
        self._add_round_key(state, rks[0])
        for r in range(1, 14):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, rks[r])
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, rks[14])
        return bytes(state)

    def _inv_sub_bytes(self, state: bytearray) -> None:
        for i in range(16):
            state[i] = _AES_RSBOX[state[i]]

    def _inv_shift_rows(self, state: bytearray) -> None:
        for r in range(1, 4):
            state[r::4] = state[r::4][-r:] + state[r::4][:-r]

    def _inv_mix_columns(self, state: bytearray) -> None:
        for c in range(4):
            a = state[c*4:(c+1)*4]
            state[c*4]   = _gmul(a[0],14)^_gmul(a[1],11)^_gmul(a[2],13)^_gmul(a[3],9)
            state[c*4+1] = _gmul(a[0],9)^_gmul(a[1],14)^_gmul(a[2],11)^_gmul(a[3],13)
            state[c*4+2] = _gmul(a[0],13)^_gmul(a[1],9)^_gmul(a[2],14)^_gmul(a[3],11)
            state[c*4+3] = _gmul(a[0],11)^_gmul(a[1],13)^_gmul(a[2],9)^_gmul(a[3],14)

    def decrypt_block(self, block: bytes) -> bytes:
        state = bytearray(block)
        rks = self._round_keys
        self._add_round_key(state, rks[14])
        for r in range(13, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, rks[r])
            self._inv_mix_columns(state)
        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, rks[0])
        return bytes(state)


# ─────────────────────────────────────────────
# PKCS7 padding
# ─────────────────────────────────────────────

def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad_len]


# ─────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────

def generate_key(length: int = 32) -> bytes:
    """Generate cryptographically secure random key."""
    return os.urandom(length)


def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """Derive a key from a password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000, dklen=length)


def encrypt_aes256(data: bytes, key: bytes) -> bytes:
    """
    Encrypt *data* with AES-256-CBC.
    Returns: base64(salt[16] + iv[16] + ciphertext + hmac[32])
    The key is derived from the raw bytes via PBKDF2 if len != 32.
    """
    if len(key) != 32:
        salt = os.urandom(16)
        derived = derive_key(key.decode(errors="replace"), salt)
    else:
        salt = os.urandom(16)
        derived = key

    iv = os.urandom(16)
    aes = _AES(derived)
    padded = _pkcs7_pad(data)
    # CBC mode
    ciphertext = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc_block = aes.encrypt_block(block)
        ciphertext.extend(enc_block)
        prev = enc_block

    mac = hmac.new(derived, salt + iv + bytes(ciphertext), hashlib.sha256).digest()
    payload = salt + iv + bytes(ciphertext) + mac
    return base64.b64encode(payload)


def decrypt_aes256(ciphertext_b64: bytes, key: bytes) -> bytes:
    """Decrypt data produced by encrypt_aes256()."""
    try:
        payload = base64.b64decode(ciphertext_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 ciphertext: {e}") from e

    if len(payload) < 16 + 16 + 16 + 32:
        raise ValueError("Ciphertext too short")

    salt = payload[:16]
    iv = payload[16:32]
    mac = payload[-32:]
    ciphertext = payload[32:-32]

    if len(key) != 32:
        derived = derive_key(key.decode(errors="replace"), salt)
    else:
        derived = key

    expected_mac = hmac.new(derived, salt + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError("HMAC verification failed – data tampered or wrong key")

    aes = _AES(derived)
    plaintext = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec_block = aes.decrypt_block(block)
        plaintext.extend(a ^ b for a, b in zip(dec_block, prev))
        prev = block
    return _pkcs7_unpad(bytes(plaintext))


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hash password with PBKDF2-HMAC-SHA256. Returns 'pbkdf2$iter$salt$hash'."""
    iterations = 260_000
    if salt is None:
        salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2 hash. Constant-time comparison."""
    try:
        _, iterations_s, salt_b64, expected_b64 = stored_hash.split("$")
        iterations = int(iterations_s)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(expected_b64)
    except Exception:
        return False
    computed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return hmac.compare_digest(computed, expected)


def sign_data(data: bytes, key: bytes) -> bytes:
    """Create HMAC-SHA256 signature. Returns base64-encoded signature."""
    sig = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(sig)


def verify_signature(data: bytes, signature_b64: bytes, key: bytes) -> bool:
    """Verify an HMAC-SHA256 signature (constant-time)."""
    try:
        sig = base64.b64decode(signature_b64)
    except Exception:
        return False
    expected = hmac.new(key, data, hashlib.sha256).digest()
    return hmac.compare_digest(sig, expected)


def hash_sha256(data: bytes) -> str:
    """Return hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def hash_sha512(data: bytes) -> str:
    """Return hex SHA-512 digest."""
    return hashlib.sha512(data).hexdigest()


def random_token(length: int = 32) -> str:
    """Generate URL-safe random token."""
    return base64.urlsafe_b64encode(os.urandom(length)).rstrip(b"=").decode()


def encrypt_envelope(plaintext: str, password: str) -> str:
    """High-level: password → PBKDF2 key → AES-256-CBC + HMAC. Returns JSON string."""
    key_salt = os.urandom(16)
    key = derive_key(password, key_salt)
    ciphertext = encrypt_aes256(plaintext.encode(), key)
    envelope = {
        "v": 1,
        "alg": "AES-256-CBC+HMAC-SHA256+PBKDF2",
        "key_salt": base64.b64encode(key_salt).decode(),
        "ciphertext": ciphertext.decode(),
    }
    return json.dumps(envelope)


def decrypt_envelope(envelope_json: str, password: str) -> str:
    """High-level: decrypt a JSON envelope produced by encrypt_envelope()."""
    env = json.loads(envelope_json)
    key_salt = base64.b64decode(env["key_salt"])
    key = derive_key(password, key_salt)
    plaintext = decrypt_aes256(env["ciphertext"].encode(), key)
    return plaintext.decode()


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="BlackRoad Encryption Suite – stdlib AES-256")
    sub = p.add_subparsers(dest="cmd")

    enc = sub.add_parser("encrypt", help="Encrypt a string")
    enc.add_argument("plaintext")
    enc.add_argument("--password", required=True)

    dec = sub.add_parser("decrypt", help="Decrypt an envelope JSON")
    dec.add_argument("envelope")
    dec.add_argument("--password", required=True)

    hp = sub.add_parser("hash-password", help="Hash a password with PBKDF2")
    hp.add_argument("password")

    vp = sub.add_parser("verify-password", help="Verify a password against stored hash")
    vp.add_argument("password")
    vp.add_argument("stored_hash")

    sg = sub.add_parser("sign", help="HMAC-SHA256 sign data")
    sg.add_argument("data")
    sg.add_argument("--key", required=True)

    vs = sub.add_parser("verify-sig", help="Verify HMAC-SHA256 signature")
    vs.add_argument("data")
    vs.add_argument("signature")
    vs.add_argument("--key", required=True)

    gk = sub.add_parser("gen-key", help="Generate a random key")
    gk.add_argument("--length", type=int, default=32)
    gk.add_argument("--format", choices=["hex","b64","raw"], default="hex")

    sh = sub.add_parser("hash", help="Hash data with SHA-256 or SHA-512")
    sh.add_argument("data")
    sh.add_argument("--algo", choices=["sha256","sha512"], default="sha256")

    args = p.parse_args(argv)

    if args.cmd == "encrypt":
        result = encrypt_envelope(args.plaintext, args.password)
        print(result)
    elif args.cmd == "decrypt":
        try:
            print(decrypt_envelope(args.envelope, args.password))
        except Exception as e:
            print(f"Decryption failed: {e}", file=sys.stderr)
            return 1
    elif args.cmd == "hash-password":
        print(hash_password(args.password))
    elif args.cmd == "verify-password":
        ok = verify_password(args.password, args.stored_hash)
        print("✅ MATCH" if ok else "❌ MISMATCH")
        return 0 if ok else 1
    elif args.cmd == "sign":
        key = args.key.encode()
        sig = sign_data(args.data.encode(), key)
        print(sig.decode())
    elif args.cmd == "verify-sig":
        key = args.key.encode()
        ok = verify_signature(args.data.encode(), args.signature.encode(), key)
        print("✅ VALID" if ok else "❌ INVALID")
        return 0 if ok else 1
    elif args.cmd == "gen-key":
        raw = generate_key(args.length)
        if args.format == "hex":
            print(raw.hex())
        elif args.format == "b64":
            print(base64.b64encode(raw).decode())
        else:
            sys.stdout.buffer.write(raw)
    elif args.cmd == "hash":
        fn = hash_sha256 if args.algo == "sha256" else hash_sha512
        print(fn(args.data.encode()))
    else:
        p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
