"""Tests for blackroad-encryption-suite."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from src.encryption_suite import (
    generate_key, encrypt_aes256, decrypt_aes256,
    hash_password, verify_password, sign_data, verify_signature,
    encrypt_envelope, decrypt_envelope, hash_sha256, random_token,
)


def test_key_generation_length():
    key = generate_key(32)
    assert len(key) == 32


def test_encrypt_decrypt_roundtrip():
    key = generate_key(32)
    plaintext = b"Hello, BlackRoad Security!"
    ciphertext = encrypt_aes256(plaintext, key)
    recovered = decrypt_aes256(ciphertext, key)
    assert recovered == plaintext


def test_encrypt_produces_different_ciphertexts():
    key = generate_key(32)
    ct1 = encrypt_aes256(b"same", key)
    ct2 = encrypt_aes256(b"same", key)
    assert ct1 != ct2  # due to random IV + salt


def test_wrong_key_raises():
    key1 = generate_key(32)
    key2 = generate_key(32)
    ct = encrypt_aes256(b"secret", key1)
    with pytest.raises(ValueError):
        decrypt_aes256(ct, key2)


def test_tampered_ciphertext_raises():
    key = generate_key(32)
    ct = bytearray(encrypt_aes256(b"data", key))
    ct[50] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt_aes256(bytes(ct), key)


def test_password_hash_verify():
    pw = "MyStr0ng!Pass"
    h = hash_password(pw)
    assert verify_password(pw, h)
    assert not verify_password("wrongpassword", h)


def test_hmac_sign_verify():
    key = b"my-secret-key-32bytesxxxxxxxxxxx"
    data = b"important data"
    sig = sign_data(data, key)
    assert verify_signature(data, sig, key)


def test_hmac_invalid_signature():
    key = b"my-secret-key-32bytesxxxxxxxxxxx"
    data = b"important data"
    sig = sign_data(data, key)
    assert not verify_signature(b"tampered data", sig, key)


def test_envelope_roundtrip():
    secret = "my_p@ssword_123!"
    plaintext = "top secret message"
    envelope = encrypt_envelope(plaintext, secret)
    recovered = decrypt_envelope(envelope, secret)
    assert recovered == plaintext


def test_sha256():
    h = hash_sha256(b"hello")
    assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_random_token_unique():
    tokens = {random_token(16) for _ in range(100)}
    assert len(tokens) == 100
