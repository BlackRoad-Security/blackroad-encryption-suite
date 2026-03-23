# blackroad-encryption-suite

> BlackRoad Security - ublackroad encryption suite

Part of the [BlackRoad OS](https://blackroad.io) ecosystem — [BlackRoad-Security](https://github.com/BlackRoad-Security)

---

# blackroad-encryption-suite

Pure Python (stdlib-only) cryptographic toolkit. **No third-party dependencies.**

## Features

- 🔐 **AES-256-CBC** – Full pure-Python AES-256 implementation (no PyCryptodome/cryptography needed)
- 🔑 **PBKDF2 Password Hashing** – 260,000 iterations, SHA-256, random salt
- ✍️ **HMAC-SHA256 Signing** – Constant-time signature verification
- 📦 **Encrypted Envelopes** – Password → PBKDF2 → AES-256-CBC + HMAC-SHA256
- 🎲 **Secure Key Generation** – `os.urandom`-based key/token generation
- 🔢 **SHA-256/SHA-512** – Standard hash functions

## Usage

```bash
# Encrypt a message
python src/encryption_suite.py encrypt "my secret" --password "mypassword"

# Decrypt
python src/encryption_suite.py decrypt '{"v":1,...}' --password "mypassword"

# Hash a password (PBKDF2)
python src/encryption_suite.py hash-password "mypassword"

# Verify password
python src/encryption_suite.py verify-password "mypassword" "pbkdf2$260000$..."

# Sign data
python src/encryption_suite.py sign "hello" --key "mykey"

# Verify signature
python src/encryption_suite.py verify-sig "hello" "signature" --key "mykey"

# Generate key
python src/encryption_suite.py gen-key --length 32 --format hex
```

## Security Properties

- AES-256-CBC with random IV (16 bytes) + random salt (16 bytes)
- HMAC-SHA256 authentication (encrypt-then-MAC)
- PBKDF2 with 260,000 iterations (OWASP 2024 recommended)
- Constant-time comparison for all secret material

## Tests

```bash
pytest tests/ -v --cov=src
```

## License

Proprietary – BlackRoad OS, Inc. All rights reserved.
