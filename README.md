<!-- BlackRoad SEO Enhanced -->

# ulackroad encryption suite

> Part of **[BlackRoad OS](https://blackroad.io)** — Sovereign Computing for Everyone

[![BlackRoad OS](https://img.shields.io/badge/BlackRoad-OS-ff1d6c?style=for-the-badge)](https://blackroad.io)
[![BlackRoad-Security](https://img.shields.io/badge/Org-BlackRoad-Security-2979ff?style=for-the-badge)](https://github.com/BlackRoad-Security)

**ulackroad encryption suite** is part of the **BlackRoad OS** ecosystem — a sovereign, distributed operating system built on edge computing, local AI, and mesh networking by **BlackRoad OS, Inc.**

### BlackRoad Ecosystem
| Org | Focus |
|---|---|
| [BlackRoad OS](https://github.com/BlackRoad-OS) | Core platform |
| [BlackRoad OS, Inc.](https://github.com/BlackRoad-OS-Inc) | Corporate |
| [BlackRoad AI](https://github.com/BlackRoad-AI) | AI/ML |
| [BlackRoad Hardware](https://github.com/BlackRoad-Hardware) | Edge hardware |
| [BlackRoad Security](https://github.com/BlackRoad-Security) | Cybersecurity |
| [BlackRoad Quantum](https://github.com/BlackRoad-Quantum) | Quantum computing |
| [BlackRoad Agents](https://github.com/BlackRoad-Agents) | AI agents |
| [BlackRoad Network](https://github.com/BlackRoad-Network) | Mesh networking |

**Website**: [blackroad.io](https://blackroad.io) | **Chat**: [chat.blackroad.io](https://chat.blackroad.io) | **Search**: [search.blackroad.io](https://search.blackroad.io)

---


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
