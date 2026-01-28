# 📕 BookCipher

BookCipher is a macOS desktop app and Python CLI that implements **authenticated, book-bound encryption** using public-domain texts. It encrypts plaintext into compact, verifiable ciphertext that is cryptographically bound to a specific set of books and can only be decrypted with the correct key and book corpus.

Designed for experimentation, learning, and cryptographic curiosity.

## ✨ Features

* 🔐 **AES-256-GCM authenticated encryption** — tamper detection and authentication verification
* 📚 **Multi-book corpus** — combine multiple .txt files into one cipher corpus
* 🔑 **Passphrase-based key derivation** — Scrypt KDF for brute-force resistance
* 🧹 **Auto-cleaning of Project Gutenberg headers** — removes boilerplate automatically
* 🧾 **Compact tokens** — base64url-encoded, no spaces or quotes needed
* **Corpus binding** — ciphertext is cryptographically bound to book order and content (SHA-256 hash)
* 🖥 **Dual interface** — Native macOS Tkinter app or command-line CLI
* 🎨 **Dark theme UI** — crimson and charcoal color scheme

## 🔐 How It Works

### Encryption Pipeline
1. **Build corpus**: Load one or more .txt book files, optionally strip Project Gutenberg headers
2. **Hash corpus**: Compute SHA-256 of combined text (corpus binding)
3. **Derive key**: Use Scrypt(passphrase, salt, n=2^17) + HKDF for 32-byte encryption key
4. **Encrypt**: AES-256-GCM encrypts plaintext with corpus hash as Additional Authenticated Data (AAD)
5. **Pack token**: `BC2.<salt>.<nonce>.<corpus_hash>.<ciphertext>` (all base64url-encoded)

### Decryption Pipeline
1. **Parse token**: Extract salt, nonce, embedded corpus hash, and ciphertext
2. **Verify corpus**: Compare embedded hash against current book corpus (fails if wrong books/order)
3. **Derive key**: Scrypt(passphrase, salt) regenerates the encryption key
4. **Decrypt & verify**: AES-256-GCM decrypts; authentication fails if key is wrong or ciphertext modified
5. **Output**: Recovered plaintext

### Security Properties
* **Authentication**: AES-256-GCM provides built-in authentication (tampering immediately detected)
* **Key derivation**: Scrypt with n=2^17, r=8, p=1 resists brute-force attacks (4x stronger than v1)
* **HKDF expansion**: Additional security layer for proper key stretching
* **Constant-time comparison**: Corpus hash verified using `hmac.compare_digest()` (prevents timing attacks)
* **Corpus binding**: Ciphertext fails to decrypt if book order changes or text is modified
* **Random salt & nonce**: Each encryption generates fresh 16-byte salt and 12-byte nonce
* **Token versioning**: Version field (`BC2`) supports future algorithm upgrades

## 🖼 Desktop App Interface

* **Books panel** — add one or more .txt files (drag & drop or file browser)
* **Plaintext area** — enter or paste text to encrypt
* **Key field** — passphrase (required for both encryption and decryption)
* **Key strength meter** — visual indicator of passphrase quality (empty → strong)
* **Ciphertext area** — compact output, ready to copy/share
* **Encrypt / Decrypt buttons** — perform the operation
* **Status messages** — real-time feedback on success or errors

## 💻 CLI Usage

```bash
# Basic encryption
python book_cipher.py --book books/pride_prejudice.txt --key "my_passphrase" encrypt --message "Hello World"

# Encrypt with multiple books
python book_cipher.py --book book1.txt --book book2.txt --key "my_key" encrypt --message "Secret"

# Decrypt a token
python book_cipher.py --book books/pride_prejudice.txt --key "my_passphrase" decrypt --cipher "BC2.xxx.yyy.zzz..."

# Interactive mode (prompts for input)
python book_cipher.py --book books/alice.txt --key "secret" encrypt
python book_cipher.py --book books/alice.txt --key "secret" decrypt

# File I/O (encrypt file to file)
python3 book_cipher.py --book books/alice.txt --key "secret" encrypt --input-file message.txt --output-file encrypted.token

# High-security Scrypt (2^18, slower but stronger)
python3 book_cipher.py --book books/alice.txt --key "secret" --scrypt-strength high encrypt --message "text"

# Verbose logging for debugging
python3 book_cipher.py --book books/alice.txt --key "secret" --verbose encrypt --message "text"

# Disable Gutenberg auto-cleaning
python3 book_cipher.py --book custom.txt --key "key" --no-autoclean encrypt --message "text"
```

### CLI Options

**Global options**:
- `--book PATH` (required, repeatable): Path to .txt book(s)
- `--key PASSPHRASE` (required): Encryption passphrase
- `--no-autoclean`: Skip Project Gutenberg header removal
- `--scrypt-strength [normal|high]`: Scrypt cost (default: normal = 2^17 ~100ms)
- `--verbose`: Enable debug logging

**Encrypt subcommand**:
- `--message TEXT`: Message to encrypt (prompts if omitted)
- `--input-file PATH`: Read plaintext from file instead
- `--output-file PATH`: Save ciphertext to file

**Decrypt subcommand**:
- `--cipher TOKEN`: Token to decrypt (prompts if omitted)
- `--input-file PATH`: Read token from file
- `--output-file PATH`: Save plaintext to file

## 📚 Supported Book Files

* Plain text (.txt)
* UTF-8 recommended
* Project Gutenberg texts work best (headers auto-removed via regex)

Example books:
* Alice's Adventures in Wonderland
* Pride and Prejudice
* Gulliver's Travels
* The Adventures of Tom Sawyer

## 📥 Installation

### macOS Desktop App
1. Download the .dmg from Releases
2. Open it
3. Drag BookCipher into your Applications folder
4. **First launch**: Right-click BookCipher → Open → Open again (required once for unsigned apps on macOS)

### Python CLI
```bash
pip install cryptography
python book_cipher.py --help
```

## 🏗 Module Structure

* **`cipher_core.py`** — Core encryption/decryption, corpus building, Scrypt KDF, AES-256-GCM, key strength analysis
* **`book_cipher.py`** — Command-line interface with argparse, file I/O, logging
* **`BookCipherApp.py`** — Tkinter desktop app with GUI, dark theme, key strength meter, threading
* **`word_cipher.py`** — Legacy/experimental cipher variant (not actively used)
* **`hybrid_cipher.py`** — Hybrid cipher variant (not actively used)
* **`app_version.py`** — Version string for app distribution
* **`tests/test_cipher_core.py`** — Comprehensive unit tests (20+ test cases)

## 🛠 Built With

* **Python 3.8+**
* **cryptography** — AES-256-GCM, Scrypt KDF, secure random generation
* **tkinter** — GUI framework (macOS native)
* **PyInstaller** — Desktop app bundling and distribution
* **base64** — URL-safe encoding for compact tokens

## ⚠️ Disclaimer

This project is **for educational and experimental use only**. It is not recommended for securing high-value secrets or for professional cryptographic applications. The underlying cipher (AES-256-GCM) is sound, but this implementation has not undergone professional security audits.

For detailed security analysis, see [THREAT_MODEL.md](THREAT_MODEL.md).

## 📚 Additional Documentation

- **[CHANGELOG.md](CHANGELOG.md)** — Version history and feature updates
- **[THREAT_MODEL.md](THREAT_MODEL.md)** — Security properties, assumptions, attack scenarios
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** — Common issues and solutions
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — Contributing guidelines and development setup

## 📄 License

MIT License — You're free to use, modify, and share.

## 💡 Why This Exists

BookCipher was built as an exploration of:
* Classical cipher techniques with modern cryptography
* Book-bound encryption as a learning tool
* Deterministic randomness and corpus binding
* macOS app packaging and distribution
* Clean UI design for cryptographic tools


