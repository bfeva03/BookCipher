# Copilot Coding Agent Instructions for BookCipher

## Project Overview
BookCipher is a Python-based encryption tool with both a Tkinter desktop GUI (macOS-focused) and a CLI. It implements authenticated, book-bound encryption using public-domain texts as the cryptographic corpus. The project is designed for experimentation and learning, not for production security.

## Architecture & Key Components
- **cipher_core.py**: Core cryptographic logic (Scrypt KDF, AES-256-GCM, corpus hashing, key strength analysis)
- **book_cipher.py**: CLI entry point (argparse, file I/O, logging, command parsing)
- **BookCipherApp.py**: Tkinter GUI (book selection, drag-and-drop, real-time feedback, threading)
- **word_cipher.py, hybrid_cipher.py**: Experimental/legacy ciphers (not actively used)
- **books/**: Example .txt book files (Project Gutenberg, UTF-8)
- **tests/**: Unit tests (pytest, focus on cipher_core)

## Developer Workflows
- **Run GUI app**: `python3 BookCipherApp.py` (macOS, requires Tkinter)
- **Run CLI**: `python3 book_cipher.py --help` for options
- **Encrypt/Decrypt**: Use `--book`, `--key`, and `encrypt`/`decrypt` subcommands (see README for examples)
- **Testing**: `pytest tests/` (unit tests for core logic)
- **Build app**: Use PyInstaller with `BookCipher.spec` (see build/ for output)

## Project-Specific Conventions
- **Corpus binding**: Ciphertext is bound to the exact book set and order (SHA-256 hash); decryption fails if books differ
- **Token format**: `BC2.<salt>.<nonce>.<corpus_hash>.<ciphertext>` (base64url, versioned)
- **Key derivation**: Scrypt (n=2^17 by default, can be set higher for more security)
- **Auto-cleaning**: Project Gutenberg headers are stripped by default (can be disabled)
- **Status messages**: GUI provides real-time feedback; errors are surfaced to the user
- **Security**: Constant-time hash comparison, HKDF, random salt/nonce, authenticated encryption

## Integration & Dependencies
- **cryptography**: For AES-GCM, Scrypt, secure random
- **tkinter**: For GUI (macOS native)
- **pytest**: For tests
- **PyInstaller**: For app packaging

## Patterns & Examples
- All encryption/decryption logic flows through `cipher_core.py` (imported by both CLI and GUI)
- Book files must be plain .txt, UTF-8, and are auto-cleaned unless `--no-autoclean` is set
- GUI and CLI both require explicit book selection and passphrase
- See `README.md` for detailed CLI usage and options

## References
- [README.md](../README.md): Full usage, architecture, and security notes
- [THREAT_MODEL.md](../THREAT_MODEL.md): Security properties and attack scenarios
- [tests/test_cipher_core.py](../tests/test_cipher_core.py): Example test cases

---
**For AI agents:**
- Always respect corpus binding and token format conventions
- Prefer updating `cipher_core.py` for cryptographic changes
- When adding features, update both CLI and GUI if user-facing
- Use real book files from `books/` for integration tests
- Reference `README.md` for workflow and option details
