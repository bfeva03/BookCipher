# Changelog

All notable changes to BookCipher are documented in this file.

## [2.0.0] - 2026-01-28

### Security Enhancements ✨
- **Scrypt strengthened**: Increased default n from 2^15 → 2^17 (4x stronger brute-force resistance)
- **HKDF key expansion**: Added HKDF-SHA256 layer for proper key stretching
- **Constant-time comparison**: Corpus hash verified using `hmac.compare_digest()` to prevent timing attacks
- **Token versioning**: Updated to BC2 format with version field for future compatibility
- **BC2 compatibility**: Preserve legacy BC2 AAD; BC3 uses domain-separated AAD
- **Input validation**: Added size checks for salt (16B) and nonce (12B)

### New Features 🎉
- **BC1 backward compatibility**: Decrypt legacy BC1 tokens with deprecation warning
- **Configurable Scrypt**: `--scrypt-strength normal|high` option (n=2^17 or n=2^18)
- **Weak key detection**: Automatic detection and warnings for weak passphrases
- **Key strength analysis**: Detailed scoring (0-100) with actionable suggestions
- **File I/O support**: 
  - `--input-file` to encrypt/decrypt from files
  - `--output-file` to save results to files
- **GUI threading**: Encrypt/decrypt now run in background threads (UI stays responsive)
- **Progress feedback**: Status messages during long operations
- **Copy-to-clipboard**: One-click copy of ciphertext tokens
- **Logging support**: `--verbose` flag for debug logging in CLI
- **Better error messages**: More specific error feedback for troubleshooting

### Code Quality 📝
- Added comprehensive unit tests (20+ test cases)
- Full type hints across codebase
- Improved error handling and validation
- Consistent logging throughout modules
- Better documentation of security properties

### Deprecations ⚠️
- BC1 tokens still supported but will emit `DeprecationWarning` on decrypt
- Recommend re-encrypting BC1 data with BC2 for stronger security

### Internal Changes
- Split encryption/decryption into configurable functions
- Added `check_key_strength()` utility function
- Refactored key derivation with optional Scrypt parameters
- Enhanced cipher_core module with logging infrastructure

## [1.0.0] - 2025-12-01

### Initial Release
- AES-256-GCM authenticated encryption
- Book-bound encryption with corpus hashing
- Scrypt key derivation (n=2^15)
- macOS Tkinter GUI app
- Python CLI interface
- Support for multiple books in corpus
- Project Gutenberg header auto-cleaning
- Optional key for deterministic encryption
- Dark theme UI with key strength meter
