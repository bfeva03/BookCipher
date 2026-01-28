# BookCipher Troubleshooting Guide

## Installation & Setup

### Q: "python: command not found" or "python3: command not found"
**Problem**: Python is not installed or not in your PATH.

**Solution**:
- Check if Python is installed: `which python3`
- Install Python via Homebrew: `brew install python@3.11`
- Verify installation: `python3 --version` (should show 3.8+)

### Q: "ModuleNotFoundError: No module named 'cryptography'"
**Problem**: Required cryptography library is not installed.

**Solution**:
```bash
pip install cryptography
# or for Python 3 specifically:
pip3 install cryptography
```

### Q: "ModuleNotFoundError: No module named 'cipher_core'"
**Problem**: Running CLI from wrong directory.

**Solution**:
```bash
cd /path/to/BookCipher/
python3 book_cipher.py --help
```

### Q: GUI app won't start (macOS)
**Problem**: App is unsigned or not verified.

**Solution**:
1. Right-click BookCipherApp.app
2. Click "Open"
3. Click "Open" again in the security dialog
4. Grant permission
(This is a one-time step for unsigned apps on macOS)

---

## Encryption / Decryption Errors

### Q: "Key is required"
**Problem**: You didn't provide a passphrase.

**Solution**:
- CLI: Add `--key "your_passphrase"`
- GUI: Click "Key:" field and type a passphrase
- Strength meter should show at least "OK" (score > 30)

### Q: "Plaintext is empty" or "Ciphertext is empty"
**Problem**: You tried to encrypt/decrypt without text.

**Solution**:
- **To encrypt**: Enter text in the plaintext field, then click "Encrypt →"
- **To decrypt**: Paste a token in the ciphertext field, then click "← Decrypt"

### Q: "Wrong key or ciphertext was modified (authentication failed)"
**Problem**: One of three things:
1. You used the wrong passphrase
2. The ciphertext token was corrupted or tampered with
3. The books changed (for corpus mismatch)

**Solution**:
- **Check passphrase**: Ensure you're using the EXACT key from encryption
  - Capitalization matters: "Key123" ≠ "key123"
  - Spaces matter: "my key" ≠ "mykey"
  - Special chars matter: "key!" ≠ "key"
- **Check token**: Copy the full token without extra spaces
  - Token format: `BC2.salt.nonce.hash.ciphertext` (5 dot-separated parts)
  - Common mistake: copying from word processors (adds invisible characters)
  - Solution: Use plain text editor or copy directly from app
- **Check books**: Decryption must use the SAME books in the SAME order
  - If books changed, corpus hash won't match
  - Solution: Use original book files and order

### Q: "Wrong books or book order (corpus mismatch)"
**Problem**: Books don't match token (different files or wrong order).

**Solution**:
- Use the EXACT same book files as encryption
  - File name must match (case-sensitive on Linux/Mac)
  - File content must be identical
  - **Helpful tip**: Both encrypted and decrypted ciphertext embed corpus hash
    - If books are wrong, this hash won't match
- Check book order:
  - If encrypted with books A, B, C → decrypt with A, B, C
  - Order A, C, B = different corpus = decryption fails
- Verify file wasn't modified:
  - Did you edit the book file? (any change breaks decryption)
  - Solution: Re-download original or use unmodified copy

### Q: "Unsupported token version: BC1"
**Problem**: You're trying to decrypt an old BC1 token (legacy format).

**Solution**:
- BC1 tokens still work but use weaker encryption (n=2^15 Scrypt)
- You should see a warning: "BC1 tokens use legacy Scrypt parameters"
- Decryption will succeed, but consider re-encrypting with BC2 for security
- To upgrade:
  ```bash
  # Decrypt BC1 token
  python3 book_cipher.py --book mybook.txt --key "mykey" decrypt --cipher "BC1.xxx..."
  
  # Save plaintext to file
  # Re-encrypt with BC2 (default)
  python3 book_cipher.py --book mybook.txt --key "mykey" encrypt --input-file plaintext.txt
  ```

### Q: "Ciphertext format invalid (expected 5 parts)"
**Problem**: Token is corrupted or incomplete.

**Solution**:
- Tokens must have format: `BC2.part1.part2.part3.part4`
- Check that you copied the ENTIRE token (all 5 parts)
- Common mistakes:
  - Truncated token (missing last part)
  - Extra spaces: `BC2.xxx . yyy . zzz` (spaces break parsing)
  - Wrong format: `BC1.xxx.yyy` (only 3 parts, need 5)
  - Solution: Copy token carefully, or use `--output-file` to save to a file

---

## Performance Issues

### Q: Encryption/decryption is very slow
**Problem**: This is expected! Scrypt is memory-hard on purpose.

**Details**:
- Default Scrypt (n=2^17): ~100ms on modern CPU
- High Scrypt (n=2^18): ~200ms on modern CPU
- This is a security feature (prevents brute-force)

**Solution**:
- If you need speed, you have two choices:
  1. Lower security: `--scrypt-strength normal` (default, already fast)
  2. Optimize hardware: Use newer, faster CPU
- **GUI users**: UI will be unresponsive during encryption
  - This is normal (we don't support threading yet in older versions)
  - Just wait ~100-200ms for operation to complete
  - Newer versions (v2.0+) use background threads (UI stays responsive)

### Q: GUI is frozen during encryption
**Problem**: Old version doesn't use threading.

**Solution**:
- Update to v2.0+ which has background threading
- Or use CLI for faster feedback:
  ```bash
  python3 book_cipher.py --book mybook.txt --key "key" encrypt --message "text" --verbose
  ```

---

## Key & Security Issues

### Q: "Weak passphrase detected"
**Problem**: Your key is not strong enough.

**Details**:
- Weak (<30): Very vulnerable to brute-force
- OK (30-60): Moderate security
- Strong (60-80): Good security
- Very strong (>80): Excellent security

**Solution**:
- Use longer passphrases (20+ chars recommended)
- Mix character types: uppercase, lowercase, numbers, special chars
- Example strong key: `Tr0pical!P@ssw0rd#2024`
- Avoid: dictionary words, personal info, repeating patterns

### Q: "Key strength: Empty"
**Problem**: You haven't entered a key yet.

**Solution**:
- Click the Key field and type a passphrase
- Watch the strength meter update as you type
- Aim for "Strong" or "Very strong" (score 60+)

### Q: "This is a very common passphrase"
**Problem**: Your key was detected as a common pattern.

**Examples of weak patterns**:
- `password`
- `123456`
- `qwerty`
- `letmein`
- `abc123`

**Solution**:
- Use a unique, non-dictionary passphrase
- Consider using a passphrase generator
- Or create a memorable phrase:
  - Instead of: `mypassword`
  - Use: `MyC4t_Fluffy@2024!`

---

## File I/O

### Q: "File not found: /path/to/book.txt"
**Problem**: Book file doesn't exist at that path.

**Solution**:
- Check the file path is correct
- Use absolute paths or relative from current directory
- Example:
  ```bash
  # Absolute path:
  python3 book_cipher.py --book "/Users/evan/Desktop/alice.txt" encrypt --message "Hi"
  
  # Relative path (from BookCipher folder):
  python3 book_cipher.py --book "./books/alice.txt" encrypt --message "Hi"
  ```

### Q: "Failed to read file: Permission denied"
**Problem**: You don't have read permission for the file.

**Solution**:
- Check file permissions: `ls -la filename.txt`
- Grant read permission:
  ```bash
  chmod 644 filename.txt
  ```

### Q: "Failed to write file: Permission denied"
**Problem**: You don't have write permission for the output directory.

**Solution**:
- Check directory permissions: `ls -ld dirname/`
- Grant write permission:
  ```bash
  chmod 755 dirname/
  ```

---

## Project Gutenberg

### Q: "Gutenberg headers still in decrypted text"
**Problem**: Autoclean is disabled or headers weren't detected.

**Solution**:
- Re-encrypt with autoclean enabled:
  ```bash
  python3 book_cipher.py --book book.txt --key "key" encrypt --message "text"
  # (autoclean is enabled by default)
  ```
- To disable autoclean (if you want to keep headers):
  ```bash
  python3 book_cipher.py --book book.txt --key "key" --no-autoclean encrypt --message "text"
  ```

### Q: "Downloaded book from Gutenberg, but autoclean didn't work"
**Problem**: Book headers might have different format than expected.

**Solution**:
1. Check header format in file:
   ```bash
   head -20 book.txt | grep "GUTENBERG"
   tail -20 book.txt | grep "GUTENBERG"
   ```
2. If markers are there but autoclean didn't work, manually remove headers:
   - Open file in text editor
   - Find lines with "*** START OF THE PROJECT GUTENBERG"
   - Delete everything before that line
   - Find lines with "*** END OF THE PROJECT GUTENBERG"
   - Delete everything after that line
   - Save and re-test

---

## CLI vs GUI

### Q: Should I use CLI or GUI?
**GUI is better if**:
- You're on macOS and want native app experience
- You prefer visual key strength meter
- You want to encrypt/decrypt one-off messages
- You're not comfortable with command line

**CLI is better if**:
- You want to encrypt many files
- You need to automate encryption in scripts
- You want to use custom Scrypt settings
- You're on Linux/Windows (GUI not available)

### Q: How do I enable verbose logging?
**Solution** (CLI only):
```bash
python3 book_cipher.py --book mybook.txt --key "key" --verbose encrypt --message "text"
# Shows debug info: Scrypt parameters, key derivation time, etc.
```

---

## Still Stuck?

1. **Check the error message carefully** — it usually tells you what's wrong
2. **Verify with a simple test**:
   ```bash
   echo "test message" > /tmp/test.txt
   python3 book_cipher.py --book books/alice.txt --key "test123" encrypt --input-file /tmp/test.txt
   # Copy token from output
   python3 book_cipher.py --book books/alice.txt --key "test123" decrypt --cipher "BC2.xxx..."
   ```
3. **Check prerequisites**:
   - Python 3.8+ installed
   - cryptography library installed (`pip3 install cryptography`)
   - You're in the BookCipher directory

4. **Report bugs** (if you think you found one):
   - Run with `--verbose` flag to get debug info
   - Include: OS, Python version, exact command, full error message
   - Don't include passwords/plaintext in bug reports!

