# BookCipher Security & Threat Model

## What BookCipher Protects Against ✅

### Confidentiality (Encryption)
- **Eavesdropping**: Ciphertext is unreadable without the correct key and books
- **AES-256-GCM**: Industry-standard authenticated encryption (same as used by governments, banks)
- **Key derivation**: Scrypt + HKDF makes brute-force attacks computationally expensive

### Integrity & Authenticity
- **Authentication tags**: AES-GCM detects if ciphertext was tampered with
- **Corpus binding**: Ciphertext fails to decrypt if book(s) are swapped or modified
- **Constant-time comparison**: Prevents timing attacks during corpus verification

### Key Management
- **Strong random salts & nonces**: Each encryption uses fresh 16-byte salt + 12-byte nonce
- **Memory-hard KDF**: Scrypt requires significant memory (resistant to GPU/ASIC brute-force)
- **Deterministic key derivation**: Same passphrase + salt = same key (allows recovery with key alone)

## What BookCipher Does NOT Protect Against ❌

### Physical/System Security
- **Keyloggers**: If your computer is compromised, keys can be intercepted before encryption
- **Screen capture**: Screenshots of plaintext or keys are not protected
- **Memory dumps**: If attacker has OS-level access, they can read memory while app runs
- **Malware**: Trojan horses or spyware can compromise the entire system

### Weak User Behavior
- **Weak passphrases**: "password", "123456", "qwerty" (we warn about these, but you can override)
- **Reused passwords**: Same key for multiple books/ciphertexts increases exposure
- **Poor key storage**: Writing passphrases on post-its or unencrypted files
- **Social engineering**: Attackers tricking you into revealing the key

### Implementation Risks
- **Zero-days**: Unknown vulnerabilities in cryptography library could be exploited
- **Side-channel attacks**: Timing/power analysis (minimal risk for this use case)
- **RNG compromise**: If `os.urandom()` is weak or unseeded (extremely unlikely on modern OS)

### Operational Risks
- **Ciphertext metadata**: Token itself doesn't hide message length or encryption time (unless padding is enabled)
- **Replay attacks**: Same ciphertext can be replayed by attacker (message_id allows external replay tracking)
- **Traffic analysis**: When you encrypt/decrypt can reveal patterns

## Security Assumptions

### Required for Correct Operation
1. **Trustworthy books**: Books in the corpus are what you expect (not modified)
2. **Good entropy**: `os.urandom()` provides cryptographically secure random bytes
3. **Library integrity**: cryptography library is not compromised
4. **Correct implementation**: No bugs in AES-GCM, Scrypt, or HKDF (as implemented by cryptography lib)

### Optional (Better Security)
- Strong passphrase (20+ chars, mixed case, numbers, symbols)
- Fresh salt for each encryption (automatic)
- Unique books per encryption (different corpus for different messages)

## Attack Scenarios

### Scenario 1: Attacker Has Ciphertext
**Goal**: Decrypt without key
**Barriers**:
- ✅ Brute-force passphrase: ~100ms per try (2^17 Scrypt cost) → 1M tries ≈ 27 hours on single CPU
- ✅ AES-256-GCM: Would need to break AES (not feasible with current math)
- ✅ Corpus binding: Changing books doesn't help (corpus hash won't match)

**Mitigation**: Use strong passphrase. If worried about brute-force, enable `--scrypt-strength high` (2^18, doubles the cost).

### Scenario 2: Attacker Knows Passphrase, Wants to Decrypt
**Goal**: Decrypt without books
**Barriers**:
- ✅ Corpus binding: Corpus hash embedded in token must match (prevents guessing)
- ✅ AES-GCM auth tag: Decryption fails if wrong corpus is used

**Mitigation**: If books are public (e.g., Alice in Wonderland), corpus is predictable. Security then relies entirely on passphrase + KDF.

### Scenario 3: Attacker Has Both Ciphertext and Books
**Goal**: Decrypt without key
**Barriers**:
- ✅ Strong passphrase: Even with correct corpus, brute-force is expensive
- ✅ Scrypt cost: n=2^17 requires 128 MB RAM per attempt (memory-hard)

**Mitigation**: Ensure passphrase is strong (score > 70/100).

### Scenario 4: Attacker Modifies Ciphertext
**Goal**: Inject malicious plaintext
**Barriers**:
- ✅ AES-GCM authentication tag: Modified ciphertext fails to decrypt (raises error)
- ✅ Constant-time comparison: Prevents timing attacks to guess hash

**Outcome**: Modification fails (ciphertext is tamper-evident).

## Comparison to Alternatives

| Feature | BookCipher | GPG | Signal | 7Zip |
|---------|-----------|-----|--------|------|
| **Cipher** | AES-256-GCM | AES-256, RSA | Double Ratchet | AES-256 |
| **KDF** | Scrypt+HKDF | SHA-1 (weak) | HKDF-SHA256 | AES (weak) |
| **Authenticated** | ✅ Yes (GCM) | ✅ Yes (DSA/RSA) | ✅ Yes (AEAD) | ✅ Yes (HMAC) |
| **User-friendly** | ✅ GUI + CLI | ❌ Complex | ✅ Good | ⚠️ Password-only |
| **Portable** | ⚠️ macOS only | ✅ All | ✅ All | ✅ All |
| **Code audited** | ❌ No | ✅ Yes | ✅ Yes | ⚠️ Partial |
| **Production use** | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes |

**BookCipher is best for**: Educational use, local file encryption, cryptographic learning.
**Not recommended for**: High-value data, adversarial environments, professional cryptography.

## Security Best Practices with BookCipher

1. **Choose strong passphrases**
   - Use the key strength meter (aim for "Very strong" / >80)
   - Include: uppercase, lowercase, numbers, special characters
   - Length: 20+ characters recommended
   - Avoid: dictionary words, personal info, common patterns

2. **Protect your books**
   - Public books are **not** secret; assume attacker knows them
   - If you use public books, your passphrase/KDF is the only secret
   - If you use private text, treat it as sensitive too

3. **Secure token storage**
   - Tokens are sensitive artifacts; treat them like secrets
   - Save tokens to encrypted drives or password-protected containers
   - Don't store in plain text files on unencrypted systems
   - Back up tokens securely if decryption is important

4. **Operational security**
   - Run on trusted, malware-free computer
   - Use on fully patched, updated OS
   - Don't type passphrases on untrusted keyboards/terminals
   - Clear clipboard after copying tokens
   - Wipe temporary files securely (swaps, temp folders)

### DO / DON’T (Quick Reference)

**DO**
- Use long passphrases (20+ chars) and strong KDF presets
- Enable padding if message length is sensitive
- Treat tokens as secrets; store on encrypted media
- Clear clipboard after copying tokens

**DON’T**
- Don’t assume public books are secret
- Don’t paste tokens or passphrases into shared chats or logs
- Don’t leave tokens in shell history on shared machines
- Don’t reuse the same passphrase across unrelated messages

5. **Testing & Validation**
   - Always test decryption immediately after encryption
   - Keep test vectors for regression testing
   - Don't assume old tokens will decrypt later (version changes)

6. **Upgrade considerations**
   - BC1 tokens are still supported but use weaker Scrypt (n=2^15)
   - Consider re-encrypting with BC2 for stronger security
   - Keep old versions if decrypting legacy tokens
   - BC2 tokens remain legacy-compatible; BC3 adds authenticated metadata (padding/message_id)

## Security Audit & Limitations

⚠️ **This code has NOT been professionally audited.**

- No external security review
- No formal verification proofs
- Implementation may contain subtle bugs
- Use at your own risk

For production systems or high-security needs, use professionally audited cryptography tools (GPG, Signal, etc.).

## Responsible Disclosure

If you find a security vulnerability, please report it responsibly:
1. Do NOT publish the vulnerability publicly
2. Email maintainers with details
3. Allow time for a fix before public disclosure
4. Do NOT use exploits maliciously
