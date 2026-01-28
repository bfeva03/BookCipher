from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import string
import warnings
from dataclasses import dataclass
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

# Logging setup
logger = logging.getLogger(__name__)

# ----------------------------
# Gutenberg auto-clean helpers
# ----------------------------

_START_RE = re.compile(
    r"\*\*\*\s*START OF (THE|THIS) PROJECT GUTENBERG EBOOK.*?\*\*\*",
    re.IGNORECASE | re.DOTALL,
)
_END_RE = re.compile(
    r"\*\*\*\s*END OF (THE|THIS) PROJECT GUTENBERG EBOOK.*?\*\*\*",
    re.IGNORECASE | re.DOTALL,
)


def clean_gutenberg_headers(text: str) -> str:
    """Remove Project Gutenberg headers/footers if markers exist."""
    m1 = _START_RE.search(text)
    m2 = _END_RE.search(text)
    if m1 and m2 and m2.start() > m1.end():
        return text[m1.end() : m2.start()].strip()
    return text


# ----------------------------
# Secure book-bound encryption
# ----------------------------

MAGIC = "BC2"  # token version prefix (incremented for security improvements)
MAGIC_BC1 = "BC1"  # legacy version (supported for backward compatibility)

# Scrypt parameters (configurable for different security levels)
SCRYPT_DEFAULT_N = 2**17  # Standard: ~100ms on modern CPU
SCRYPT_HIGH_N = 2**18  # High security: ~200ms on modern CPU
SCRYPT_R = 8
SCRYPT_P = 1


def check_key_strength(passphrase: str) -> tuple[int, list[str]]:
    """
    Analyze passphrase strength (0-100).
    Returns (score, warnings) where warnings are actionable suggestions.
    """
    warnings_list = []
    score = 0

    if not passphrase:
        return 0, ["Passphrase is empty"]

    length = len(passphrase)

    # Length score (0-40 points)
    if length < 8:
        warnings_list.append(f"Passphrase too short ({length}/12 chars recommended)")
        score += length * 5
    elif length < 12:
        score += 30
        warnings_list.append(f"Increase to 12+ chars for better security")
    else:
        score += 40

    # Character diversity (0-40 points)
    has_lower = any(c.islower() for c in passphrase)
    has_upper = any(c.isupper() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    has_special = any(not c.isalnum() for c in passphrase)

    char_classes = sum([has_lower, has_upper, has_digit, has_special])
    score += char_classes * 10

    if not has_lower:
        warnings_list.append("Add lowercase letters")
    if not has_upper:
        warnings_list.append("Add uppercase letters")
    if not has_digit:
        warnings_list.append("Add numbers")
    if not has_special:
        warnings_list.append("Add special characters (!@#$%)")

    # No common patterns (0-20 points)
    if passphrase.lower() not in ["password", "qwerty", "123456", "abc123", "letmein"]:
        score += 20
    else:
        warnings_list.append("This is a very common passphrase")

    return min(100, score), warnings_list


@dataclass(frozen=True)
class Corpus:
    text: str
    sha256: bytes  # 32 bytes


def build_corpus(book_texts: Iterable[str], autoclean: bool = True) -> Corpus:
    parts = []
    for t in book_texts:
        if autoclean:
            t = clean_gutenberg_headers(t)
        parts.append(t)

    corpus_text = "\n\n".join(parts)
    corpus_hash = hashlib.sha256(corpus_text.encode("utf-8", errors="replace")).digest()
    return Corpus(text=corpus_text, sha256=corpus_hash)


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("ascii"))


def _derive_key(passphrase: str, salt: bytes, scrypt_n: int = SCRYPT_DEFAULT_N) -> bytes:
    """
    Derive 32-byte key using Scrypt (memory-hard KDF) + HKDF.

    Args:
        passphrase: User-provided key
        salt: Random 16-byte salt
        scrypt_n: Scrypt cost parameter (2^15 to 2^18 supported)

    Security improvements:
    - Scrypt with configurable n for flexible security levels
    - HKDF expansion for additional key derivation security
    - 16-byte salt (128 bits)
    """
    if len(salt) != 16:
        raise ValueError("Salt must be exactly 16 bytes.")

    # Validate scrypt_n
    valid_n_values = [2**15, 2**16, 2**17, 2**18]
    if scrypt_n not in valid_n_values:
        raise ValueError(f"scrypt_n must be one of {valid_n_values}")

    logger.debug(f"Deriving key with Scrypt n={scrypt_n}")

    # Scrypt: memory-hard KDF (higher n = more compute & memory cost)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=scrypt_n,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    scrypt_key = kdf.derive(passphrase.encode("utf-8"))

    # HKDF expansion: additional security layer, proper key stretching
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"BookCipherAES256GCM",
    )
    final_key = hkdf.derive(scrypt_key)

    return final_key


def encrypt(plain: str, key: str, corpus: Corpus, scrypt_n: int = SCRYPT_DEFAULT_N) -> str:
    """
    Returns compact token: BC2.<salt>.<nonce>.<corpushash>.<ciphertext>

    Args:
        plain: Plaintext to encrypt
        key: Passphrase (required)
        corpus: Corpus object with text and hash
        scrypt_n: Scrypt cost parameter (default 2^17)

    Security properties:
    - AES-256-GCM: authenticated encryption (AEAD)
    - Corpus hash as AAD: binds ciphertext to book set
    - Fresh random salt (16 bytes) & nonce (12 bytes) per encryption
    - Scrypt + HKDF for key derivation

    Raises ValueError if key is empty.
    """
    if not key or not key.strip():
        raise ValueError("Key is required.")

    # Warn on weak keys
    score, key_warnings = check_key_strength(key)
    if score < 50:
        logger.warning(f"Weak passphrase detected (score: {score}): {'; '.join(key_warnings)}")

    salt = os.urandom(16)
    nonce = os.urandom(12)

    k = _derive_key(key, salt, scrypt_n)
    aesgcm = AESGCM(k)

    aad = corpus.sha256
    ct = aesgcm.encrypt(nonce, plain.encode("utf-8"), aad)

    logger.debug(f"Encrypted message, ciphertext size: {len(ct)} bytes")

    return ".".join(
        [
            MAGIC,
            _b64u_encode(salt),
            _b64u_encode(nonce),
            _b64u_encode(corpus.sha256),
            _b64u_encode(ct),
        ]
    )


def decrypt(token: str, key: str, corpus: Corpus) -> str:
    """
    Decrypt a BC2 or BC1 token with security validation.

    Args:
        token: Encrypted token (BC1 or BC2 format)
        key: Passphrase (required)
        corpus: Corpus object with text and hash

    Supports both BC1 (legacy) and BC2 (current) formats:
    - BC1 uses Scrypt n=2^15 (legacy, slower key derivation)
    - BC2 uses Scrypt n=2^17 + HKDF (current standard)

    Validation steps:
    1. Parse token format (5 parts)
    2. Determine token version (BC1 or BC2)
    3. Verify corpus hash with constant-time comparison
    4. Derive key from salt (with appropriate n value)
    5. Decrypt & verify authentication tag

    Raises ValueError if token format is invalid, corpus mismatches, or auth fails.
    """
    if not key or not key.strip():
        raise ValueError("Key is required.")

    parts = token.strip().split(".")
    if len(parts) != 5:
        raise ValueError("Ciphertext format invalid (expected 5 parts).")

    magic = parts[0]
    if magic not in [MAGIC, MAGIC_BC1]:
        raise ValueError(f"Unsupported token version: {magic} (expected BC1 or BC2).")

    # Warn if BC1 is used (legacy)
    if magic == MAGIC_BC1:
        warnings.warn(
            "BC1 tokens use legacy Scrypt parameters. Consider re-encrypting with BC2.",
            DeprecationWarning,
        )
        logger.info("Decrypting BC1 (legacy) token")
        scrypt_n = 2**15
    else:
        scrypt_n = SCRYPT_DEFAULT_N

    try:
        salt = _b64u_decode(parts[1])
        nonce = _b64u_decode(parts[2])
        token_corpus_hash = _b64u_decode(parts[3])
        ct = _b64u_decode(parts[4])
    except Exception as e:
        raise ValueError(f"Failed to decode token: {e}")

    # Constant-time comparison for corpus hash (prevents timing attacks)
    if not hmac.compare_digest(token_corpus_hash, corpus.sha256):
        raise ValueError("Wrong books or book order (corpus mismatch).")

    # Validate component sizes
    if len(salt) != 16:
        raise ValueError("Invalid salt size in token.")
    if len(nonce) != 12:
        raise ValueError("Invalid nonce size in token.")

    k = _derive_key(key, salt, scrypt_n)
    aesgcm = AESGCM(k)

    try:
        pt = aesgcm.decrypt(nonce, ct, corpus.sha256)
    except Exception:
        raise ValueError("Wrong key or ciphertext was modified (authentication failed).")

    logger.debug(f"Decrypted message, plaintext size: {len(pt)} bytes")
    return pt.decode("utf-8", errors="replace")
