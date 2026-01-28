from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

# ----------------------------
# Gutenberg auto-clean helpers
# ----------------------------

_START_RE = re.compile(r"\*\*\*\s*START OF (THE|THIS) PROJECT GUTENBERG EBOOK.*?\*\*\*", re.IGNORECASE | re.DOTALL)
_END_RE = re.compile(r"\*\*\*\s*END OF (THE|THIS) PROJECT GUTENBERG EBOOK.*?\*\*\*", re.IGNORECASE | re.DOTALL)


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


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive 32-byte key using Scrypt (memory-hard KDF) + HKDF.
    
    Security improvements:
    - Scrypt with n=2^17 (higher cost), r=8, p=1 for brute-force resistance
    - HKDF expansion for additional key derivation security
    - Larger salt (16 bytes = 128 bits)
    """
    if len(salt) != 16:
        raise ValueError("Salt must be exactly 16 bytes.")
    
    # Scrypt: memory-hard KDF (higher n = more compute & memory cost)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**17,  # Increased from 2^15 (4x stronger against brute-force)
        r=8,
        p=1,
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


def encrypt(plain: str, key: str, corpus: Corpus) -> str:
    """
    Returns compact token: BC2.<salt>.<nonce>.<corpushash>.<ciphertext>
    
    Security properties:
    - AES-256-GCM: authenticated encryption (AEAD)
    - Corpus hash as AAD: binds ciphertext to book set
    - Fresh random salt (16 bytes) & nonce (12 bytes) per encryption
    - Scrypt + HKDF for key derivation
    
    Raises ValueError if key is empty.
    """
    if not key or not key.strip():
        raise ValueError("Key is required.")

    salt = os.urandom(16)
    nonce = os.urandom(12)

    k = _derive_key(key, salt)
    aesgcm = AESGCM(k)

    aad = corpus.sha256
    ct = aesgcm.encrypt(nonce, plain.encode("utf-8"), aad)

    return ".".join([
        MAGIC,
        _b64u_encode(salt),
        _b64u_encode(nonce),
        _b64u_encode(corpus.sha256),
        _b64u_encode(ct),
    ])


def decrypt(token: str, key: str, corpus: Corpus) -> str:
    """
    Decrypt a BC2 token with security validation.
    
    Validation steps:
    1. Parse token format (5 parts)
    2. Verify corpus hash with constant-time comparison
    3. Derive key from salt
    4. Decrypt & verify authentication tag
    
    Raises ValueError if token format is invalid, corpus mismatches, or auth fails.
    """
    if not key or not key.strip():
        raise ValueError("Key is required.")

    parts = token.strip().split(".")
    if len(parts) != 5:
        raise ValueError("Ciphertext format invalid (expected 5 parts).")
    
    if parts[0] != MAGIC:
        raise ValueError(f"Unsupported token version: {parts[0]} (expected {MAGIC}).")

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

    k = _derive_key(key, salt)
    aesgcm = AESGCM(k)

    try:
        pt = aesgcm.decrypt(nonce, ct, corpus.sha256)
    except Exception:
        raise ValueError("Wrong key or ciphertext was modified (authentication failed).")

    return pt.decode("utf-8", errors="replace")

