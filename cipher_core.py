from __future__ import annotations

import base64
import hashlib
import os
import re
from dataclasses import dataclass
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

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

MAGIC = "BC1"  # token version prefix


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
    # Scrypt: brute-force resistant vs naive hashing
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plain: str, key: str, corpus: Corpus) -> str:
    """
    Returns compact no-space token:
    BC1.<salt>.<nonce>.<corpushash>.<ciphertext>

    AES-GCM provides authentication (tamper/wrong key -> fail)
    Corpus hash binds ciphertext to the chosen books.
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
    if not key or not key.strip():
        raise ValueError("Key is required.")

    parts = token.strip().split(".")
    if len(parts) != 5 or parts[0] != MAGIC:
        raise ValueError("Ciphertext format invalid.")

    salt = _b64u_decode(parts[1])
    nonce = _b64u_decode(parts[2])
    token_corpus_hash = _b64u_decode(parts[3])
    ct = _b64u_decode(parts[4])

    if token_corpus_hash != corpus.sha256:
        raise ValueError("Wrong books or book order (corpus mismatch).")

    k = _derive_key(key, salt)
    aesgcm = AESGCM(k)

    try:
        pt = aesgcm.decrypt(nonce, ct, corpus.sha256)
    except Exception:
        raise ValueError("Wrong key or ciphertext was modified (authentication failed).")

    return pt.decode("utf-8", errors="replace")

