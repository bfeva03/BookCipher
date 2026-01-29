from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import struct
import uuid
import warnings
from dataclasses import dataclass
from typing import Iterable, Optional

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
MAGIC_BC3 = "BC3"  # padding + optional message_id metadata
MAGIC_BC1 = "BC1"  # legacy version (supported for backward compatibility)

# Scrypt parameters (configurable for different security levels)
SCRYPT_LEGACY_N = 2**15  # Legacy (BC1)
SCRYPT_MIN_N = 2**16  # Minimum for non-legacy operation
SCRYPT_DEFAULT_N = 2**17  # Standard: ~100ms on modern CPU
SCRYPT_HIGH_N = 2**18  # High security: ~200ms on modern CPU
SCRYPT_R = 8
SCRYPT_P = 1

SCRYPT_PRESETS = {
    "low": (2**16, 8, 1),
    "medium": (2**17, 8, 1),
    "high": (2**18, 8, 1),
}

# Padding
PADDING_OFF = "off"
PADDING_BLOCK = "block"
PADDING_POW2 = "pow2"
PADDING_MODES = {
    PADDING_OFF: 0,
    PADDING_BLOCK: 1,
    PADDING_POW2: 2,
}
PADDING_MODES_BY_CODE = {v: k for k, v in PADDING_MODES.items()}
PADDING_BLOCK_DEFAULT = 4096
PADDING_POW2_MIN = 256
PADDING_BLOCK_SIZE_MAX = 16 * 1024 * 1024
PADDING_PADDED_LEN_MAX = 2**32

_META_VERSION = 1
_META_STRUCT = struct.Struct(">BBII16s")

AAD_BC3_PREFIX = b"BookCipher:BC3:"


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


@dataclass(frozen=True)
class ScryptParams:
    n: int
    r: int
    p: int
    label: str = "custom"


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


def _validate_scrypt_params(n: int, r: int, p: int, allow_weak: bool = False) -> None:
    if n < SCRYPT_LEGACY_N:
        raise ValueError("scrypt_n too small (must be >= 2^15).")
    if (n & (n - 1)) != 0:
        raise ValueError("scrypt_n must be a power of two.")
    if n < SCRYPT_MIN_N and not allow_weak:
        raise ValueError("scrypt_n too low; use allow_weak_kdf to override.")
    if r <= 0 or p <= 0:
        raise ValueError("scrypt_r and scrypt_p must be positive.")


def _resolve_scrypt_params(
    *,
    scrypt_strength: Optional[str],
    scrypt_n: int,
    scrypt_r: int,
    scrypt_p: int,
    allow_weak_kdf: bool,
) -> ScryptParams:
    if scrypt_strength:
        if scrypt_strength not in SCRYPT_PRESETS:
            raise ValueError(f"Unknown scrypt_strength: {scrypt_strength}")
        n, r, p = SCRYPT_PRESETS[scrypt_strength]
        _validate_scrypt_params(n, r, p, allow_weak_kdf)
        return ScryptParams(n=n, r=r, p=p, label=scrypt_strength)

    _validate_scrypt_params(scrypt_n, scrypt_r, scrypt_p, allow_weak_kdf)
    return ScryptParams(n=scrypt_n, r=scrypt_r, p=scrypt_p, label="custom")


def _derive_key(
    passphrase: str,
    salt: bytes,
    *,
    scrypt_params: ScryptParams,
    allow_weak_kdf: bool = False,
) -> bytes:
    """
    Derive 32-byte key using Scrypt (memory-hard KDF) + HKDF.

    Args:
        passphrase: User-provided key
        salt: Random 16-byte salt
        scrypt_params: Scrypt params (n, r, p)

    Security improvements:
    - Scrypt with configurable n for flexible security levels
    - HKDF expansion for additional key derivation security
    - 16-byte salt (128 bits)
    """
    if len(salt) != 16:
        raise ValueError("Salt must be exactly 16 bytes.")

    _validate_scrypt_params(scrypt_params.n, scrypt_params.r, scrypt_params.p, allow_weak_kdf)

    logger.debug(f"Deriving key with Scrypt n={scrypt_params.n}, r={scrypt_params.r}, p={scrypt_params.p}")

    # Scrypt: memory-hard KDF (higher n = more compute & memory cost)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=scrypt_params.n,
        r=scrypt_params.r,
        p=scrypt_params.p,
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


def _normalize_padding_mode(mode: str) -> str:
    if mode not in PADDING_MODES:
        raise ValueError(f"padding must be one of {list(PADDING_MODES.keys())}")
    return mode


def _compute_padded_length(orig_len: int, mode: str, block_size: int) -> int:
    if mode == PADDING_OFF:
        return orig_len
    if mode == PADDING_BLOCK:
        if block_size <= 0 or block_size > PADDING_BLOCK_SIZE_MAX:
            raise ValueError("padding_block_size out of range")
        padded_len = ((orig_len + block_size - 1) // block_size) * block_size
        if padded_len > PADDING_PADDED_LEN_MAX:
            raise ValueError("padded length out of range")
        return padded_len
    if mode == PADDING_POW2:
        target = max(orig_len, 1)
        pow2 = 1 << (target - 1).bit_length()
        padded_len = max(PADDING_POW2_MIN, pow2)
        if padded_len > PADDING_PADDED_LEN_MAX:
            raise ValueError("padded length out of range")
        return padded_len
    raise ValueError("Unknown padding mode")


def _resolve_message_id(message_id: Optional[str] | bool) -> Optional[uuid.UUID]:
    if message_id is None:
        return None
    if message_id is True or message_id == "auto":
        return uuid.uuid4()
    try:
        msg_uuid = uuid.UUID(message_id)
    except Exception:
        raise ValueError("message_id must be a valid UUIDv4 string or 'auto'")
    if msg_uuid.version != 4:
        raise ValueError("message_id must be UUIDv4")
    return msg_uuid


def _encode_metadata(
    *,
    padding_mode: str,
    orig_len: int,
    padding_block_size: int,
    message_id: Optional[uuid.UUID],
) -> bytes:
    if orig_len < 0 or orig_len > 0xFFFFFFFF:
        raise ValueError("Plaintext length out of range for metadata.")
    if padding_mode == PADDING_BLOCK:
        if padding_block_size <= 0 or padding_block_size > PADDING_BLOCK_SIZE_MAX:
            raise ValueError("padding_block_size out of range")
    else:
        if padding_block_size != 0:
            raise ValueError("padding_block_size must be 0 for non-block padding")
        padding_block_size = 0
    msg_bytes = message_id.bytes if message_id else b"\x00" * 16
    return _META_STRUCT.pack(
        _META_VERSION,
        PADDING_MODES[padding_mode],
        orig_len,
        padding_block_size,
        msg_bytes,
    )


def _decode_metadata(meta: bytes) -> dict:
    if len(meta) != _META_STRUCT.size:
        raise ValueError("Invalid metadata size.")
    version, pad_code, orig_len, block_size, msg_bytes = _META_STRUCT.unpack(meta)
    if version != _META_VERSION:
        raise ValueError("Unsupported metadata version.")
    padding_mode = PADDING_MODES_BY_CODE.get(pad_code)
    if padding_mode is None:
        raise ValueError("Invalid padding mode.")
    if padding_mode == PADDING_BLOCK:
        if block_size <= 0 or block_size > PADDING_BLOCK_SIZE_MAX:
            raise ValueError("padding_block_size out of range")
    else:
        if block_size != 0:
            raise ValueError("padding_block_size must be 0 for non-block padding")
        block_size = 0
    padded_len = _compute_padded_length(orig_len, padding_mode, block_size or PADDING_BLOCK_DEFAULT)
    if orig_len > padded_len or padded_len > PADDING_PADDED_LEN_MAX:
        raise ValueError("Invalid original length.")
    message_id = None
    if msg_bytes != b"\x00" * 16:
        msg_uuid = uuid.UUID(bytes=msg_bytes)
        if msg_uuid.version != 4:
            raise ValueError("Invalid message_id version.")
        message_id = str(msg_uuid)
    return {
        "padding_mode": padding_mode,
        "orig_len": orig_len,
        "padding_block_size": block_size,
        "message_id": message_id,
    }


def get_token_metadata(token: str) -> dict:
    """Parse metadata from BC3 tokens; returns empty dict for BC1/BC2."""
    parts = token.strip().split(".")
    if len(parts) == 6 and parts[0] == MAGIC_BC3:
        try:
            meta = _b64u_decode(parts[4])
        except Exception as e:
            raise ValueError(f"Failed to decode metadata: {e}")
        return _decode_metadata(meta)
    return {}


def decrypt_with_metadata(
    token: str,
    key: str,
    corpus: Corpus,
    *,
    scrypt_strength: Optional[str] = None,
    scrypt_n: int = SCRYPT_DEFAULT_N,
    scrypt_r: int = SCRYPT_R,
    scrypt_p: int = SCRYPT_P,
    allow_weak_kdf: bool = False,
) -> tuple[str, dict]:
    """Decrypt and return (plaintext, metadata) for BC3 tokens."""
    parts = token.strip().split(".")
    if len(parts) == 6 and parts[0] == MAGIC_BC3:
        meta = get_token_metadata(token)
    else:
        meta = {}
    return (
        decrypt(
            token,
            key,
            corpus,
            scrypt_strength=scrypt_strength,
            scrypt_n=scrypt_n,
            scrypt_r=scrypt_r,
            scrypt_p=scrypt_p,
            allow_weak_kdf=allow_weak_kdf,
        ),
        meta,
    )


def encrypt(
    plain: str,
    key: str,
    corpus: Corpus,
    scrypt_n: int = SCRYPT_DEFAULT_N,
    *,
    scrypt_strength: Optional[str] = None,
    scrypt_r: int = SCRYPT_R,
    scrypt_p: int = SCRYPT_P,
    allow_weak_kdf: bool = False,
    padding: str = PADDING_OFF,
    padding_block_size: int = PADDING_BLOCK_DEFAULT,
    message_id: Optional[str] | bool = None,
) -> str:
    """
    Returns compact token: BC2.<salt>.<nonce>.<corpushash>.<ciphertext>

    Args:
        plain: Plaintext to encrypt
        key: Passphrase (required)
        corpus: Corpus object with text and hash
        scrypt_n: Scrypt cost parameter (default 2^17)
        scrypt_strength: Preset strength ("low" | "medium" | "high")
        padding: "off" | "block" | "pow2"
        padding_block_size: Block size for padding="block"
        message_id: UUIDv4 string or "auto" to generate one

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

    padding = _normalize_padding_mode(padding)
    msg_uuid = _resolve_message_id(message_id)
    scrypt_params = _resolve_scrypt_params(
        scrypt_strength=scrypt_strength,
        scrypt_n=scrypt_n,
        scrypt_r=scrypt_r,
        scrypt_p=scrypt_p,
        allow_weak_kdf=allow_weak_kdf,
    )

    k = _derive_key(key, salt, scrypt_params=scrypt_params, allow_weak_kdf=allow_weak_kdf)
    aesgcm = AESGCM(k)

    plain_bytes = plain.encode("utf-8")
    orig_len = len(plain_bytes)
    padded_len = _compute_padded_length(orig_len, padding, padding_block_size)
    pad_len = padded_len - len(plain_bytes)
    if pad_len < 0:
        raise ValueError("Padding computation error.")
    if pad_len:
        plain_bytes += os.urandom(pad_len)

    if padding != PADDING_OFF or msg_uuid is not None:
        meta_block_size = padding_block_size if padding == PADDING_BLOCK else 0
        meta = _encode_metadata(
            padding_mode=padding,
            orig_len=orig_len,
            padding_block_size=meta_block_size,
            message_id=msg_uuid,
        )
        aad = AAD_BC3_PREFIX + corpus.sha256 + meta
        ct = aesgcm.encrypt(nonce, plain_bytes, aad)
        logger.debug(f"Encrypted message, ciphertext size: {len(ct)} bytes")
        return ".".join(
            [
                MAGIC_BC3,
                _b64u_encode(salt),
                _b64u_encode(nonce),
                _b64u_encode(corpus.sha256),
                _b64u_encode(meta),
                _b64u_encode(ct),
            ]
        )

    aad = corpus.sha256
    ct = aesgcm.encrypt(nonce, plain_bytes, aad)

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


def decrypt(
    token: str,
    key: str,
    corpus: Corpus,
    *,
    scrypt_strength: Optional[str] = None,
    scrypt_n: int = SCRYPT_DEFAULT_N,
    scrypt_r: int = SCRYPT_R,
    scrypt_p: int = SCRYPT_P,
    allow_weak_kdf: bool = False,
) -> str:
    """
    Decrypt a BC2 or BC1 token with security validation.

    Args:
        token: Encrypted token (BC1 or BC2 format)
        key: Passphrase (required)
        corpus: Corpus object with text and hash

    Supports BC1 (legacy), BC2, and BC3 (metadata) formats:
    - BC1 uses Scrypt n=2^15 (legacy, slower key derivation)
    - BC2 uses Scrypt (current standard)
    - BC3 uses Scrypt + authenticated metadata (padding/message_id)

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
    if len(parts) not in (5, 6):
        raise ValueError("Ciphertext format invalid (expected 5 or 6 parts).")

    magic = parts[0]
    if magic not in [MAGIC, MAGIC_BC1, MAGIC_BC3]:
        raise ValueError(f"Unsupported token version: {magic} (expected BC1, BC2, or BC3).")

    # Warn if BC1 is used (legacy)
    if magic == MAGIC_BC1:
        warnings.warn(
            "BC1 tokens use legacy Scrypt parameters. Consider re-encrypting with BC2.",
            DeprecationWarning,
        )
        logger.info("Decrypting BC1 (legacy) token")
        scrypt_params = ScryptParams(n=SCRYPT_LEGACY_N, r=SCRYPT_R, p=SCRYPT_P, label="legacy")
        allow_weak_kdf = True
    else:
        scrypt_params = _resolve_scrypt_params(
            scrypt_strength=scrypt_strength,
            scrypt_n=scrypt_n,
            scrypt_r=scrypt_r,
            scrypt_p=scrypt_p,
            allow_weak_kdf=allow_weak_kdf,
        )

    try:
        salt = _b64u_decode(parts[1])
        nonce = _b64u_decode(parts[2])
        token_corpus_hash = _b64u_decode(parts[3])
        if magic == MAGIC_BC3:
            meta = _b64u_decode(parts[4])
            ct = _b64u_decode(parts[5])
        else:
            meta = b""
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

    k = _derive_key(key, salt, scrypt_params=scrypt_params, allow_weak_kdf=allow_weak_kdf)
    aesgcm = AESGCM(k)

    aad = corpus.sha256
    meta_info = None
    if magic == MAGIC_BC3:
        meta_info = _decode_metadata(meta)
        aad = AAD_BC3_PREFIX + corpus.sha256 + meta

    try:
        pt = aesgcm.decrypt(nonce, ct, aad)
    except Exception:
        raise ValueError("Wrong key or ciphertext was modified (authentication failed).")

    if magic == MAGIC_BC3 and meta_info is not None:
        padded_len = _compute_padded_length(
            meta_info["orig_len"],
            meta_info["padding_mode"],
            meta_info["padding_block_size"],
        )
        if len(pt) != padded_len:
            raise ValueError("Invalid padding length.")
        pt = pt[: meta_info["orig_len"]]

    logger.debug(f"Decrypted message, plaintext size: {len(pt)} bytes")
    return pt.decode("utf-8", errors="replace")
