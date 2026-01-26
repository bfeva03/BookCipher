#!/usr/bin/env python3
import argparse
import random
import re
from pathlib import Path

# Message tokenizer: words OR non-words (spaces/punct/etc.)
TOKEN_RE = re.compile(r"([A-Za-z0-9']+|[^A-Za-z0-9']+)")
BOOK_WORD_RE = re.compile(r"[a-z0-9']+")

# --- Compact token format (no spaces, hides W/C) ---
# We encode each token as an integer:
#   value = (index << 3) | (capcode << 1) | typebit
#
# typebit: 1 = WORD token, 0 = CHAR token
# capcode (only meaningful for WORD tokens):
#   0 = lower, 1 = Title, 2 = UPPER, 3 = reserved
#
# Tokens are then base36-encoded and joined with '.' => no spaces => no quotes needed.

BASE36_ALPH = "0123456789abcdefghijklmnopqrstuvwxyz"


def b36_encode(n: int) -> str:
    if n < 0:
        raise ValueError("Cannot base36-encode negative numbers")
    if n == 0:
        return "0"
    out = []
    while n:
        n, r = divmod(n, 36)
        out.append(BASE36_ALPH[r])
    return "".join(reversed(out))


def b36_decode(s: str) -> int:
    s = s.strip().lower()
    if not s:
        raise ValueError("Empty base36 token")
    n = 0
    for ch in s:
        if ch not in BASE36_ALPH:
            raise ValueError(f"Invalid base36 character: {ch!r}")
        n = n * 36 + BASE36_ALPH.index(ch)
    return n


def load_book(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def book_words(text: str) -> list[str]:
    return BOOK_WORD_RE.findall(text.lower())


def build_word_index(words: list[str]) -> dict[str, list[int]]:
    idx: dict[str, list[int]] = {}
    for i, w in enumerate(words):
        idx.setdefault(w, []).append(i)
    return idx


def build_char_index(text: str) -> dict[str, list[int]]:
    idx: dict[str, list[int]] = {}
    for i, ch in enumerate(text):
        idx.setdefault(ch, []).append(i)
    return idx


def tokenize_message(msg: str) -> list[str]:
    return TOKEN_RE.findall(msg)


def capcode_for(word: str) -> int | None:
    """Return capcode for supported patterns, else None (means: encode as chars)."""
    if word.islower():
        return 0
    if word.isupper():
        return 2
    # Title-case-ish: first letter uppercase, rest lowercase
    if len(word) >= 1 and word[0].isupper() and word[1:].islower():
        return 1
    return None


def apply_capcode(word_lower: str, capcode: int) -> str:
    if capcode == 0:
        return word_lower
    if capcode == 1:
        return word_lower.capitalize()
    if capcode == 2:
        return word_lower.upper()
    return word_lower  # reserved / fallback


def pack_token(index: int, typebit: int, capcode: int = 0) -> str:
    value = (index << 3) | ((capcode & 0b11) << 1) | (typebit & 0b1)
    return b36_encode(value)


def unpack_token(tok: str) -> tuple[int, int, int]:
    value = b36_decode(tok)
    typebit = value & 0b1
    capcode = (value >> 1) & 0b11
    index = value >> 3
    return index, typebit, capcode


def encrypt(book_text: str, message: str) -> str:
    words = book_words(book_text)
    widx = build_word_index(words)
    cidx = build_char_index(book_text)

    packed_tokens: list[str] = []

    for token in tokenize_message(message):
        # Word chunk?
        if re.fullmatch(r"[A-Za-z0-9']+", token):
            key = token.lower()
            cc = capcode_for(token)

            # Only use WORD token if:
            # - word exists in book AND
            # - cap pattern is supported (lower/title/upper)
            if key in widx and cc is not None:
                wi = random.choice(widx[key])
                packed_tokens.append(pack_token(wi, typebit=1, capcode=cc))
            else:
                # fallback: encode exact characters so we preserve weird casing perfectly
                for ch in token:
                    if ch not in cidx:
                        raise ValueError(f"Character {ch!r} not found in book text.")
                    ci = random.choice(cidx[ch])
                    packed_tokens.append(pack_token(ci, typebit=0, capcode=0))
        else:
            # Non-word chunk (spaces/punct): encode char-by-char
            for ch in token:
                if ch not in cidx:
                    raise ValueError(f"Character {ch!r} not found in book text.")
                ci = random.choice(cidx[ch])
                packed_tokens.append(pack_token(ci, typebit=0, capcode=0))

    # No spaces => no quotes needed
    return ".".join(packed_tokens)


def decrypt(book_text: str, cipher: str) -> str:
    words = book_words(book_text)

    out_parts: list[str] = []
    if not cipher.strip():
        return ""

    for tok in cipher.strip().split("."):
        index, typebit, capcode = unpack_token(tok)
        if typebit == 0:
            # CHAR
            if index < 0 or index >= len(book_text):
                raise ValueError(f"Char index out of range: {index}")
            out_parts.append(book_text[index])
        else:
            # WORD
            if index < 0 or index >= len(words):
                raise ValueError(f"Word index out of range: {index}")
            w = words[index]  # lower
            out_parts.append(apply_capcode(w, capcode))

    return "".join(out_parts)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Hybrid book cipher: word-index when possible, char fallback always. Compact ciphertext (no spaces) hides token types."
    )
    ap.add_argument("--book", required=True, help="Path to a UTF-8 .txt book file (interchangeable)")
    ap.add_argument("--key", default="", help="Optional key (seed) for repeatable encryption")
    sub = ap.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a message")
    enc.add_argument("--message", help="Message to encrypt (if omitted, you’ll be prompted)")

    dec = sub.add_parser("decrypt", help="Decrypt ciphertext")
    dec.add_argument("--cipher", help="Ciphertext (no quotes needed). If omitted, you’ll be prompted.")

    args = ap.parse_args()

    book_text = load_book(Path(args.book))

    if args.key:
        random.seed(args.key)

    if args.cmd == "encrypt":
        msg = args.message if args.message is not None else input("Message to encrypt: ")
        print(encrypt(book_text, msg))
        return 0

    if args.cmd == "decrypt":
        c = args.cipher if args.cipher is not None else input("Paste ciphertext: ").strip()
        print(decrypt(book_text, c))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
