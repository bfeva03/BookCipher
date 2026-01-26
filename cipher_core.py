from __future__ import annotations

import random
import re
from pathlib import Path

# Message tokenizer: words OR non-words (spaces/punct/etc.)
TOKEN_RE = re.compile(r"([A-Za-z0-9']+|[^A-Za-z0-9']+)")
BOOK_WORD_RE = re.compile(r"[a-z0-9']+")
BASE36_ALPH = "0123456789abcdefghijklmnopqrstuvwxyz"


# -------------------------
# Base36 helpers
# -------------------------
def b36_encode(n: int) -> str:
    if n < 0:
        raise ValueError("negative")
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
        raise ValueError("empty token")
    n = 0
    for ch in s:
        if ch not in BASE36_ALPH:
            raise ValueError(f"bad base36 char: {ch!r}")
        n = n * 36 + BASE36_ALPH.index(ch)
    return n


# -------------------------
# Gutenberg cleaner
# -------------------------
def strip_gutenberg(text: str) -> str:
    """
    Remove Project Gutenberg header/footer if present.
    If markers aren't found, returns original text.
    """
    start_markers = [
        "*** START OF THIS PROJECT GUTENBERG EBOOK",
        "*** START OF THE PROJECT GUTENBERG EBOOK",
        "***START OF THIS PROJECT GUTENBERG EBOOK",
        "*** START OF PROJECT GUTENBERG EBOOK",
    ]
    end_markers = [
        "*** END OF THIS PROJECT GUTENBERG EBOOK",
        "*** END OF THE PROJECT GUTENBERG EBOOK",
        "***END OF THIS PROJECT GUTENBERG EBOOK",
        "*** END OF PROJECT GUTENBERG EBOOK",
    ]

    upper = text.upper()

    start_pos = None
    for m in start_markers:
        p = upper.find(m)
        if p != -1:
            nl = text.find("\n", p)
            start_pos = (nl + 1) if nl != -1 else p
            break

    end_pos = None
    for m in end_markers:
        p = upper.find(m)
        if p != -1:
            end_pos = p
            break

    if start_pos is not None and end_pos is not None and end_pos > start_pos:
        return text[start_pos:end_pos].strip()

    return text


def load_book_text(path: str | Path, *, autoclean: bool = True) -> str:
    p = Path(path)
    raw = p.read_text(encoding="utf-8", errors="replace")
    return strip_gutenberg(raw) if autoclean else raw


def load_multiple_books(paths: list[str], *, autoclean: bool = True) -> str:
    """
    Load and combine multiple .txt books into one corpus.
    Auto-strips Gutenberg header/footer for each book.
    """
    parts = []
    for p in paths:
        parts.append(load_book_text(p, autoclean=autoclean))
    sep = "\n\n" + ("-" * 80) + "\n\n"
    return sep.join(parts) + "\n"


# -------------------------
# Indexing helpers
# -------------------------
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


# -------------------------
# Capitalization handling
# -------------------------
def capcode_for(word: str) -> int | None:
    """
    0=lower, 1=Title, 2=UPPER.
    If weird mixed caps (iPhone), return None -> char fallback to preserve perfectly.
    """
    if word.islower():
        return 0
    if word.isupper():
        return 2
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
    return word_lower


# -------------------------
# Compact token format (no W/C shown, no spaces)
# value = (index << 3) | (capcode<<1) | typebit
# typebit: 1=WORD, 0=CHAR
# capcode used only for WORD
# -------------------------
def pack_token(index: int, typebit: int, capcode: int = 0) -> str:
    value = (index << 3) | ((capcode & 0b11) << 1) | (typebit & 0b1)
    return b36_encode(value)


def unpack_token(tok: str) -> tuple[int, int, int]:
    value = b36_decode(tok)
    typebit = value & 0b1
    capcode = (value >> 1) & 0b11
    index = value >> 3
    return index, typebit, capcode


# -------------------------
# Encrypt / decrypt
# -------------------------
def encrypt(book_text: str, message: str, *, key: str = "") -> str:
    """
    Encrypt into compact ciphertext with '.' separators (no spaces).
    Optional key seeds randomness for repeatable output.
    """
    if key:
        random.seed(key)

    words = book_words(book_text)
    widx = build_word_index(words)
    cidx = build_char_index(book_text)

    packed_tokens: list[str] = []

    for token in tokenize_message(message):
        # word chunk?
        if re.fullmatch(r"[A-Za-z0-9']+", token):
            k = token.lower()
            cc = capcode_for(token)

            if k in widx and cc is not None:
                wi = random.choice(widx[k])
                packed_tokens.append(pack_token(wi, typebit=1, capcode=cc))
            else:
                # fallback to chars to preserve exact spelling/case
                for ch in token:
                    if ch not in cidx:
                        raise ValueError(f"Character {ch!r} not found in book.")
                    packed_tokens.append(pack_token(random.choice(cidx[ch]), typebit=0))
        else:
            # punctuation/spaces
            for ch in token:
                if ch not in cidx:
                    raise ValueError(f"Character {ch!r} not found in book.")
                packed_tokens.append(pack_token(random.choice(cidx[ch]), typebit=0))

    return ".".join(packed_tokens)


def decrypt(book_text: str, cipher: str) -> str:
    words = book_words(book_text)
    out: list[str] = []

    cipher = cipher.strip()
    if not cipher:
        return ""

    for tok in cipher.split("."):
        index, typebit, capcode = unpack_token(tok)
        if typebit == 0:
            if index < 0 or index >= len(book_text):
                raise ValueError(f"Char index out of range: {index}")
            out.append(book_text[index])
        else:
            if index < 0 or index >= len(words):
                raise ValueError(f"Word index out of range: {index}")
            out.append(apply_capcode(words[index], capcode))

    return "".join(out)
