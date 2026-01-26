import re
import random

BOOK_FILE = "alice.txt"

# Tokenizer: keeps words AND separators (spaces/punctuation) in order
TOKEN_RE = re.compile(r"([A-Za-z0-9']+|[^A-Za-z0-9']+)")

def load_book(filename):
    return open(filename, "r", encoding="utf-8", errors="replace").read()

def book_words(text):
    # Only words, used for W-index
    return re.findall(r"[a-z0-9']+", text.lower())

def build_word_index(words):
    idx = {}
    for i, w in enumerate(words):
        idx.setdefault(w, []).append(i)
    return idx

def build_char_index(text):
    idx = {}
    for i, ch in enumerate(text):
        idx.setdefault(ch, []).append(i)
    return idx

def tokenize_message(msg):
    return TOKEN_RE.findall(msg)

def encrypt(book_text, message):
    words = book_words(book_text)
    widx = build_word_index(words)
    cidx = build_char_index(book_text)

    cipher_tokens = []
    for tok in tokenize_message(message):
        # If it's a word chunk
        if re.fullmatch(r"[A-Za-z0-9']+", tok):
            key = tok.lower()
            if key in widx:
                cipher_tokens.append(f"W{random.choice(widx[key])}")
            else:
                # fallback to chars for this word
                for ch in tok:
                    if ch not in cidx:
                        raise ValueError(f"Character {ch!r} not found in book.")
                    cipher_tokens.append(f"C{random.choice(cidx[ch])}")
        else:
            # Non-word chunk (spaces/punctuation): encode as chars so it’s reversible
            for ch in tok:
                if ch not in cidx:
                    raise ValueError(f"Character {ch!r} not found in book.")
                cipher_tokens.append(f"C{random.choice(cidx[ch])}")
    return cipher_tokens

def decrypt(book_text, cipher_tokens):
    words = book_words(book_text)

    out_parts = []
    for item in cipher_tokens:
        if item.startswith("W"):
            out_parts.append(words[int(item[1:])])
        elif item.startswith("C"):
            out_parts.append(book_text[int(item[1:])])
        else:
            raise ValueError(f"Bad token: {item!r}")

    # Join chars/words back exactly as produced
    # Note: W tokens decrypt to lowercase words from the book.
    return "".join(out_parts)

def main():
    book_text = load_book(BOOK_FILE)

    mode = input("Type 'e' to encrypt or 'd' to decrypt: ").strip().lower()
key_text = input("Optional key (press Enter for random): ").strip()
if key_text:
    random.seed(key_text)
    if mode == "e":
        msg = input("Message to encrypt: ")
        result = encrypt(book_text, msg)
        print("Encrypted message:")
        print(" ".join(result))

    elif mode == "d":
        data = input("Paste cipher tokens: ").strip()
        tokens = data.split()
        print("Decrypted message:")
        print(decrypt(book_text, tokens))

    else:
        print("Please type only 'e' or 'd'.")

if __name__ == "__main__":
    main()
