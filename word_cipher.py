import re
import random

BOOK_FILE = "alice.txt"

def load_words(filename):
    # Lowercase and keep only letters/numbers/apostrophes inside words
    text = open(filename, "r", encoding="utf-8", errors="replace").read().lower()
    return re.findall(r"[a-z0-9']+", text)

def build_index(words):
    # Map each word -> list of positions where it appears in the book
    index = {}
    for i, w in enumerate(words):
        index.setdefault(w, []).append(i)
    return index

def encrypt(words, message):
    idx = build_index(words)
    msg_words = re.findall(r"[a-z0-9']+", message.lower())

    cipher_positions = []
    for w in msg_words:
        if w not in idx:
            raise ValueError(f"Word not found in book: {w!r}")
        cipher_positions.append(random.choice(idx[w]))
    return cipher_positions

def decrypt(words, positions):
    return " ".join(words[p] for p in positions)

# --- main ---
book_words = load_words(BOOK_FILE)

mode = input("Type 'e' to encrypt or 'd' to decrypt: ").strip().lower()

if mode == "e":
    msg = input("Message to encrypt (words only): ")
    cipher = encrypt(book_words, msg)
    print("Encrypted message (word positions):")
    print(" ".join(map(str, cipher)))

elif mode == "d":
    data = input("Paste the numbers: ")
    positions = [int(x) for x in data.replace(",", " ").split()]
    print("Decrypted message:")
    print(decrypt(book_words, positions))
else:
    print("Please type only 'e' or 'd'.")
