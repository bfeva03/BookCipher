from __future__ import annotations

import argparse
from pathlib import Path

import cipher_core


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="BookCipher CLI (authenticated, book-bound encryption)"
    )

    ap.add_argument(
        "--book",
        action="append",
        required=True,
        help="Path to a .txt book (repeatable)",
    )
    ap.add_argument(
        "--key",
        required=True,
        help="Passphrase key",
    )
    ap.add_argument(
        "--no-autoclean",
        action="store_true",
        help="Disable Gutenberg auto-clean",
    )

    sub = ap.add_subparsers(dest="mode", required=True)

    enc = sub.add_parser("encrypt")
    enc.add_argument(
        "--message",
        help="Message to encrypt (if omitted, you will be prompted)",
    )

    dec = sub.add_parser("decrypt")
    dec.add_argument(
        "--cipher",
        help="Ciphertext token (if omitted, you will be prompted)",
    )

    args = ap.parse_args()

    books = [load_text(Path(p)) for p in args.book]
    corpus = cipher_core.build_corpus(
        books, autoclean=not args.no_autoclean
    )

    if args.mode == "encrypt":
        msg = args.message or input("Message to encrypt: ")
        token = cipher_core.encrypt(msg, args.key, corpus)
        print(token)
    else:
        token = args.cipher or input("Paste ciphertext token: ").strip()
        plaintext = cipher_core.decrypt(token, args.key, corpus)
        print(plaintext)


if __name__ == "__main__":
    main()

