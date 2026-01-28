from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import cipher_core

# Logging setup
logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def load_text(path: Path) -> str:
    """Load text from file, handling encoding errors gracefully."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {path}")
    except Exception as e:
        raise RuntimeError(f"Failed to read file {path}: {e}")


def save_text(path: Path, text: str) -> None:
    """Save text to file."""
    try:
        path.write_text(text, encoding="utf-8")
        logger.info(f"Saved to {path}")
    except Exception as e:
        raise RuntimeError(f"Failed to write file {path}: {e}")


def main() -> None:
    ap = argparse.ArgumentParser(description="BookCipher CLI (authenticated, book-bound encryption)")

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
    ap.add_argument(
        "--scrypt-strength",
        choices=["normal", "high"],
        default="normal",
        help="Scrypt strength: 'normal' (2^17, ~100ms) or 'high' (2^18, ~200ms)",
    )
    ap.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    sub = ap.add_subparsers(dest="mode", required=True)

    enc = sub.add_parser("encrypt")
    enc.add_argument(
        "--message",
        help="Message to encrypt (if omitted, you will be prompted)",
    )
    enc.add_argument(
        "--input-file",
        help="Read plaintext from file instead of command line",
    )
    enc.add_argument(
        "--output-file",
        help="Save ciphertext token to file",
    )

    dec = sub.add_parser("decrypt")
    dec.add_argument(
        "--cipher",
        help="Ciphertext token (if omitted, you will be prompted)",
    )
    dec.add_argument(
        "--input-file",
        help="Read ciphertext token from file",
    )
    dec.add_argument(
        "--output-file",
        help="Save plaintext to file",
    )

    args = ap.parse_args()

    # Configure logging
    if args.verbose:
        logging.getLogger("cipher_core").setLevel(logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    # Load books
    books = [load_text(Path(p)) for p in args.book]
    corpus = cipher_core.build_corpus(books, autoclean=not args.no_autoclean)

    # Determine Scrypt strength
    scrypt_n = cipher_core.SCRYPT_HIGH_N if args.scrypt_strength == "high" else cipher_core.SCRYPT_DEFAULT_N

    if args.mode == "encrypt":
        # Get plaintext
        if args.input_file:
            plaintext = load_text(Path(args.input_file))
        elif args.message:
            plaintext = args.message
        else:
            plaintext = input("Message to encrypt: ")

        # Encrypt
        token = cipher_core.encrypt(plaintext, args.key, corpus, scrypt_n)

        # Output
        if args.output_file:
            save_text(Path(args.output_file), token)
        else:
            print(token)

    else:  # decrypt
        # Get ciphertext
        if args.input_file:
            token = load_text(Path(args.input_file)).strip()
        elif args.cipher:
            token = args.cipher
        else:
            token = input("Paste ciphertext token: ").strip()

        # Decrypt
        plaintext = cipher_core.decrypt(token, args.key, corpus)

        # Output
        if args.output_file:
            save_text(Path(args.output_file), plaintext)
        else:
            print(plaintext)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, FileNotFoundError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
