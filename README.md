📕 BookCipher
BookCipher is a macOS desktop app that implements a hybrid book cipher using public-domain texts. It converts plaintext into compact ciphertext using word positions, with optional deterministic keying for repeatable results.
Designed for experimentation, learning, and cryptographic curiosity.

✨ Features
* 🔐 Hybrid book cipher
* 📚 Combine multiple .txt books into one cipher corpus
* 🧹 Optional auto-cleaning of Project Gutenberg headers
* 🔑 Optional key (same key → same output)
* 🧾 Compact ciphertext (no spaces, no quotes needed)
* 🖥 Native macOS app (no terminal required)
* 🎨 Custom app icon and dark UI theme

🖼 Interface Overview
* Books panel — add one or more .txt files
* Plaintext — enter or paste text to encrypt
* Ciphertext — compact output, ready to copy
* Encrypt / Decrypt buttons
* Key (optional) — makes encryption deterministic

📥 Installation
1. Download the .dmg
2. Open it
3. Drag BookCipher into your Applications folder
First launch (important)
Because this app is not notarized by Apple:
1. Right-click BookCipher
2. Click Open
3. Click Open again
This is required once only. It’s a standard macOS security step for independent apps.

📚 Supported Book Files
* Plain text (.txt)
* UTF-8 recommended
* Public-domain texts work best (e.g. Project Gutenberg)
Examples:
* Alice’s Adventures in Wonderland
* Pride and Prejudice
* Gulliver’s Travels
* The Adventures of Tom Sawyer

🔐 Cipher Notes
* Encryption uses word indexing, not substitution
* Ciphertext cannot be decrypted without the same book corpus
* Using a key seeds the cipher for reproducibility
* Capitalization and punctuation are preserved in output
This app is intended for educational and experimental use, not for secure communications.

🛠 Built With
* Python
* Tkinter
* PyInstaller
* macOS ad-hoc code signing

⚠ Security & Privacy
* No network access
* No telemetry
* No data collection
* All processing is local

📄 License
MIT License You’re free to use, modify, and share.

💡 Why This Exists
BookCipher was built as an exploration of:
* Classical cipher techniques
* Deterministic randomness
* macOS app packaging
* Clean UI for cryptographic tools


