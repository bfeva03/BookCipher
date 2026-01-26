from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from pathlib import Path

import cipher_core

# -------------------------
# Crimson theme palette
# -------------------------
BG = "#12060A"          # near-black crimson
PANEL = "#1C0A10"       # panel background
ACCENT = "#A1122A"      # crimson
ACCENT_2 = "#D7263D"    # brighter crimson
FG = "#F3E9EC"          # near-white
MUTED = "#BCA7AE"       # muted text
ENTRY_BG = "#220B13"    # entry/text bg
BORDER = "#3A131F"      # border-ish


class BookCipherApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BookCipher")
        self.geometry("860x640")
        self.configure(bg=BG)

        # Force ttk to use a theme that allows colors (fixes “invisible buttons” on macOS)
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # ttk styles
        style.configure("Crimson.TFrame", background=BG)
        style.configure("Panel.TLabelframe", background=PANEL, foreground=FG, bordercolor=BORDER)
        style.configure("Panel.TLabelframe.Label", background=PANEL, foreground=FG)

        style.configure("Crimson.TLabel", background=BG, foreground=FG)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)

        style.configure(
            "Crimson.TCheckbutton",
            background=BG,
            foreground=FG,
            focusthickness=0,
        )

        style.configure(
            "Crimson.TButton",
            background=ACCENT,
            foreground=FG,
            padding=(14, 10),
            borderwidth=0,
            focusthickness=2,
            focuscolor=ACCENT_2,
        )
        style.map(
            "Crimson.TButton",
            background=[("active", ACCENT_2), ("pressed", ACCENT_2)],
            foreground=[("disabled", MUTED)],
        )

        style.configure(
            "Secondary.TButton",
            background="#2A0F18",
            foreground=FG,
            padding=(14, 10),
            borderwidth=0,
            focusthickness=2,
            focuscolor=ACCENT_2,
        )
        style.map(
            "Secondary.TButton",
            background=[("active", "#3A131F"), ("pressed", "#3A131F")],
        )

        # State
        self.book_paths: list[str] = []
        self.corpus_text: str | None = None
        self.autoclean_var = tk.BooleanVar(value=True)
        self.key_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Add one or more book .txt files to begin.")

        # --- Header ---
        header = ttk.Frame(self, style="Crimson.TFrame")
        header.pack(fill="x", padx=16, pady=(14, 8))

        ttk.Label(header, text="BookCipher", style="Crimson.TLabel", font=("Helvetica", 20, "bold")).pack(anchor="w")
        ttk.Label(
            header,
            text="Hybrid book cipher • compact ciphertext (no spaces) • optional key",
            style="Muted.TLabel",
            font=("Helvetica", 12),
        ).pack(anchor="w", pady=(2, 0))

        # --- Controls row ---
        controls = ttk.Frame(self, style="Crimson.TFrame")
        controls.pack(fill="x", padx=16, pady=(0, 10))

        ttk.Button(controls, text="Add Books (.txt)…", command=self.add_books, style="Crimson.TButton").pack(side="left")
        ttk.Button(controls, text="Remove Selected", command=self.remove_selected, style="Secondary.TButton").pack(
            side="left", padx=(8, 0)
        )

        ttk.Checkbutton(
            controls,
            text="Auto-clean Gutenberg headers",
            variable=self.autoclean_var,
            style="Crimson.TCheckbutton",
        ).pack(side="left", padx=(14, 0))

        keybox = ttk.Frame(controls, style="Crimson.TFrame")
        keybox.pack(side="right")

        ttk.Label(keybox, text="Key (optional):", style="Crimson.TLabel").pack(side="left", padx=(0, 8))
        self.key_entry = tk.Entry(
            keybox,
            textvariable=self.key_var,
            bg=ENTRY_BG,
            fg=FG,
            insertbackground=FG,
            highlightbackground=BORDER,
            highlightcolor=ACCENT_2,
            highlightthickness=1,
            width=26,
            relief="flat",
        )
        self.key_entry.pack(side="left")
        ttk.Label(keybox, text="(same key ⇒ same output)", style="Muted.TLabel").pack(side="left", padx=(10, 0))

        # --- Books panel ---
        books_panel = ttk.LabelFrame(self, text="Books (combined into one corpus)", style="Panel.TLabelframe")
        books_panel.pack(fill="x", padx=16, pady=(0, 12))

        self.books_list = tk.Listbox(
            books_panel,
            height=4,
            bg=ENTRY_BG,
            fg=FG,
            selectbackground=ACCENT,
            selectforeground=FG,
            highlightbackground=BORDER,
            highlightcolor=ACCENT_2,
            highlightthickness=1,
            borderwidth=0,
        )
        self.books_list.pack(fill="x", padx=10, pady=10)

        # --- Text panels ---
        mid = ttk.Frame(self, style="Crimson.TFrame")
        mid.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        plain_frame = ttk.LabelFrame(mid, text="Plaintext", style="Panel.TLabelframe")
        plain_frame.pack(fill="both", expand=True)

        self.plain = tk.Text(
            plain_frame,
            height=8,
            wrap="word",
            bg=ENTRY_BG,
            fg=FG,
            insertbackground=FG,
            highlightbackground=BORDER,
            highlightcolor=ACCENT_2,
            highlightthickness=1,
            borderwidth=0,
        )
        self.plain.pack(fill="both", expand=True, padx=10, pady=10)

        cipher_frame = ttk.LabelFrame(mid, text="Ciphertext (no spaces; no quotes needed)", style="Panel.TLabelframe")
        cipher_frame.pack(fill="both", expand=True, pady=(12, 0))

        self.cipher = tk.Text(
            cipher_frame,
            height=8,
            wrap="none",
            bg=ENTRY_BG,
            fg=FG,
            insertbackground=FG,
            highlightbackground=BORDER,
            highlightcolor=ACCENT_2,
            highlightthickness=1,
            borderwidth=0,
        )
        self.cipher.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Bottom buttons ---
        bottom = ttk.Frame(self, style="Crimson.TFrame")
        bottom.pack(fill="x", padx=16, pady=(0, 10))

        ttk.Button(bottom, text="Encrypt →", command=self.do_encrypt, style="Crimson.TButton").pack(side="left")
        ttk.Button(bottom, text="← Decrypt", command=self.do_decrypt, style="Secondary.TButton").pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(bottom, text="Copy Ciphertext", command=self.copy_cipher, style="Secondary.TButton").pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(bottom, text="Clear Text", command=self.clear_text, style="Secondary.TButton").pack(side="right")

        # --- Status bar ---
        status = ttk.Label(self, textvariable=self.status_var, style="Muted.TLabel")
        status.pack(fill="x", padx=16, pady=(0, 12))

    # -------------------------
    # Book management
    # -------------------------
    def add_books(self):
        paths = filedialog.askopenfilenames(
            title="Add book text files",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not paths:
            return

        for p in paths:
            if p not in self.book_paths:
                self.book_paths.append(p)

        self._refresh_books_list()
        self.corpus_text = None
        self.status_var.set(f"Added {len(paths)} book(s). Ready.")

    def remove_selected(self):
        sel = list(self.books_list.curselection())
        if not sel:
            return
        for i in reversed(sel):
            del self.book_paths[i]
        self._refresh_books_list()
        self.corpus_text = None
        self.status_var.set("Removed selected book(s).")

    def _refresh_books_list(self):
        self.books_list.delete(0, "end")
        for p in self.book_paths:
            self.books_list.insert("end", Path(p).name)

    def _get_corpus(self) -> str:
        if not self.book_paths:
            raise ValueError("No books added. Click 'Add Books (.txt)…' first.")
        if self.corpus_text is None:
            self.corpus_text = cipher_core.load_multiple_books(
                self.book_paths,
                autoclean=self.autoclean_var.get(),
            )
        return self.corpus_text

    # -------------------------
    # Crypto actions
    # -------------------------
    def do_encrypt(self):
        try:
            corpus = self._get_corpus()
            msg = self.plain.get("1.0", "end").rstrip("\n")
            if not msg.strip():
                raise ValueError("Plaintext is empty.")
            key = self.key_var.get()
            ct = cipher_core.encrypt(corpus, msg, key=key)
            self.cipher.delete("1.0", "end")
            self.cipher.insert("1.0", ct)
            self.status_var.set("Encrypted.")
        except Exception as e:
            messagebox.showerror("Encrypt failed", str(e))

    def do_decrypt(self):
        try:
            corpus = self._get_corpus()
            ct = self.cipher.get("1.0", "end").strip()
            if not ct:
                raise ValueError("Ciphertext is empty.")
            pt = cipher_core.decrypt(corpus, ct)
            self.plain.delete("1.0", "end")
            self.plain.insert("1.0", pt)
            self.status_var.set("Decrypted.")
        except Exception as e:
            messagebox.showerror("Decrypt failed", str(e))

    def copy_cipher(self):
        ct = self.cipher.get("1.0", "end").strip()
        self.clipboard_clear()
        self.clipboard_append(ct)
        self.status_var.set("Ciphertext copied to clipboard.")

    def clear_text(self):
        self.plain.delete("1.0", "end")
        self.cipher.delete("1.0", "end")
        self.status_var.set("Cleared.")


if __name__ == "__main__":
    BookCipherApp().mainloop()

