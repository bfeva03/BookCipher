from __future__ import annotations
import os
if os.environ.get('DISPLAY','') == '':
    try:
        from ctypes import cdll
        appkit = cdll.LoadLibrary('/System/Library/Frameworks/AppKit.framework/AppKit')
        appkit.NSApplicationActivateIgnoringOtherApps(1)
    except Exception:
        pass
import logging
import threading
from pathlib import Path
from typing import Optional
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import cipher_core

# Logging setup
logger = logging.getLogger(__name__)

# Use tkmacosx if present for nicer buttons on macOS (optional)
try:
    from tkmacosx import Button as MacButton  # type: ignore
except Exception:
    MacButton = None

# macOS: Force Tkinter window to front
import os
if os.environ.get('DISPLAY','') == '':
    try:
        from ctypes import cdll
        appkit = cdll.LoadLibrary('/System/Library/Frameworks/AppKit.framework/AppKit')
        appkit.NSApplicationActivateIgnoringOtherApps(1)
    except Exception:
        pass

# ----------------------------
# Crimson theme palette
# ----------------------------
BG = "#12060A"
PANEL = "#1C0A10"
PANEL_2 = "#220B13"
ACCENT = "#A1122A"
ACCENT_2 = "#D7263D"
FG = "#F3E9EC"
MUTED = "#BCA7AE"
BORDER = "#4A1A24"
ENTRY_BG = "#2A0F18"  # Lighter for better visibility
TEXT_BG = "#1A0C12"  # Lighter than BG for text widgets

APP_TITLE = "BookCipher"


def key_strength_score(s: str) -> tuple[int, str]:
    """
    Use cipher_core's key strength analysis for consistency.
    Returns (0-100, label)
    """
    score, warnings_list = cipher_core.check_key_strength(s)

    if score < 30:
        label = "Weak"
    elif score < 60:
        label = "OK"
    elif score < 80:
        label = "Strong"
    else:
        label = "Very strong"

    return score, label


class BookCipherApp(tk.Tk):
    def _on_canvas_press(self, event):
        pass

    def _on_canvas_drag(self, event):
        pass

    def _on_canvas_release(self, event):
        pass
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.configure(bg=BG)

        # optional logo in header area (doesn't affect macOS .icns app icon)
        self._logo_img = None
        self._try_load_logo()

        # State
        self.book_paths: list[Path] = []
        self.autoclean_var = tk.BooleanVar(value=True)

        self.key_var = tk.StringVar(value="")
        self.show_key_var = tk.BooleanVar(value=False)

        self.status_var = tk.StringVar(value="Pick one or more .txt books to begin.")
        self.strength_var = tk.StringVar(value="Key strength: Empty")
        self.strength_value = tk.IntVar(value=0)

        # Threading
        self._operation_thread: Optional[threading.Thread] = None
        self._processing = tk.BooleanVar(value=False)

        # Build UI
        self._build_styles()
        self._build_ui()
        self._bind_events()

        self._update_key_strength()

    # ---------- UI helpers ----------

    def _build_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=PANEL, foreground=FG)
        style.configure("Title.TLabel", background=PANEL, foreground=FG, font=("Helvetica", 18, "bold"))
        style.configure("Sub.TLabel", background=PANEL, foreground=MUTED)

        style.configure(
            "TCheckbutton",
            background=PANEL,
            foreground=FG,
        )

        style.configure(
            "Strength.Horizontal.TProgressbar",
            troughcolor=PANEL_2,
            background=ACCENT,
            bordercolor=BORDER,
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )

    def _try_load_logo(self) -> None:
        # Put logo.png in the same folder as BookCipherApp.py (or project root)
        candidates = [
            Path(__file__).with_name("logo.png"),
            Path.cwd() / "logo.png",
        ]
        for p in candidates:
            if p.exists():
                try:
                    self._logo_img = tk.PhotoImage(file=str(p))
                    return
                except Exception:
                    self._logo_img = None
                    return

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, style="Panel.TFrame", padding=14)
        outer.pack(fill="both", expand=True)

        # Header
        header = ttk.Frame(outer, style="Panel.TFrame")
        header.pack(fill="x")

        if self._logo_img:
            logo_lbl = tk.Label(header, image=self._logo_img, bg=PANEL)
            logo_lbl.pack(side="left", padx=(0, 10))

        title = ttk.Label(header, text="BookCipher", style="Title.TLabel")
        title.pack(side="left")

        subtitle = ttk.Label(
            outer,
            text="Hybrid book cipher • compact ciphertext (no spaces) • authenticated encryption",
            style="Sub.TLabel",
        )
        subtitle.pack(anchor="w", pady=(6, 10))

        # Top row controls
        top = ttk.Frame(outer, style="Panel.TFrame")
        top.pack(fill="x", pady=(0, 10))

        self._btn(top, "Add Books (.txt)…", self.add_books).pack(side="left")

        ttk.Checkbutton(
            top,
            text="Auto-clean Gutenberg headers",
            variable=self.autoclean_var,
            command=self._on_books_changed,
        ).pack(side="left", padx=(16, 0))

        ttk.Label(top, text="Key:", style="TLabel").pack(side="left", padx=(16, 6))

        # Key entry + show/hide
        self.key_entry = tk.Entry(
            top,
            textvariable=self.key_var,
            show="•",
            bg=ENTRY_BG,
            fg=FG,
            insertbackground=FG,
            highlightbackground=BORDER,
            highlightcolor=ACCENT_2,
            highlightthickness=1,
            relief="flat",
            width=28,
        )
        self.key_entry.pack(side="left")

        self.show_key_btn = self._btn(top, "Show", self.toggle_show_key, mini=True)
        self.show_key_btn.pack(side="left", padx=(8, 0))

        # Strength meter
        strength_row = ttk.Frame(outer, style="Panel.TFrame")
        strength_row.pack(fill="x", pady=(0, 10))

        self.strength_label = ttk.Label(strength_row, textvariable=self.strength_var, style="Sub.TLabel")
        self.strength_label.pack(side="left")

        self.strength_bar = ttk.Progressbar(
            strength_row,
            style="Strength.Horizontal.TProgressbar",
            maximum=100,
            variable=self.strength_value,
            length=220,
        )
        self.strength_bar.pack(side="left", padx=(10, 0))

        # Books list with numbering and drag-drop support
        books_box = ttk.Frame(outer, style="Panel.TFrame")
        books_box.pack(fill="x", expand=False)

        ttk.Label(
            books_box,
            text="Books (combined into one corpus) — Drag to reorder",
            style="TLabel",
        ).pack(anchor="w")

        # Create frame for listbox and controls
        books_frame = ttk.Frame(books_box, style="Panel.TFrame")
        books_frame.pack(fill="x", pady=(6, 0))

        # Listbox for books
        self.books_list = tk.Listbox(
            books_frame,
            selectmode="extended",
            bg=TEXT_BG,
            fg=FG,
            selectbackground=ACCENT,
            selectforeground=FG,
            highlightbackground=BORDER,
            highlightcolor=ACCENT_2,
            highlightthickness=2,
            relief="flat",
            height=4,
            exportselection=False,
            width=60,
            font=("Helvetica", 11),
        )
        self.books_list.pack(side="left", fill="both", expand=True)

        # Add vertical scrollbar
        scrollbar = ttk.Scrollbar(books_frame, orient="vertical", command=self.books_list.yview)
        scrollbar.pack(side="right", fill="y")
        self.books_list.config(yscrollcommand=scrollbar.set)

        # Bind drag-drop events
        self.books_list.bind("<Button-1>", self._on_listbox_press)
        self.books_list.bind("<B1-Motion>", self._on_listbox_drag)
        self.books_list.bind("<ButtonRelease-1>", self._on_listbox_release)
        self._drag_start_index = None

        # Reorder buttons
        btn_frame = ttk.Frame(books_box, style="Panel.TFrame")
        btn_frame.pack(fill="x", pady=(6, 10))

        self._btn(btn_frame, "↑ Move Up", self.move_book_up).pack(side="left", padx=(0, 5))
        self._btn(btn_frame, "↓ Move Down", self.move_book_down).pack(side="left", padx=(0, 5))
        self._btn(btn_frame, "Randomize Order", self.randomize_books).pack(side="left", padx=(0, 5))
        self._btn(btn_frame, "Remove Selected", self.remove_selected).pack(side="left")

        # Main content area for text widgets and actions
        content = ttk.Frame(outer, style="Panel.TFrame")
        content.pack(fill="both", expand=True, pady=(10, 0))

        # Plaintext
        ttk.Label(content, text="Plaintext", style="TLabel").pack(anchor="w")
        self.plain = tk.Text(
            content,
            height=7,
            bg=TEXT_BG,
            fg=FG,
            insertbackground=FG,
            selectbackground=ACCENT,
            selectforeground=FG,
            highlightbackground=BORDER,
            highlightcolor=ACCENT_2,
            highlightthickness=2,
            relief="flat",
            wrap="word",
            font=("Courier", 12),
        )
        self.plain.pack(fill="both", expand=True, pady=(6, 10))

        # Ciphertext
        ttk.Label(content, text="Ciphertext (no spaces; no quotes needed)", style="TLabel").pack(anchor="w")
        self.cipher = tk.Text(
            content,
            height=6,
            bg=TEXT_BG,
            fg=FG,
            insertbackground=FG,
            selectbackground=ACCENT,
            selectforeground=FG,
            highlightbackground=BORDER,
            highlightcolor=ACCENT_2,
            highlightthickness=2,
            relief="flat",
            wrap="none",
            font=("Courier", 12),
        )
        self.cipher.pack(fill="both", expand=True, pady=(6, 12))

        # Buttons row
        actions = ttk.Frame(content, style="Panel.TFrame")
        actions.pack(fill="x")

        self.encrypt_btn = self._btn(actions, "Encrypt →", self.do_encrypt)
        self.encrypt_btn.pack(side="left")

        self.decrypt_btn = self._btn(actions, "← Decrypt", self.do_decrypt)
        self.decrypt_btn.pack(side="left", padx=(10, 0))

        self.copy_btn = self._btn(actions, "Copy Ciphertext", self.copy_cipher)
        self.copy_btn.pack(side="left", padx=(10, 0))

        self.clear_btn = self._btn(actions, "Clear Boxes", self.clear_boxes)
        self.clear_btn.pack(side="right")

        # Status bar
        status = ttk.Frame(content, style="Panel.TFrame")
        status.pack(fill="x", pady=(10, 0))

        self.status_label = ttk.Label(status, textvariable=self.status_var, style="Sub.TLabel")
        self.status_label.pack(side="left")

    def randomize_books(self) -> None:
        """Randomize the order of the selected books."""
        import random

        if not self.book_paths:
            return
        random.shuffle(self.book_paths)
        self._refresh_books_list()
        self._on_books_changed()

    def _btn(self, parent, text: str, cmd, mini: bool = False):
        # Prefer tkmacosx Button if available (fixes “white ttk button” look)
        if MacButton is not None:
            return MacButton(
                parent,
                text=text,
                command=cmd,
                bg=ACCENT,
                fg=FG,
                activebackground=ACCENT_2,
                activeforeground=FG,
                borderless=1,
                focuscolor="",
                padx=10 if not mini else 8,
                pady=6 if not mini else 4,
                highlightthickness=0,
            )

        # Fallback: tk.Button (not ttk) so we can control colors
        return tk.Button(
            parent,
            text=text,
            command=cmd,
            bg=ACCENT,
            fg=FG,
            activebackground=ACCENT_2,
            activeforeground=FG,
            relief="flat",
            padx=10 if not mini else 8,
            pady=6 if not mini else 4,
            highlightthickness=0,
        )

    def _bind_events(self) -> None:
        self.key_var.trace_add("write", lambda *_: self._update_key_strength())

    # ---------- logic ----------

    def add_books(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Add book text files",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not paths:
            return

        for p in paths:
            pp = Path(p)
            if pp not in self.book_paths:
                self.book_paths.append(pp)

        self._refresh_books_list()
        self._on_books_changed()

    def remove_selected(self) -> None:
        sel = list(self.books_list.curselection())
        if not sel:
            return
        # remove in reverse order
        for i in reversed(sel):
            try:
                del self.book_paths[i]
            except Exception:
                pass
        self._refresh_books_list()
        self._on_books_changed()

    def _refresh_books_list(self) -> None:
        """Refresh books list with numbering and full title."""
        self.books_list.delete(0, "end")
        for i, p in enumerate(self.book_paths, 1):
            # Display: "1. full filename.txt"
            self.books_list.insert("end", f"{i}. {p.name}")

    def _set_books_selection(self, index: int) -> None:
        """Keep selection visible when moving items."""
        if not self.book_paths:
            return
        index = max(0, min(index, len(self.book_paths) - 1))
        self.books_list.selection_clear(0, "end")
        self.books_list.selection_set(index)
        self.books_list.activate(index)
        self.books_list.see(index)
        self.books_list.focus_set()

    def move_book_up(self) -> None:
        """Move selected book up in the list."""
        sel = list(self.books_list.curselection())
        if not sel or sel[0] == 0:
            return
        idx = sel[0]
        # Swap with previous
        self.book_paths[idx], self.book_paths[idx - 1] = self.book_paths[idx - 1], self.book_paths[idx]
        self._refresh_books_list()
        self._set_books_selection(idx - 1)
        self._on_books_changed()

    def move_book_down(self) -> None:
        """Move selected book down in the list."""
        sel = list(self.books_list.curselection())
        if not sel or sel[0] == len(self.book_paths) - 1:
            return
        idx = sel[0]
        # Swap with next
        self.book_paths[idx], self.book_paths[idx + 1] = self.book_paths[idx + 1], self.book_paths[idx]
        self._refresh_books_list()
        self._set_books_selection(idx + 1)
        self._on_books_changed()

    def _on_listbox_press(self, event: tk.Event) -> None:
        """Handle mouse press for drag-start."""
        selection = self.books_list.curselection()
        if selection:
            self._drag_start_index = selection[0]

    def _on_listbox_drag(self, event: tk.Event) -> None:
        """Handle dragging - move book in real-time as user drags with animation."""
        if self._drag_start_index is None:
            return

        # Get the item under the current mouse position
        drop_index = self.books_list.nearest(event.y)
        if drop_index < 0 or drop_index == self._drag_start_index:
            return

        # Determine swap direction and perform single swap step
        if drop_index > self._drag_start_index:
            # Moving down
            book = self.book_paths.pop(self._drag_start_index)
            self.book_paths.insert(drop_index, book)
        else:
            # Moving up
            book = self.book_paths.pop(self._drag_start_index)
            self.book_paths.insert(drop_index, book)

        # Update display with animation effect
        self._refresh_books_list()
        self._set_books_selection(drop_index)
        self._drag_start_index = drop_index
        self._on_books_changed()

    def _on_listbox_release(self, event: tk.Event) -> None:
        """Handle mouse release - just cleanup."""
        self._drag_start_index = None

    def _on_books_changed(self) -> None:
        if self.book_paths:
            self.status_var.set(f"Loaded {len(self.book_paths)} book(s). Ready.")
        else:
            self.status_var.set("Pick one or more .txt books to begin.")

    def toggle_show_key(self) -> None:
        self.show_key_var.set(not self.show_key_var.get())
        if self.show_key_var.get():
            self.key_entry.config(show="")
            self.show_key_btn.config(text="Hide")
        else:
            self.key_entry.config(show="•")
            self.show_key_btn.config(text="Show")

        self.status_var.set("Key visible." if self.show_key_var.get() else "Key hidden.")

    def _update_key_strength(self) -> None:
        score, label = key_strength_score(self.key_var.get())
        self.strength_value.set(score)
        self.strength_var.set(f"Key strength: {label} ({score}/100)")

    def _load_books_texts(self) -> list[str]:
        if not self.book_paths:
            raise ValueError("No books selected.")
        texts = []
        for p in self.book_paths:
            texts.append(p.read_text(encoding="utf-8", errors="replace"))
        return texts

    def _require_key(self) -> str:
        k = self.key_var.get()
        if not k or not k.strip():
            raise ValueError("Key is required.")
        return k

    def do_encrypt(self) -> None:
        """Encrypt plaintext in a background thread to keep UI responsive."""
        if self._processing.get():
            messagebox.showwarning("In Progress", "Another operation is in progress.")
            return

        try:
            key = self._require_key()
            books = self._load_books_texts()
            msg = self.plain.get("1.0", "end").rstrip("\n")
            if not msg.strip():
                raise ValueError("Plaintext is empty.")

            self._processing.set(True)
            self.encrypt_btn.config(state="disabled")
            self.decrypt_btn.config(state="disabled")
            self.status_var.set("Encrypting... (this may take ~100ms)")

            # Run in background thread
            thread = threading.Thread(target=self._encrypt_worker, args=(key, books, msg), daemon=True)
            self._operation_thread = thread
            thread.start()
        except Exception as e:
            self._processing.set(False)
            messagebox.showerror("Encrypt failed", str(e))
            self.status_var.set("Encrypt failed.")

    def _encrypt_worker(self, key: str, books: list[str], msg: str) -> None:
        """Background worker for encryption."""
        try:
            corpus = cipher_core.build_corpus(books, autoclean=self.autoclean_var.get())
            token = cipher_core.encrypt(msg, key, corpus)

            # Update UI on main thread
            self.after(0, self._encrypt_done, token)
        except Exception as e:
            self.after(0, self._encrypt_error, str(e))

    def _encrypt_done(self, token: str) -> None:
        """Called when encryption completes (on main thread)."""
        self.cipher.delete("1.0", "end")
        self.cipher.insert("1.0", token)
        self.status_var.set("Encrypted. (Copy ciphertext or decrypt later)")
        self.encrypt_btn.config(state="normal")
        self.decrypt_btn.config(state="normal")
        self._processing.set(False)

    def _encrypt_error(self, error: str) -> None:
        """Called if encryption fails (on main thread)."""
        messagebox.showerror("Encrypt failed", error)
        self.status_var.set("Encrypt failed.")
        self.encrypt_btn.config(state="normal")
        self.decrypt_btn.config(state="normal")
        self._processing.set(False)

    def do_decrypt(self) -> None:
        """Decrypt ciphertext in a background thread to keep UI responsive."""
        if self._processing.get():
            messagebox.showwarning("In Progress", "Another operation is in progress.")
            return

        try:
            key = self._require_key()
            books = self._load_books_texts()
            token = self.cipher.get("1.0", "end").strip()
            if not token:
                raise ValueError("Ciphertext is empty.")

            self._processing.set(True)
            self.encrypt_btn.config(state="disabled")
            self.decrypt_btn.config(state="disabled")
            self.status_var.set("Decrypting... (this may take ~100ms)")

            # Run in background thread
            thread = threading.Thread(target=self._decrypt_worker, args=(key, books, token), daemon=True)
            self._operation_thread = thread
            thread.start()
        except Exception as e:
            self._processing.set(False)
            messagebox.showerror("Decrypt failed", str(e))
            self.status_var.set("Decrypt failed.")

    def _decrypt_worker(self, key: str, books: list[str], token: str) -> None:
        """Background worker for decryption."""
        try:
            corpus = cipher_core.build_corpus(books, autoclean=self.autoclean_var.get())
            pt = cipher_core.decrypt(token, key, corpus)

            # Update UI on main thread
            self.after(0, self._decrypt_done, pt)
        except Exception as e:
            self.after(0, self._decrypt_error, str(e))

    def _decrypt_done(self, pt: str) -> None:
        """Called when decryption completes (on main thread)."""
        self.plain.delete("1.0", "end")
        self.plain.insert("1.0", pt)
        self.status_var.set("Decrypted successfully.")
        self.encrypt_btn.config(state="normal")
        self.decrypt_btn.config(state="normal")
        self._processing.set(False)

    def _decrypt_error(self, error: str) -> None:
        """Called if decryption fails (on main thread)."""
        messagebox.showerror("Decrypt failed", error)
        self.status_var.set("Decrypt failed.")
        self.encrypt_btn.config(state="normal")
        self.decrypt_btn.config(state="normal")
        self._processing.set(False)

    def copy_cipher(self) -> None:
        token = self.cipher.get("1.0", "end").strip()
        if not token:
            self.status_var.set("Nothing to copy.")
            return
        self.clipboard_clear()
        self.clipboard_append(token)
        self.status_var.set("Ciphertext copied to clipboard.")

    def clear_boxes(self) -> None:
        self.plain.delete("1.0", "end")
        self.cipher.delete("1.0", "end")
        self.status_var.set("Cleared plaintext and ciphertext.")


if __name__ == "__main__":
    app = BookCipherApp()
    app.geometry("980x720")
    app.minsize(860, 620)
    app.mainloop()
