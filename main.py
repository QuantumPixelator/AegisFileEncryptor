"""
Aegis File Encryptor

A modern, user-friendly GUI application for encrypting and decrypting files using
Fernet symmetric encryption from the cryptography library. Supports any file type
and allows users to choose save locations with overwrite protection.

Features:
- AES-128 encryption with HMAC integrity
- Themeable interface with persistent theme selection
- File selection dialogs for input and output
- Status updates and error handling
- Password-derived key management prompted per operation
- Chunked processing for large files with length prefixes
- Progress bar for operations
- Multithreading for UI responsiveness

Dependencies: tkinter, ttkthemes, cryptography
"""

import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import ttkthemes
from ttkthemes import ThemedStyle
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64
from pathlib import Path
import secrets
import threading
import queue
import struct

# Configuration constants
KEY_FILE = "secret.key"
THEME_CONFIG_FILE = "theme_config.txt"
CHUNK_SIZE = 1024 * 1024  # 1MB chunks
SALT_SIZE = 16
LENGTH_PREFIX_SIZE = 4  # 4 bytes for chunk length

# Key Management Functions

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a Fernet key from password using PBKDF2.

    Args:
        password (str): User-provided password.
        salt (bytes): Salt for key derivation.

    Returns:
        bytes: Derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def generate_key_if_missing():
    """
    Generates a new salt and saves it to KEY_FILE if it doesn't exist.

    Returns:
        tuple: (bool, str) - (key_generated, status_message)
    """
    if not Path(KEY_FILE).exists():
        salt = secrets.token_bytes(SALT_SIZE)
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(salt)
        return True, "Generated new salt for key derivation."
    return False, "Salt loaded for key derivation."

def load_salt() -> bytes:
    """
    Loads the salt from KEY_FILE.

    Returns:
        bytes or None: The salt if found, None otherwise.
    """
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        return None

class AegisApp(ttkthemes.ThemedTk):
    """
    Main GUI application class for file encryption/decryption.

    Inherits from ttkthemes.ThemedTk for theme support. Provides a user interface
    for selecting files, encrypting/decrypting them, and choosing save locations.
    Uses Fernet for secure AES encryption with password-derived keys.
    """

    def __init__(self):
        """
        Initializes the application window, theme, styles, and UI components.
        """
        super().__init__()
        self.title("🛡️ Aegis File Encryptor")
        self.geometry("650x623")
        self.resizable(True, True)
        # Load saved theme or default
        self.saved_theme = self._load_theme()
        self.set_theme(self.saved_theme)
        self.key_status = ""
        self.encrypt_file = ""
        self.decrypt_file = ""
        self.operation_queue = queue.Queue()

        # Custom styles for elegance
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 11, "bold"), padding=(10, 5), relief="flat")
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        self.style.configure("Section.TLabel", font=("Segoe UI", 12, "bold"))
        self.style.configure("Card.TLabelframe", borderwidth=2, relief="solid")
        self.style.configure("Card.TLabelframe.Label", font=("Segoe UI", 12, "bold"))
        self.style.configure("Error.TLabel", foreground="red")

        # Initialize salt
        self._initialize_salt()

        # Set up UI elements
        self._create_widgets()

        # Center the window
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def _initialize_salt(self):
        """
        Ensures the salt exists and updates the key status for display in the UI.
        """
        key_generated, status_message = generate_key_if_missing()
        salt = load_salt()

        if salt:
            self.key_status = f"Ready. Key status: {status_message}"
        else:
            messagebox.showerror("Error", "Could not find or generate salt. Check permissions.")
            self.key_status = "Error: Salt unavailable."
            self.destroy()

    def _get_password(self) -> str:
        """
        Displays a themed dialog to get the user's password.

        Returns:
            str: The entered password, or empty if cancelled.
        """
        dialog = tk.Toplevel(self)
        dialog.title("Enter Password")
        dialog.geometry("300x150")
        dialog.resizable(False, False)

        # Apply theme to dialog
        dialog_style = ThemedStyle(dialog)
        dialog_style.set_theme(self.get_theme())

        ttk.Label(dialog, text="Password for key derivation:").pack(pady=10)
        password_var = tk.StringVar()
        entry = ttk.Entry(dialog, show="*", textvariable=password_var)
        entry.pack(pady=5)
        entry.focus()

        def submit():
            dialog.quit()

        ttk.Button(dialog, text="Submit", command=submit).pack(pady=10)
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
        dialog.mainloop()
        dialog.destroy()
        return password_var.get()

    def _create_widgets(self):
        """
        Creates and arranges all GUI widgets including frames, buttons, labels, progress bar, and theme selector.
        Configures layout and styling for the main interface.
        """
        # Configure grid for resizing
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Main Frame ---
        main_frame = ttk.Frame(self, padding=30)
        main_frame.grid(row=0, column=0, sticky="nsew")
        main_frame.grid_columnconfigure(0, weight=1)

        # Title with icon and theme selector
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, pady=(0, 40), sticky="ew")
        title_frame.grid_columnconfigure(1, weight=1)

        ttk.Label(title_frame, text="🛡️", font=("Segoe UI", 24)).grid(row=0, column=0, padx=(0, 10))
        title_label = ttk.Label(title_frame, text="Aegis File Encryptor", style="Title.TLabel")
        title_label.grid(row=0, column=1, sticky="w")

        # Theme selector
        theme_frame = ttk.Frame(title_frame)
        theme_frame.grid(row=0, column=2, padx=(20, 0))
        ttk.Label(theme_frame, text="Theme:", font=("Segoe UI", 10)).grid(row=0, column=0, padx=(0, 5))
        self.theme_var = tk.StringVar(value=self.saved_theme)
        self.theme_combo = ttk.Combobox(theme_frame, textvariable=self.theme_var, values=ttkthemes.THEMES, state="readonly", width=12)
        self.theme_combo.grid(row=0, column=1)
        self.theme_combo.bind("<<ComboboxSelected>>", self._change_theme)

        # --- Encryption Section ---
        encrypt_frame = ttk.LabelFrame(main_frame, text="🔐 Encryption", style="Card.TLabelframe", padding=20)
        encrypt_frame.grid(row=1, column=0, sticky="ew", pady=(0, 25))
        encrypt_frame.grid_columnconfigure(0, weight=1)

        ttk.Label(encrypt_frame, text="Select a file to encrypt and choose where to save the encrypted version:", style="Section.TLabel").grid(row=0, column=0, pady=(0, 20), sticky="w")

        button_frame1 = ttk.Frame(encrypt_frame)
        button_frame1.grid(row=1, column=0, pady=(0, 15))

        self.select_encrypt_button = ttk.Button(button_frame1, text="📁 Select File", command=self._select_encrypt_file)
        self.select_encrypt_button.grid(row=0, column=0, padx=(0, 15))

        self.encrypt_button = ttk.Button(button_frame1, text="Encrypt & Save", command=self._start_encrypt_action, state=tk.DISABLED)
        self.encrypt_button.grid(row=0, column=1)

        self.reset_encrypt_button = ttk.Button(button_frame1, text="Reset", command=self._reset_encrypt, state=tk.DISABLED)
        self.reset_encrypt_button.grid(row=0, column=2, padx=(15, 0))

        # --- Separator ---
        ttk.Separator(main_frame, orient="horizontal").grid(row=2, column=0, sticky="ew", pady=10)

        # --- Decryption Section ---
        decrypt_frame = ttk.LabelFrame(main_frame, text="🔓 Decryption", style="Card.TLabelframe", padding=20)
        decrypt_frame.grid(row=3, column=0, sticky="ew", pady=(0, 30))
        decrypt_frame.grid_columnconfigure(0, weight=1)

        ttk.Label(decrypt_frame, text="Select an encrypted file and choose where to save the decrypted version:", style="Section.TLabel").grid(row=0, column=0, pady=(0, 20), sticky="w")

        button_frame2 = ttk.Frame(decrypt_frame)
        button_frame2.grid(row=1, column=0, pady=(0, 15))

        self.select_decrypt_button = ttk.Button(button_frame2, text="📁 Select Encrypted File", command=self._select_decrypt_file)
        self.select_decrypt_button.grid(row=0, column=0, padx=(0, 15))

        self.decrypt_button = ttk.Button(button_frame2, text="Decrypt & Save", command=self._start_decrypt_action, state=tk.DISABLED)
        self.decrypt_button.grid(row=0, column=1)

        self.reset_decrypt_button = ttk.Button(button_frame2, text="Reset", command=self._reset_decrypt, state=tk.DISABLED)
        self.reset_decrypt_button.grid(row=0, column=2, padx=(15, 0))

        # --- Progress Bar ---
        self.progress = ttk.Progressbar(main_frame, orient="horizontal", mode="determinate", length=400)
        self.progress.grid(row=4, column=0, pady=10, sticky="ew")

        # --- Status Bar ---
        status_frame = ttk.Frame(self, relief="sunken", borderwidth=1)
        status_frame.grid(row=1, column=0, sticky="ew")
        status_frame.grid_columnconfigure(0, weight=1)

        self.status_bar = ttk.Label(status_frame, text=self.key_status, padding=8, font=("Segoe UI", 9))
        self.status_bar.grid(row=0, column=0, sticky="ew")

    def _load_theme(self):
        """
        Loads the saved theme from config file, defaults to 'arc' if not found.

        Returns:
            str: The theme name.
        """
        path = Path(THEME_CONFIG_FILE)
        if path.exists():
            theme = path.read_text().strip()
            if theme in ttkthemes.THEMES:
                return theme
        return "arc"

    def _save_theme(self, theme):
        """
        Saves the current theme to config file.

        Args:
            theme (str): The theme name to save.
        """
        Path(THEME_CONFIG_FILE).write_text(theme)

    def _change_theme(self, event):
        """
        Event handler for theme selection. Applies the selected theme immediately.

        Args:
            event: The combobox selection event (unused).
        """
        new_theme = self.theme_var.get()
        self.set_theme(new_theme)
        self._save_theme(new_theme)
        # Reapply custom styles to ensure they work with the new theme
        self.style.configure("TButton", font=("Segoe UI", 11, "bold"), padding=(10, 5), relief="flat")
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        self.style.configure("Section.TLabel", font=("Segoe UI", 12, "bold"))
        self.style.configure("Card.TLabelframe", borderwidth=2, relief="solid")
        self.style.configure("Card.TLabelframe.Label", font=("Segoe UI", 12, "bold"))
        self.style.configure("Error.TLabel", foreground="red")

    def _select_encrypt_file(self):
        """
        Opens a file dialog for selecting a file to encrypt.
        Enables the encrypt and reset buttons and updates status if a file is selected.
        """
        file_path = filedialog.askopenfilename(title="Select a file to encrypt")
        if file_path:
            self.encrypt_file = file_path
            self.encrypt_button.config(state=tk.NORMAL)
            self.reset_encrypt_button.config(state=tk.NORMAL)
            self._update_status(f"Selected: {Path(file_path).name}")

    def _select_decrypt_file(self):
        """
        Opens a file dialog for selecting an encrypted file to decrypt.
        Enables the decrypt and reset buttons and updates status if a file is selected.
        """
        file_path = filedialog.askopenfilename(
            title="Select an encrypted file to decrypt",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if file_path:
            self.decrypt_file = file_path
            self.decrypt_button.config(state=tk.NORMAL)
            self.reset_decrypt_button.config(state=tk.NORMAL)
            self._update_status(f"Selected: {Path(file_path).name}")

    def _reset_encrypt(self):
        """
        Resets encryption selection and buttons.
        """
        self.encrypt_file = ""
        self.encrypt_button.config(state=tk.DISABLED)
        self.reset_encrypt_button.config(state=tk.DISABLED)
        self._update_status("Encryption selection reset.")

    def _reset_decrypt(self):
        """
        Resets decryption selection and buttons.
        """
        self.decrypt_file = ""
        self.decrypt_button.config(state=tk.DISABLED)
        self.reset_decrypt_button.config(state=tk.DISABLED)
        self._update_status("Decryption selection reset.")

    def _start_encrypt_action(self):
        """
        Starts the encryption process in a separate thread after prompting for password.
        """
        if not self.encrypt_file:
            self._update_status("No file selected for encryption.", is_error=True)
            return

        # Choose save location
        default_name = Path(self.encrypt_file).name + ".enc"
        save_path = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            defaultextension=".enc",
            initialfile=default_name,
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
            confirmoverwrite=True
        )
        if not save_path:
            return  # User cancelled

        # Prompt for password
        password = self._get_password()
        if not password:
            return  # Cancelled

        salt = load_salt()
        if not salt:
            self._update_status("Error: Salt unavailable.", is_error=True)
            return

        key = derive_key(password, salt)
        fernet = Fernet(key)

        self._disable_buttons()
        self._update_status("Encrypting...")
        self.progress["value"] = 0

        thread = threading.Thread(target=self._encrypt_thread, args=(self.encrypt_file, save_path, fernet))
        thread.start()
        self.after(100, self._check_queue)

    def _encrypt_thread(self, input_path: str, output_path: str, fernet: Fernet):
        """
        Thread for encrypting the file in chunks.

        Args:
            input_path (str): Path to input file.
            output_path (str): Path to output file.
            fernet (Fernet): Fernet instance for encryption.
        """
        try:
            file_size = Path(input_path).stat().st_size
            self.operation_queue.put(('max', file_size))
            processed = 0

            with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
                while chunk := infile.read(CHUNK_SIZE):
                    encrypted_chunk = fernet.encrypt(chunk)
                    length = len(encrypted_chunk)
                    outfile.write(struct.pack('>I', length))  # Big-endian unsigned int
                    outfile.write(encrypted_chunk)
                    processed += len(chunk)
                    self.operation_queue.put(('progress', processed))

            self.operation_queue.put(('done', f"Encrypted and saved as '{Path(output_path).name}'."))
            self.operation_queue.put(('reset_encrypt',))

        except Exception as e:
            self.operation_queue.put(('error', f"Error during encryption: {e}"))

    def _start_decrypt_action(self):
        """
        Starts the decryption process in a separate thread after prompting for password.
        """
        if not self.decrypt_file:
            self._update_status("No encrypted file selected for decryption.", is_error=True)
            return

        # Suggest original filename
        path = Path(self.decrypt_file)
        base_name = path.name
        if base_name.endswith(".enc"):
            default_name = base_name[:-4]  # Remove .enc
        else:
            default_name = base_name + "_decrypted"

        save_path = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialfile=default_name,
            filetypes=[("All files", "*.*")],
            confirmoverwrite=True
        )
        if not save_path:
            return  # User cancelled

        # Prompt for password
        password = self._get_password()
        if not password:
            return  # Cancelled

        salt = load_salt()
        if not salt:
            self._update_status("Error: Salt unavailable.", is_error=True)
            return

        key = derive_key(password, salt)
        fernet = Fernet(key)

        self._disable_buttons()
        self._update_status("Decrypting...")
        self.progress["value"] = 0

        thread = threading.Thread(target=self._decrypt_thread, args=(self.decrypt_file, save_path, fernet))
        thread.start()
        self.after(100, self._check_queue)

    def _decrypt_thread(self, input_path: str, output_path: str, fernet: Fernet):
        """
        Thread for decrypting the file in chunks.

        Args:
            input_path (str): Path to input file.
            output_path (str): Path to output file.
            fernet (Fernet): Fernet instance for decryption.
        """
        try:
            file_size = Path(input_path).stat().st_size
            self.operation_queue.put(('max', file_size))
            processed = 0

            with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
                while True:
                    length_bytes = infile.read(LENGTH_PREFIX_SIZE)
                    if not length_bytes:
                        break
                    if len(length_bytes) < LENGTH_PREFIX_SIZE:
                        raise ValueError("Incomplete length prefix")
                    length = struct.unpack('>I', length_bytes)[0]
                    encrypted_chunk = infile.read(length)
                    if len(encrypted_chunk) < length:
                        raise ValueError("Incomplete chunk")
                    decrypted_chunk = fernet.decrypt(encrypted_chunk)
                    outfile.write(decrypted_chunk)
                    processed += LENGTH_PREFIX_SIZE + length
                    self.operation_queue.put(('progress', processed))

            self.operation_queue.put(('done', f"Decrypted and saved as '{Path(output_path).name}'."))
            self.operation_queue.put(('reset_decrypt',))

        except InvalidToken:
            self.operation_queue.put(('error', "Error: Invalid key or corrupted data."))
        except FileNotFoundError:
            self.operation_queue.put(('error', f"Error: File '{input_path}' not found."))
        except Exception as e:
            self.operation_queue.put(('error', f"Error during decryption: {e}"))

    def _check_queue(self):
        """
        Checks the operation queue for updates and processes them.
        """
        try:
            while True:
                msg_type, value = self.operation_queue.get_nowait()
                if msg_type == 'max':
                    self.progress["maximum"] = value
                elif msg_type == 'progress':
                    self.progress["value"] = value
                elif msg_type == 'done':
                    self._update_status(value)
                    self._enable_buttons()
                    self.progress["value"] = 0
                elif msg_type == 'error':
                    self._update_status(value, is_error=True)
                    self._enable_buttons()
                    self.progress["value"] = 0
                elif msg_type == 'reset_encrypt':
                    self._reset_encrypt()
                elif msg_type == 'reset_decrypt':
                    self._reset_decrypt()
        except queue.Empty:
            pass

        if self.encrypt_button['state'] == tk.DISABLED or self.decrypt_button['state'] == tk.DISABLED:
            self.after(100, self._check_queue)

    def _disable_buttons(self):
        """
        Disables all action buttons during operation.
        """
        self.select_encrypt_button.config(state=tk.DISABLED)
        self.encrypt_button.config(state=tk.DISABLED)
        self.reset_encrypt_button.config(state=tk.DISABLED)
        self.select_decrypt_button.config(state=tk.DISABLED)
        self.decrypt_button.config(state=tk.DISABLED)
        self.reset_decrypt_button.config(state=tk.DISABLED)

    def _enable_buttons(self):
        """
        Enables action buttons after operation.
        """
        self.select_encrypt_button.config(state=tk.NORMAL)
        self.select_decrypt_button.config(state=tk.NORMAL)
        # Other buttons enabled based on selection

    def _update_status(self, message: str, is_error: bool = False):
        """
        Updates the status bar with the given message.

        Args:
            message (str): The status message.
            is_error (bool): If True, style as error.
        """
        style = "Error.TLabel" if is_error else "TLabel"
        self.status_bar.config(text=message, style=style)

if __name__ == "__main__":
    app = AegisApp()
    app.mainloop()