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
- Automatic key generation and management

Dependencies: tkinter, ttkthemes, cryptography
"""

import tkinter as tk
from tkinter import messagebox, filedialog
import tkinter.ttk as ttk
import ttkthemes
from cryptography.fernet import Fernet
import os

# Configuration constants
KEY_FILE = "secret.key"
THEME_CONFIG_FILE = "theme_config.txt"

# Key Management Functions

def generate_key_if_missing():
    """
    Generates a new Fernet key and saves it to KEY_FILE if it doesn't exist.

    Returns:
        tuple: (bool, str) - (key_generated, status_message)
    """
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return True, "Generated new encryption key."
    return False, "Encryption key loaded."


def load_key():
    """
    Loads the encryption key from KEY_FILE.

    Returns:
        bytes or None: The key data if found, None otherwise.
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
    Uses Fernet for secure AES encryption.
    """

    def __init__(self):
        """
        Initializes the application window, theme, styles, and UI components.
        """
        super().__init__()
        self.title("🛡️ Aegis File Encryptor")
        self.geometry("650x580")
        self.resizable(True, True)
        # Load saved theme or default
        self.saved_theme = self._load_theme()
        self.set_theme(self.saved_theme)
        self.fernet = None
        self.key_status = ""
        self.encrypt_file = ""
        self.decrypt_file = ""

        # Custom styles for elegance
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 11, "bold"), padding=(10, 5), relief="flat")
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        self.style.configure("Section.TLabel", font=("Segoe UI", 12, "bold"))
        self.style.configure("Card.TLabelframe", borderwidth=2, relief="solid")
        self.style.configure("Card.TLabelframe.Label", font=("Segoe UI", 12, "bold"))

        # Load/Generate Key and Initialize Fernet
        self._initialize_encryption()

        # Set up UI elements
        self._create_widgets()
        
        # Center the window
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def _initialize_encryption(self):
        """
        Loads or generates the encryption key and initializes the Fernet cipher object.
        Updates the key status for display in the UI.
        """
        key_generated, status_message = generate_key_if_missing()
        key = load_key()

        if key:
            self.fernet = Fernet(key)
            self.key_status = f"Ready. Key status: {status_message}"
        else:
            messagebox.showerror("Error", "Could not find or generate encryption key. Check permissions.")
            self.key_status = "Error: Key unavailable."
            self.fernet = None

    def _create_widgets(self):
        """
        Creates and arranges all GUI widgets including frames, buttons, labels, and the theme selector.
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

        self.encrypt_button = ttk.Button(button_frame1, text="Encrypt & Save", command=self._encrypt_action, state=tk.DISABLED)
        self.encrypt_button.grid(row=0, column=1)

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

        self.decrypt_button = ttk.Button(button_frame2, text="Decrypt & Save", command=self._decrypt_action, state=tk.DISABLED)
        self.decrypt_button.grid(row=0, column=1)

        # --- Status Bar ---
        status_frame = ttk.Frame(self, relief="sunken", borderwidth=1)
        status_frame.grid(row=1, column=0, sticky="ew")
        status_frame.grid_columnconfigure(0, weight=1)

        self.status_bar = ttk.Label(status_frame, text=self.key_status, padding=8, font=("Segoe UI", 9))
        self.status_bar.grid(row=0, column=0, sticky="ew")

        # Disable buttons if key is missing
        if not self.fernet:
            self.select_encrypt_button.config(state=tk.DISABLED)
            self.select_decrypt_button.config(state=tk.DISABLED)

    def _load_theme(self):
        """
        Loads the saved theme from config file, defaults to 'arc' if not found.

        Returns:
            str: The theme name.
        """
        try:
            with open(THEME_CONFIG_FILE, "r") as f:
                theme = f.read().strip()
                if theme in ttkthemes.THEMES:
                    return theme
        except FileNotFoundError:
            pass
        return "arc"

    def _save_theme(self, theme):
        """
        Saves the current theme to config file.

        Args:
            theme (str): The theme name to save.
        """
        with open(THEME_CONFIG_FILE, "w") as f:
            f.write(theme)

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

    def _select_encrypt_file(self):
        """
        Opens a file dialog for selecting a file to encrypt.
        Enables the encrypt button and updates status if a file is selected.
        """
        file_path = filedialog.askopenfilename(title="Select a file to encrypt")
        if file_path:
            self.encrypt_file = file_path
            self.encrypt_button.config(state=tk.NORMAL)
            self._update_status(f"Selected: {os.path.basename(file_path)}")

    def _select_decrypt_file(self):
        """
        Opens a file dialog for selecting an encrypted file to decrypt.
        Enables the decrypt button and updates status if a file is selected.
        """
        file_path = filedialog.askopenfilename(
            title="Select an encrypted file to decrypt",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if file_path:
            self.decrypt_file = file_path
            self.decrypt_button.config(state=tk.NORMAL)
            self._update_status(f"Selected: {os.path.basename(file_path)}")

    def _encrypt_action(self):
        """
        Handles the encryption process: reads the selected file, encrypts it,
        and saves to user-specified location. Updates UI state and status.
        """
        if not self.fernet:
            messagebox.showerror("Error", "Encryption service not initialized.")
            return

        if not self.encrypt_file:
            self._update_status("No file selected for encryption.", is_error=True)
            return

        # Choose save location
        default_name = os.path.basename(self.encrypt_file) + ".enc"
        save_path = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            defaultextension=".enc",
            initialfile=default_name,
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        if not save_path:
            return  # User cancelled

        try:
            with open(self.encrypt_file, "rb") as file:
                data_bytes = file.read()

            encrypted_data = self.fernet.encrypt(data_bytes)

            with open(save_path, "wb") as file:
                file.write(encrypted_data)

            self._update_status(f"Encrypted and saved as '{os.path.basename(save_path)}'.")
            self.encrypt_file = ""
            self.encrypt_button.config(state=tk.DISABLED)

        except Exception as e:
            self._update_status(f"Error during encryption: {e}", is_error=True)

    def _decrypt_action(self):
        """
        Handles the decryption process: reads the selected encrypted file, decrypts it,
        and saves to user-specified location. Updates UI state and status.
        """
        if not self.fernet:
            messagebox.showerror("Error", "Encryption service not initialized.")
            return

        if not self.decrypt_file:
            self._update_status("No encrypted file selected for decryption.", is_error=True)
            return

        # Suggest original filename
        base_name = os.path.basename(self.decrypt_file)
        if base_name.endswith(".enc"):
            default_name = base_name[:-4]  # Remove .enc
        else:
            default_name = base_name + "_decrypted"

        save_path = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialfile=default_name,
            filetypes=[("All files", "*.*")]
        )
        if not save_path:
            return  # User cancelled

        try:
            with open(self.decrypt_file, "rb") as file:
                encrypted_data = file.read()

            decrypted_data_bytes = self.fernet.decrypt(encrypted_data)

            with open(save_path, "wb") as file:
                file.write(decrypted_data_bytes)

            self._update_status(f"Decrypted and saved as '{os.path.basename(save_path)}'.")
            self.decrypt_file = ""
            self.decrypt_button.config(state=tk.DISABLED)

        except FileNotFoundError:
            self._update_status(f"Error: File '{self.decrypt_file}' not found.", is_error=True)
        except Exception as e:
            self._update_status(f"Error during decryption (Key invalid or data corrupted): {e}", is_error=True)

if __name__ == "__main__":
    app = AegisApp()
    app.mainloop()