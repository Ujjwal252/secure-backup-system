"""Secure Backup System — Main Entry Point
========================================
Run this file to launch the application:
    python main.py

Modules:
    ui.py         — Tkinter GUI (SecureBackupApp class)
    encryption.py — AES-256-GCM file encryption
    decryption.py — AES-256-GCM file decryption
    key_manager.py — PBKDF2 key derivation
    integrity.py   — SHA-256 integrity verification
    utils.py       — Helper utilities
    exceptions.py  — Custom exception classes
    constants.py   — Project-wide constants
"""

import tkinter as tk
from ui import SecureBackupApp

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureBackupApp(root)
    root.mainloop()
