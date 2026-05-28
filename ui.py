"""Tkinter GUI for the Secure Backup System."""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os

from encryption import encrypt_file
from decryption import decrypt_file
from utils import validate_password_strength, format_file_size
from backup_manager import (
    generate_backup_filename,
    register_backup,
    get_all_backups,
    delete_backup_entry,
    get_vault_dir,
)
from exceptions import (
    WrongPasswordError,
    FileIntegrityError,
    CorruptedFileError,
    BackupFileNotFoundError,
)


class SecureBackupApp:
    """Main Tkinter application with Encrypt, Restore, and Backup Manager tabs."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure Backup System — AES-256 Encryption")
        self.root.geometry("680x520")
        self.root.resizable(False, False)
        self._build_ui()

    def _build_ui(self):
        """Build the notebook with three tabs."""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 1 — Encrypt
        tab1 = ttk.Frame(self.notebook)
        self.notebook.add(tab1, text="🔒  Encrypt & Backup")
        self._build_encrypt_tab(tab1)

        # Tab 2 — Restore
        tab2 = ttk.Frame(self.notebook)
        self.notebook.add(tab2, text="🔓  Restore")
        self._build_restore_tab(tab2)

        # Tab 3 — Backup Manager
        tab3 = ttk.Frame(self.notebook)
        self.notebook.add(tab3, text="🗂  Backup Manager")
        self._build_manager_tab(tab3)

    # ──────────────────────────────────────────────
    # TAB 1 — ENCRYPT
    # ──────────────────────────────────────────────

    def _build_encrypt_tab(self, parent):
        """Build the Encrypt & Backup tab layout."""
        parent.columnconfigure(1, weight=1)

        # Vault info banner
        vault_frame = tk.Frame(parent, bg="#e8f5e9", pady=6)
        vault_frame.grid(row=0, column=0, columnspan=3,
                         sticky="ew", padx=15, pady=(12, 4))
        tk.Label(
            vault_frame,
            text=f"📁  Backup Vault: {get_vault_dir()}",
            bg="#e8f5e9", fg="#2e7d32", font=("Helvetica", 9),
        ).pack(padx=8)

        # File selection
        tk.Label(parent, text="Select File to Backup:").grid(
            row=1, column=0, sticky="w", padx=15, pady=(12, 2))
        self.enc_file_path = tk.StringVar()
        tk.Entry(parent, textvariable=self.enc_file_path, width=48).grid(
            row=2, column=0, columnspan=2, padx=15, sticky="ew")
        tk.Button(parent, text="Browse",
                  command=self._browse_encrypt_file).grid(
            row=2, column=2, padx=(0, 15))

        # Password
        tk.Label(parent, text="Password:").grid(
            row=3, column=0, sticky="w", padx=15, pady=(10, 2))
        self.enc_password = tk.StringVar()
        enc_pwd_entry = tk.Entry(parent, textvariable=self.enc_password,
                                 show="*", width=35)
        enc_pwd_entry.grid(row=4, column=0, columnspan=2, padx=15, sticky="w")
        enc_pwd_entry.bind("<KeyRelease>", self._check_password_strength)

        # Confirm password
        tk.Label(parent, text="Confirm Password:").grid(
            row=5, column=0, sticky="w", padx=15, pady=(10, 2))
        self.enc_confirm_password = tk.StringVar()
        tk.Entry(parent, textvariable=self.enc_confirm_password,
                 show="*", width=35).grid(
            row=6, column=0, columnspan=2, padx=15, sticky="w")

        # Password strength label
        self.enc_strength_label = tk.Label(parent, text="", fg="orange",
                                           font=("Helvetica", 9))
        self.enc_strength_label.grid(row=7, column=0, columnspan=3,
                                     sticky="w", padx=15)

        # Encrypt button
        tk.Button(
            parent, text="🔒  Encrypt & Backup",
            command=self._on_encrypt_clicked,
            bg="#2e7d32", fg="white", width=28,
            font=("Helvetica", 10, "bold"),
        ).grid(row=8, column=0, columnspan=3, pady=14)

        # Status label
        self.enc_status_label = tk.Label(
            parent, text="", wraplength=600,
            justify="left", font=("Helvetica", 9))
        self.enc_status_label.grid(row=9, column=0, columnspan=3,
                                   padx=15, sticky="w")

    def _browse_encrypt_file(self):
        path = filedialog.askopenfilename(title="Select file to backup")
        if path:
            self.enc_file_path.set(path)

    def _check_password_strength(self, event=None):
        password = self.enc_password.get()
        warnings = validate_password_strength(password)
        if warnings:
            self.enc_strength_label.config(
                text=" | ".join(warnings), fg="orange")
        else:
            self.enc_strength_label.config(
                text="Password strength: Strong ✓", fg="green")

    def _on_encrypt_clicked(self):
        """Handle Encrypt & Backup button click."""
        file_path = self.enc_file_path.get().strip()
        password = self.enc_password.get()
        confirm = self.enc_confirm_password.get()

        if not file_path:
            self.enc_status_label.config(
                text="✗ Please select a file.", fg="red")
            return
        if not password:
            self.enc_status_label.config(
                text="✗ Please enter a password.", fg="red")
            return
        if password != confirm:
            self.enc_status_label.config(
                text="✗ Passwords do not match.", fg="red")
            return

        warnings = validate_password_strength(password)
        if warnings:
            proceed = messagebox.askokcancel(
                "Weak Password",
                "Your password is weak:\n" + "\n".join(warnings) +
                "\n\nDo you want to continue anyway?",
            )
            if not proceed:
                return

        try:
            # Generate versioned backup path inside the vault
            backup_path = generate_backup_filename(file_path)

            # Encrypt the file directly into the vault
            result = encrypt_file(file_path, password, backup_path)

            # Register in backup registry
            register_backup(
                original_path=file_path,
                backup_path=backup_path,
                original_hash=result["original_hash"],
                file_size=result["file_size"],
            )

            size_str = format_file_size(result["file_size"])
            self.enc_status_label.config(
                text=(
                    f"✓ Backup created successfully!\n"
                    f"Vault: {backup_path}\n"
                    f"Size: {size_str}\n"
                    f"SHA-256: {result['original_hash'][:40]}..."
                ),
                fg="green",
            )

        except BackupFileNotFoundError as e:
            self.enc_status_label.config(text=f"✗ File not found: {e}", fg="red")
        except Exception as e:
            self.enc_status_label.config(
                text=f"✗ Backup failed: {e}", fg="red")

    # ──────────────────────────────────────────────
    # TAB 2 — RESTORE
    # ──────────────────────────────────────────────

    def _build_restore_tab(self, parent):
        """Build the Restore tab layout."""
        parent.columnconfigure(1, weight=1)

        tk.Label(parent, text="Select Encrypted Backup (.enc):").grid(
            row=0, column=0, sticky="w", padx=15, pady=(12, 2))
        self.dec_file_path = tk.StringVar()
        tk.Entry(parent, textvariable=self.dec_file_path, width=48).grid(
            row=1, column=0, columnspan=2, padx=15, sticky="ew")
        tk.Button(parent, text="Browse",
                  command=self._browse_decrypt_file).grid(
            row=1, column=2, padx=(0, 15))

        tk.Label(parent, text="Password:").grid(
            row=2, column=0, sticky="w", padx=15, pady=(10, 2))
        self.dec_password = tk.StringVar()
        tk.Entry(parent, textvariable=self.dec_password,
                 show="*", width=35).grid(
            row=3, column=0, columnspan=2, padx=15, sticky="w")

        tk.Label(parent, text="Restore To Folder (optional):").grid(
            row=4, column=0, sticky="w", padx=15, pady=(10, 2))
        self.dec_output_folder = tk.StringVar()
        tk.Entry(parent, textvariable=self.dec_output_folder, width=48).grid(
            row=5, column=0, columnspan=2, padx=15, sticky="ew")
        tk.Button(parent, text="Browse",
                  command=self._browse_output_folder).grid(
            row=5, column=2, padx=(0, 15))

        tk.Button(
            parent, text="🔓  Restore File",
            command=self._on_restore_clicked,
            bg="#1565c0", fg="white", width=28,
            font=("Helvetica", 10, "bold"),
        ).grid(row=6, column=0, columnspan=3, pady=14)

        self.dec_status_label = tk.Label(
            parent, text="", wraplength=600,
            justify="left", font=("Helvetica", 9))
        self.dec_status_label.grid(row=7, column=0, columnspan=3,
                                   padx=15, sticky="w")

    def _browse_decrypt_file(self):
        path = filedialog.askopenfilename(
            title="Select backup file",
            filetypes=[("Encrypted backups", "*.enc"), ("All files", "*.*")],
            initialdir=get_vault_dir(),
        )
        if path:
            self.dec_file_path.set(path)

    def _browse_output_folder(self):
        folder = filedialog.askdirectory(title="Select restore folder")
        if folder:
            self.dec_output_folder.set(folder)

    def _on_restore_clicked(self):
        """Handle Restore File button click."""
        enc_path = self.dec_file_path.get().strip()
        password = self.dec_password.get()
        output_folder = self.dec_output_folder.get().strip() or None

        if not enc_path:
            self.dec_status_label.config(
                text="✗ Please select a backup file.", fg="red")
            return
        if not password:
            self.dec_status_label.config(
                text="✗ Please enter a password.", fg="red")
            return

        try:
            result = decrypt_file(enc_path, password, output_folder)
            self.dec_status_label.config(
                text=(
                    f"✓ File restored successfully!\n"
                    f"Saved to: {result['output_path']}\n"
                    f"Integrity: {result['integrity']}\n"
                    f"SHA-256 verified: {result['original_hash'][:40]}..."
                ),
                fg="green",
            )

        except WrongPasswordError:
            self.dec_status_label.config(
                text="✗ Incorrect password. Please check and try again.",
                fg="red")
        except FileIntegrityError:
            self.dec_status_label.config(
                text="✗ Integrity check failed. Backup may be corrupted.",
                fg="red")
        except CorruptedFileError:
            self.dec_status_label.config(
                text="✗ Selected file is not a valid encrypted backup.",
                fg="red")
        except BackupFileNotFoundError as e:
            self.dec_status_label.config(text=f"✗ File not found: {e}",
                                         fg="red")
        except Exception as e:
            self.dec_status_label.config(text=f"✗ Restore failed: {e}",
                                         fg="red")

    # ──────────────────────────────────────────────
    # TAB 3 — BACKUP MANAGER
    # ──────────────────────────────────────────────

    def _build_manager_tab(self, parent):
        """Build the Backup Manager tab showing all stored backups."""
        # Header row
        header_frame = tk.Frame(parent)
        header_frame.pack(fill="x", padx=15, pady=(12, 4))

        tk.Label(
            header_frame,
            text="All Backups in Vault",
            font=("Helvetica", 11, "bold"),
        ).pack(side="left")

        tk.Button(
            header_frame, text="⟳  Refresh",
            command=self._refresh_manager,
            font=("Helvetica", 9),
        ).pack(side="right")

        tk.Button(
            header_frame, text="📂  Open Vault Folder",
            command=self._open_vault_folder,
            font=("Helvetica", 9),
        ).pack(side="right", padx=6)

        # Treeview table
        columns = ("original_name", "timestamp", "encrypted_size")
        self.tree = ttk.Treeview(parent, columns=columns,
                                 show="headings", height=10)
        self.tree.heading("original_name", text="Original File")
        self.tree.heading("timestamp",     text="Backup Date & Time")
        self.tree.heading("encrypted_size", text="Backup Size")
        self.tree.column("original_name",  width=220)
        self.tree.column("timestamp",      width=170)
        self.tree.column("encrypted_size", width=110, anchor="center")

        scrollbar = ttk.Scrollbar(parent, orient="vertical",
                                  command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side="left", fill="both", expand=True,
                       padx=(15, 0), pady=4)
        scrollbar.pack(side="left", fill="y", pady=4)

        # Action buttons below table
        btn_frame = tk.Frame(parent)
        btn_frame.pack(fill="x", padx=15, pady=8)

        tk.Button(
            btn_frame, text="🔓  Restore Selected",
            command=self._restore_selected,
            bg="#1565c0", fg="white", width=20,
        ).pack(side="left", padx=(0, 8))

        tk.Button(
            btn_frame, text="🗑  Delete Selected",
            command=self._delete_selected,
            bg="#c62828", fg="white", width=20,
        ).pack(side="left")

        # Status label for manager tab
        self.mgr_status_label = tk.Label(
            parent, text="", fg="green",
            wraplength=600, font=("Helvetica", 9))
        self.mgr_status_label.pack(padx=15, anchor="w")

        # Load backups on first open
        self._refresh_manager()

    def _refresh_manager(self):
        """Reload the backup list from the registry into the treeview."""
        for row in self.tree.get_children():
            self.tree.delete(row)

        backups = get_all_backups()
        if not backups:
            self.tree.insert("", "end", values=(
                "No backups found.", "", ""))
            return

        for entry in backups:
            size_str = format_file_size(entry["encrypted_size"])
            self.tree.insert("", "end", iid=entry["backup_path"], values=(
                entry["original_name"],
                entry["timestamp"],
                size_str,
            ))

    def _open_vault_folder(self):
        """Open the vault folder in the system file explorer."""
        vault = get_vault_dir()
        os.startfile(vault)

    def _restore_selected(self):
        """Restore the backup selected in the treeview."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection",
                                   "Please select a backup to restore.")
            return

        backup_path = selected[0]

        # Ask for password via popup dialog
        dialog = PasswordDialog(self.root, "Enter password to restore backup:")
        self.root.wait_window(dialog.top)

        if not dialog.password:
            return

        try:
            # Restore to Downloads folder by default
            output_folder = os.path.join(os.path.expanduser("~"), "Downloads")
            result = decrypt_file(backup_path, dialog.password, output_folder)
            self.mgr_status_label.config(
                text=(f"✓ Restored to: {result['output_path']}  "
                      f"| Integrity: {result['integrity']}"),
                fg="green",
            )
        except WrongPasswordError:
            self.mgr_status_label.config(
                text="✗ Incorrect password.", fg="red")
        except FileIntegrityError:
            self.mgr_status_label.config(
                text="✗ Integrity check failed.", fg="red")
        except Exception as e:
            self.mgr_status_label.config(
                text=f"✗ Restore failed: {e}", fg="red")

    def _delete_selected(self):
        """Delete the selected backup from vault and registry."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection",
                                   "Please select a backup to delete.")
            return

        backup_path = selected[0]
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Permanently delete this backup?\n{backup_path}",
        )
        if not confirm:
            return

        try:
            delete_backup_entry(backup_path)
            self._refresh_manager()
            self.mgr_status_label.config(
                text="✓ Backup deleted successfully.", fg="green")
        except Exception as e:
            self.mgr_status_label.config(
                text=f"✗ Delete failed: {e}", fg="red")


# ──────────────────────────────────────────────
# PASSWORD DIALOG (popup for manager tab restore)
# ──────────────────────────────────────────────

class PasswordDialog:
    """Simple modal dialog to collect a password string."""

    def __init__(self, parent, prompt: str):
        self.password = None
        self.top = tk.Toplevel(parent)
        self.top.title("Enter Password")
        self.top.geometry("340x140")
        self.top.resizable(False, False)
        self.top.grab_set()

        tk.Label(self.top, text=prompt,
                 wraplength=300).pack(pady=(16, 6), padx=16)

        self.pwd_var = tk.StringVar()
        tk.Entry(self.top, textvariable=self.pwd_var,
                 show="*", width=30).pack(padx=16)

        tk.Button(
            self.top, text="OK",
            command=self._on_ok,
            bg="#1565c0", fg="white", width=12,
        ).pack(pady=12)

    def _on_ok(self):
        self.password = self.pwd_var.get()
        self.top.destroy()