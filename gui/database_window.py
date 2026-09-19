import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from storage.database import DatabaseManager


class DatabaseWindow(ttk.Frame):
    """
    Database Management & Maintenance View.
    Displays DB metrics, automated/manual backups, and safe restore.
    """

    def __init__(self, parent: tk.Widget, db_manager: DatabaseManager):
        super().__init__(parent, padding=20)
        self.db = db_manager

        self.create_widgets()
        self.refresh_db_stats()

    def create_widgets(self):
        ttk.Label(self, text="SQLite Database Management & Storage Controls", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 20))

        # 1. Info Card
        info_frame = ttk.LabelFrame(self, text=" Database Metrics ", padding=15)
        info_frame.pack(fill="x", pady=10)

        self.path_var = tk.StringVar(value=f"Path: {self.db.db_path}")
        self.size_var = tk.StringVar(value="Size: 0 KB")
        self.scans_var = tk.StringVar(value="Total Scans: 0")
        self.obs_var = tk.StringVar(value="Total Observations: 0")
        self.events_var = tk.StringVar(value="Total Events: 0")

        ttk.Label(info_frame, textvariable=self.path_var, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=2)
        ttk.Label(info_frame, textvariable=self.size_var, font=("Segoe UI", 9)).pack(anchor="w", pady=2)
        ttk.Label(info_frame, textvariable=self.scans_var, font=("Segoe UI", 9)).pack(anchor="w", pady=2)
        ttk.Label(info_frame, textvariable=self.obs_var, font=("Segoe UI", 9)).pack(anchor="w", pady=2)
        ttk.Label(info_frame, textvariable=self.events_var, font=("Segoe UI", 9)).pack(anchor="w", pady=2)

        # 2. Operations Card
        ops_frame = ttk.LabelFrame(self, text=" Backup & Restore Operations ", padding=15)
        ops_frame.pack(fill="x", pady=10)

        ttk.Button(ops_frame, text="Create Backup Now", command=self.create_backup).pack(side="left", padx=(0, 10))
        ttk.Button(ops_frame, text="Restore Database Backup", command=self.restore_backup).pack(side="left", padx=10)
        ttk.Button(ops_frame, text="Clear Event History", command=self.clear_events).pack(side="right", padx=10)

    def refresh_db_stats(self):
        db_path = self.db.db_path
        if os.path.exists(db_path):
            stat = os.stat(db_path)
            size_kb = stat.st_size / 1024
            self.size_var.set(f"Database Size: {size_kb:.2f} KB ({stat.st_size} bytes)")

        stats = self.db.get_monitoring_stats()
        self.scans_var.set(f"Total Scans Recorded: {stats.get('total_scans', 0)}")
        self.obs_var.set(f"Tracked BSSIDs: {stats.get('tracked_bssids', 0)}")
        self.events_var.set(f"Total Events Logged: {stats.get('total_events', 0)}")

    def create_backup(self):
        success, res = self.db.backup_mgr.create_backup(label="user_manual")
        if success:
            messagebox.showinfo("Backup Successful", f"Database backup created at:\n\n{res}")
        else:
            messagebox.showerror("Backup Error", f"Failed to create backup:\n\n{res}")

    def restore_backup(self):
        backups = self.db.backup_mgr.list_backups()
        if not backups:
            messagebox.showinfo("Restore Database", "No automated backups found in data/backups directory.")
            return

        filepath = filedialog.askopenfilename(
            title="Select Database Backup to Restore",
            initialdir=self.db.backup_mgr.backup_dir,
            filetypes=[("Database files", "*.db"), ("All files", "*.*")]
        )
        if not filepath:
            return

        if messagebox.askyesno("CONFIRM RESTORE", f"Are you sure you want to restore the database from:\n{filepath}\n\nCurrent database state will be safely snapshotted first."):
            success, msg = self.db.backup_mgr.restore_backup(filepath, user_confirmed=True)
            if success:
                messagebox.showinfo("Restore Complete", msg)
                self.refresh_db_stats()
            else:
                messagebox.showerror("Restore Error", msg)

    def clear_events(self):
        if messagebox.askyesno("CONFIRM CLEAR", "Are you sure you want to clear all history and events from the database?"):
            self.db.clear_history()
            self.refresh_db_stats()
            messagebox.showinfo("Cleared", "Database history cleared successfully.")
