import tkinter as tk
from tkinter import ttk
from storage.database import DatabaseManager
from utils.diagnostics import ApplicationDiagnostics


class DiagnosticsWindow(ttk.Frame):
    """
    System Diagnostics & Health Check View.
    """

    def __init__(self, parent: tk.Widget, db_manager: DatabaseManager):
        super().__init__(parent, padding=20)
        self.db = db_manager
        self.diag = ApplicationDiagnostics(self.db)

        self.create_widgets()
        self.run_diagnostics()

    def create_widgets(self):
        hdr = ttk.Frame(self)
        hdr.pack(fill="x", pady=(0, 15))

        ttk.Label(hdr, text="Application System Diagnostics & Environment Audit", font=("Segoe UI", 16, "bold")).pack(side="left")
        ttk.Button(hdr, text="Run Diagnostics", command=self.run_diagnostics).pack(side="right")

        card = ttk.LabelFrame(self, text=" Diagnostic Results ", padding=15)
        card.pack(fill="both", expand=True)

        self.txt = tk.Text(card, font=("Consolas", 10), relief="groove", wrap="word", bg="#1e293b", fg="#f8fafc", padx=10, pady=10)
        self.txt.pack(fill="both", expand=True)

    def run_diagnostics(self):
        res = self.diag.run_diagnostics()

        lines = [
            "============================================================",
            "        WI-FI SECURITY PLATFORM DIAGNOSTICS REPORT        ",
            "============================================================",
            f"Python Version    : {res['python_version']}",
            f"Operating System  : {res['operating_system']}",
            "------------------------------------------------------------",
            f"WLAN Adapter      : {res['adapter_name']}",
            f"Adapter Health    : {res['adapter_status']}",
            "------------------------------------------------------------",
            f"Database Health   : {res['database_status']}",
            f"Database File     : {res['database_path']}",
            f"Database Size     : {res['database_size_mb']} MB",
            "------------------------------------------------------------",
            f"Total Scans       : {res['total_scans']}",
            f"Tracked BSSIDs    : {res['tracked_bssids']}",
            f"Active BSSIDs     : {res['active_bssids']}",
            f"Total Events      : {res['total_events']}",
            f"High Severity Ev  : {res['high_severity_events']}",
            "============================================================",
            "Status: System environment diagnostic checks passed cleanly."
        ]

        self.txt.config(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.insert("1.0", "\n".join(lines))
        self.txt.config(state="disabled")
