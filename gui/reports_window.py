import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List
from models.network import Network
from storage.database import DatabaseManager
from reports.report_generator import ReportGenerator


class ReportsWindow(ttk.Frame):
    """
    Security Report Generation and Export View.
    Allows exporting HTML security reports, CSV datasets, and JSON archives.
    """

    def __init__(self, parent: tk.Widget, db_manager: DatabaseManager):
        super().__init__(parent, padding=20)
        self.db = db_manager
        self.report_gen = ReportGenerator(self.db)
        self.networks: List[Network] = []

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Security Report & Data Export Center", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 15))

        # Card 1: HTML Executive Report
        card1 = ttk.LabelFrame(self, text=" HTML Executive Security Report ", padding=15)
        card1.pack(fill="x", pady=8)

        ttk.Label(card1, text="Generates a standalone, styled HTML executive report including summary statistics, network details, event logs, passive anomalies, and security limitations statement.", font=("Segoe UI", 9), wraplength=700).pack(anchor="w", pady=(0, 10))

        ttk.Button(card1, text="Generate HTML Report", command=self.generate_html_report).pack(anchor="w")

        # Card 2: CSV Data Export
        card2 = ttk.LabelFrame(self, text=" CSV Dataset Exports ", padding=15)
        card2.pack(fill="x", pady=8)

        ttk.Label(card2, text="Export network history, security events, or passive anomalies to standard CSV files for offline analysis.", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 10))

        btn_grid = ttk.Frame(card2)
        btn_grid.pack(anchor="w")

        ttk.Button(btn_grid, text="Export Networks (CSV)", command=lambda: self.export_csv("networks")).pack(side="left", padx=(0, 10))
        ttk.Button(btn_grid, text="Export Events (CSV)", command=lambda: self.export_csv("events")).pack(side="left", padx=10)
        ttk.Button(btn_grid, text="Export Anomalies (CSV)", command=lambda: self.export_csv("anomalies")).pack(side="left", padx=10)

        # Card 3: JSON Dataset Export
        card3 = ttk.LabelFrame(self, text=" JSON Dataset Exports ", padding=15)
        card3.pack(fill="x", pady=8)

        ttk.Label(card3, text="Export raw structured dataset JSON files for integration or archiving.", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 10))

        json_btn_grid = ttk.Frame(card3)
        json_btn_grid.pack(anchor="w")

        ttk.Button(json_btn_grid, text="Export Networks (JSON)", command=lambda: self.export_json("networks")).pack(side="left", padx=(0, 10))
        ttk.Button(json_btn_grid, text="Export Events (JSON)", command=lambda: self.export_json("events")).pack(side="left", padx=10)
        ttk.Button(json_btn_grid, text="Export Active Baseline (JSON)", command=lambda: self.export_json("baseline")).pack(side="left", padx=10)

    def update_networks(self, networks: List[Network]):
        self.networks = networks

    def generate_html_report(self):
        filepath = filedialog.asksaveasfilename(
            title="Save Executive HTML Report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")]
        )
        if not filepath:
            return

        success = self.report_gen.generate_html_report(self.networks, filepath)
        if success:
            messagebox.showinfo("Report Generated", f"Executive HTML Security Report created successfully:\n\n{filepath}")
        else:
            messagebox.showerror("Error", "Failed to generate HTML report.")

    def export_csv(self, dataset: str):
        filepath = filedialog.asksaveasfilename(
            title=f"Export {dataset.capitalize()} to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not filepath:
            return

        success = self.report_gen.generate_csv_report(dataset, filepath, self.networks if dataset == "networks" else None)
        if success:
            messagebox.showinfo("Export Successful", f"Successfully exported {dataset} dataset to:\n\n{filepath}")
        else:
            messagebox.showerror("Export Error", f"Failed to export {dataset} CSV.")

    def export_json(self, dataset: str):
        filepath = filedialog.asksaveasfilename(
            title=f"Export {dataset.capitalize()} to JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not filepath:
            return

        success = self.report_gen.generate_json_export(dataset, filepath, self.networks if dataset == "networks" else None)
        if success:
            messagebox.showinfo("Export Successful", f"Successfully exported {dataset} dataset to JSON:\n\n{filepath}")
        else:
            messagebox.showerror("Export Error", f"Failed to export {dataset} JSON.")
