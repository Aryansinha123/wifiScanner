import tkinter as tk
from tkinter import ttk, messagebox
from utils.config import ConfigManager


class SettingsWindow(ttk.Frame):
    """
    Application Settings and Configuration Preferences view.
    """

    def __init__(self, parent: tk.Widget, config_mgr: ConfigManager):
        super().__init__(parent, padding=20)
        self.config_mgr = config_mgr

        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Application Preferences & Monitoring Settings", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 20))

        form = ttk.LabelFrame(self, text=" Monitoring Configuration ", padding=15)
        form.pack(fill="x", pady=10)

        # 1. Scan Interval
        ttk.Label(form, text="Auto Scan Interval (seconds):", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", pady=8)
        self.interval_var = tk.StringVar(value=str(self.config_mgr.get("scan_interval_sec", 30)))
        interval_combo = ttk.Combobox(form, textvariable=self.interval_var, values=["10", "30", "60", "300", "600"], width=15)
        interval_combo.grid(row=0, column=1, sticky="w", padx=15, pady=8)

        # 2. Missing Scan Threshold
        ttk.Label(form, text="Missing Scan Threshold (scans):", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky="w", pady=8)
        self.threshold_var = tk.StringVar(value=str(self.config_mgr.get("missing_scan_threshold", 3)))
        ttk.Entry(form, textvariable=self.threshold_var, width=18).grid(row=1, column=1, sticky="w", padx=15, pady=8)

        # 3. Signal Change Threshold
        ttk.Label(form, text="Signal Change Threshold (%):", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky="w", pady=8)
        self.sig_thresh_var = tk.StringVar(value=str(self.config_mgr.get("signal_change_threshold", 20)))
        ttk.Entry(form, textvariable=self.sig_thresh_var, width=18).grid(row=2, column=1, sticky="w", padx=15, pady=8)

        # 4. Simulation Mode Checkbox
        self.sim_var = tk.BooleanVar(value=self.config_mgr.get("simulation_mode", False))
        ttk.Checkbutton(form, text="Enable Offline Simulation Mode (Synthetic Scenario Testing)", variable=self.sim_var).grid(row=3, column=0, columnspan=2, sticky="w", pady=12)

        # Save Button
        ttk.Button(form, text="Save Settings", command=self.save_settings).grid(row=4, column=0, sticky="w", pady=(15, 0))

    def save_settings(self):
        try:
            interval = int(self.interval_var.get())
            threshold = int(self.threshold_var.get())
            sig_thresh = int(self.sig_thresh_var.get())

            self.config_mgr.set("scan_interval_sec", interval)
            self.config_mgr.set("missing_scan_threshold", threshold)
            self.config_mgr.set("signal_change_threshold", sig_thresh)
            self.config_mgr.set("simulation_mode", self.sim_var.get())

            messagebox.showinfo("Settings Saved", "Application configuration settings updated successfully!")
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid numeric values for configuration options.")
