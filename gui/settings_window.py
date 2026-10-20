import tkinter as tk
from tkinter import ttk, messagebox
from utils.config import ConfigManager
from monitoring.alert_manager import AlertManager


class SettingsWindow(ttk.Frame):
    """
    Application Settings, Monitoring Preferences, and Real-Time Alert Configuration view.
    """

    def __init__(self, parent: tk.Widget, config_mgr: ConfigManager, db_manager=None):
        super().__init__(parent, padding=20)
        self.config_mgr = config_mgr
        self.db = db_manager

        self.create_widgets()

    def create_widgets(self):
        # Header
        ttk.Label(self, text="Application Preferences & Security Alert Settings", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 15))

        # Canvas & Scrollbar container for clean display
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # =========================================================
        # SECTION 1: MONITORING CONFIGURATION
        # =========================================================
        form = ttk.LabelFrame(scrollable_frame, text=" Monitoring Configuration ", padding=15)
        form.pack(fill="x", pady=(0, 15))

        # 1. Scan Interval
        ttk.Label(form, text="Auto Scan Interval (seconds):", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", pady=6)
        self.interval_var = tk.StringVar(value=str(self.config_mgr.get("scan_interval_sec", 30)))
        interval_combo = ttk.Combobox(form, textvariable=self.interval_var, values=["10", "30", "60", "300", "600"], width=15)
        interval_combo.grid(row=0, column=1, sticky="w", padx=15, pady=6)

        # 2. Missing Scan Threshold
        ttk.Label(form, text="Missing Scan Threshold (scans):", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky="w", pady=6)
        self.threshold_var = tk.StringVar(value=str(self.config_mgr.get("missing_scan_threshold", 3)))
        ttk.Entry(form, textvariable=self.threshold_var, width=18).grid(row=1, column=1, sticky="w", padx=15, pady=6)

        # 3. Signal Change Threshold
        ttk.Label(form, text="Signal Change Threshold (%):", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky="w", pady=6)
        self.sig_thresh_var = tk.StringVar(value=str(self.config_mgr.get("signal_change_threshold", 20)))
        ttk.Entry(form, textvariable=self.sig_thresh_var, width=18).grid(row=2, column=1, sticky="w", padx=15, pady=6)

        # 4. Simulation Mode Checkbox
        self.sim_var = tk.BooleanVar(value=self.config_mgr.get("simulation_mode", False))
        ttk.Checkbutton(form, text="Enable Offline Simulation Mode (Synthetic Scenarios)", variable=self.sim_var).grid(row=3, column=0, columnspan=2, sticky="w", pady=8)

        # =========================================================
        # SECTION 2: REAL-TIME ALERT SETTINGS (Feature 2)
        # =========================================================
        alert_box = ttk.LabelFrame(scrollable_frame, text=" Real-Time Alerts & Notification Engine (Feature 2) ", padding=15)
        alert_box.pack(fill="x", pady=(0, 15))

        # 2.1 Severity Threshold
        ttk.Label(alert_box, text="Alert Severity Threshold:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", pady=6)
        self.alert_thresh_var = tk.StringVar(value=self.config_mgr.get("alert_severity_threshold", "HIGH"))
        thresh_combo = ttk.Combobox(alert_box, textvariable=self.alert_thresh_var, values=["HIGH", "CRITICAL", "MEDIUM", "ALL", "DISABLED"], state="readonly", width=18)
        thresh_combo.grid(row=0, column=1, sticky="w", padx=15, pady=6)
        ttk.Label(alert_box, text="Notifications will only trigger if severity is equal to or above this level.", font=("Segoe UI", 8, "italic"), foreground="#666666").grid(row=0, column=2, sticky="w")

        # 2.2 Cooldown Minutes
        ttk.Label(alert_box, text="Alert Cooldown (Minutes):", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky="w", pady=6)
        self.cooldown_var = tk.StringVar(value=str(self.config_mgr.get("alert_cooldown_minutes", 30)))
        cooldown_entry = ttk.Entry(alert_box, textvariable=self.cooldown_var, width=18)
        cooldown_entry.grid(row=1, column=1, sticky="w", padx=15, pady=6)
        ttk.Label(alert_box, text="Deduplication window: suppress duplicate alerts for the same BSSID within this duration.", font=("Segoe UI", 8, "italic"), foreground="#666666").grid(row=1, column=2, sticky="w")

        # 2.3 Windows Toast Notifications
        self.toast_var = tk.BooleanVar(value=self.config_mgr.get("alert_toast_enabled", True))
        ttk.Checkbutton(alert_box, text="Enable Windows Native Toast Notifications (Works 100% Offline)", variable=self.toast_var).grid(row=2, column=0, columnspan=2, sticky="w", pady=8)

        # 2.4 Telegram Notifications
        self.tele_var = tk.BooleanVar(value=self.config_mgr.get("alert_telegram_enabled", False))
        ttk.Checkbutton(alert_box, text="Enable Telegram Bot Alerts", variable=self.tele_var).grid(row=3, column=0, sticky="w", pady=6)

        tele_sub = ttk.Frame(alert_box)
        tele_sub.grid(row=4, column=0, columnspan=3, sticky="w", padx=(20, 0), pady=4)

        ttk.Label(tele_sub, text="Bot Token:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.tele_token_var = tk.StringVar(value=self.config_mgr.get("alert_telegram_bot_token", ""))
        ttk.Entry(tele_sub, textvariable=self.tele_token_var, width=32, show="*").grid(row=0, column=1, sticky="w", padx=(0, 15))

        ttk.Label(tele_sub, text="Chat ID:").grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.tele_chat_var = tk.StringVar(value=self.config_mgr.get("alert_telegram_chat_id", ""))
        ttk.Entry(tele_sub, textvariable=self.tele_chat_var, width=18).grid(row=0, column=3, sticky="w")

        # 2.5 Email Notifications
        self.email_var = tk.BooleanVar(value=self.config_mgr.get("alert_email_enabled", False))
        ttk.Checkbutton(alert_box, text="Enable SMTP Email Alerts", variable=self.email_var).grid(row=5, column=0, sticky="w", pady=6)

        email_sub = ttk.Frame(alert_box)
        email_sub.grid(row=6, column=0, columnspan=3, sticky="w", padx=(20, 0), pady=4)

        ttk.Label(email_sub, text="SMTP Server:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.smtp_server_var = tk.StringVar(value=self.config_mgr.get("alert_email_smtp_server", ""))
        ttk.Entry(email_sub, textvariable=self.smtp_server_var, width=22).grid(row=0, column=1, sticky="w", padx=(0, 10))

        ttk.Label(email_sub, text="Port:").grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.smtp_port_var = tk.StringVar(value=str(self.config_mgr.get("alert_email_smtp_port", 587)))
        ttk.Entry(email_sub, textvariable=self.smtp_port_var, width=8).grid(row=0, column=3, sticky="w", padx=(0, 10))

        ttk.Label(email_sub, text="Recipient Email:").grid(row=0, column=4, sticky="w", padx=(0, 5))
        self.smtp_to_var = tk.StringVar(value=self.config_mgr.get("alert_email_recipient", ""))
        ttk.Entry(email_sub, textvariable=self.smtp_to_var, width=22).grid(row=0, column=5, sticky="w")

        # Action Buttons
        btn_box = ttk.Frame(scrollable_frame)
        btn_box.pack(fill="x", pady=10)

        ttk.Button(btn_box, text="💾 Save Configuration", command=self.save_settings).pack(side="left", padx=(0, 10))
        ttk.Button(btn_box, text="🔔 Send Test Notification", command=self.send_test_alert).pack(side="left")

    def save_settings(self):
        try:
            interval = int(self.interval_var.get())
            threshold = int(self.threshold_var.get())
            sig_thresh = int(self.sig_thresh_var.get())
            cooldown = int(self.cooldown_var.get())

            self.config_mgr.set("scan_interval_sec", interval)
            self.config_mgr.set("missing_scan_threshold", threshold)
            self.config_mgr.set("signal_change_threshold", sig_thresh)
            self.config_mgr.set("simulation_mode", self.sim_var.get())

            # Real-Time Alert Settings
            self.config_mgr.set("alert_severity_threshold", self.alert_thresh_var.get())
            self.config_mgr.set("alert_cooldown_minutes", cooldown)
            self.config_mgr.set("alert_toast_enabled", self.toast_var.get())
            self.config_mgr.set("alert_telegram_enabled", self.tele_var.get())
            self.config_mgr.set("alert_telegram_bot_token", self.tele_token_var.get().strip())
            self.config_mgr.set("alert_telegram_chat_id", self.tele_chat_var.get().strip())
            self.config_mgr.set("alert_email_enabled", self.email_var.get())
            self.config_mgr.set("alert_email_smtp_server", self.smtp_server_var.get().strip())
            self.config_mgr.set("alert_email_smtp_port", int(self.smtp_port_var.get() or 587))
            self.config_mgr.set("alert_email_recipient", self.smtp_to_var.get().strip())

            messagebox.showinfo("Settings Saved", "Application and Alert Configuration updated successfully!")
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid numeric values for intervals and thresholds.")

    def send_test_alert(self):
        """
        Dispatches a test notification immediately across all enabled channels.
        """
        # Save current UI settings first
        self.save_settings()

        alert_mgr = AlertManager(self.db if self.db else None, self.config_mgr)
        success = alert_mgr.send_windows_toast(
            title="Wi-Fi Security Scanner Test",
            message="Offline toast alert test succeeded! Notifications are fully active."
        )

        msg = "Test Toast Notification triggered."
        if self.tele_var.get():
            token = self.tele_token_var.get().strip()
            chat_id = self.tele_chat_var.get().strip()
            if token and chat_id:
                t_ok = alert_mgr.send_telegram_alert(token, chat_id, "🔔 *Wi-Fi Scanner*: Test Notification verified successfully.")
                msg += f"\nTelegram Test: {'Sent' if t_ok else 'Failed to connect'}"

        messagebox.showinfo("Test Notification", msg)
