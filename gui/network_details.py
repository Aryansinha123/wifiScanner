import tkinter as tk
from tkinter import ttk
from typing import Dict, Any
from models.network import Network
from storage.database import DatabaseManager
from intelligence.bssid_analyzer import BSSIDAnalyzer
from security.configuration_analyzer import ConfigurationAnalyzer


class NetworkDetailsModal(tk.Toplevel):
    """
    Multi-section Network Details Modal Window.
    Displays Identity, Signal, Radio, Security, History, Changes, and Anomalies.
    """

    def __init__(self, parent: tk.Widget, network: Network, db_manager: DatabaseManager):
        super().__init__(parent)
        self.network = network
        self.db = db_manager
        self.bssid_analyzer = BSSIDAnalyzer(self.db)

        self.title(f"BSSID Profile & Intelligence — {network.ssid}")
        self.geometry("640x720")
        self.resizable(True, True)
        self.transient(parent)
        self.grab_set()

        self.create_widgets()

    def create_widgets(self):
        profile = self.bssid_analyzer.get_bssid_profile(self.network.bssid)
        config_analysis = ConfigurationAnalyzer.analyze_network_configuration(self.network)

        # Header
        hdr = ttk.Frame(self, padding=15)
        hdr.pack(fill="x")

        ttk.Label(hdr, text=f"Network Profile: {self.network.ssid}", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(hdr, text=f"BSSID: {self.network.bssid} | Vendor: {profile.get('vendor', 'Unknown Vendor')}", font=("Segoe UI", 9), foreground="#666666").pack(anchor="w")

        # Notebook Tabs
        nb = ttk.Notebook(self, padding=10)
        nb.pack(fill="both", expand=True)

        # Tab 1: Parameters & Identity
        t1 = ttk.Frame(nb, padding=15)
        nb.add(t1, text="Identity & Radio")

        params = [
            ("SSID Name:", self.network.ssid),
            ("BSSID MAC:", self.network.bssid),
            ("MAC Vendor:", profile.get("vendor", "Unknown Vendor")),
            ("Current Signal:", f"{self.network.signal_percent}% ({self.network.signal_dbm} dBm)"),
            ("Signal Range (Min/Max):", f"{profile.get('min_signal', self.network.signal_percent)}% - {profile.get('max_signal', self.network.signal_percent)}% (Avg: {profile.get('avg_signal', self.network.signal_percent)}%)"),
            ("Channel / Band:", f"Channel {self.network.channel or 'N/A'} ({self.network.band})"),
            ("Radio Standard:", self.network.radio_type),
            ("First Seen:", profile.get("first_seen", "N/A")),
            ("Last Seen:", profile.get("last_seen", "N/A")),
            ("Total Observations:", str(profile.get("observation_count", 1)))
        ]

        for idx, (k, v) in enumerate(params):
            ttk.Label(t1, text=k, font=("Segoe UI", 9, "bold")).grid(row=idx, column=0, sticky="w", py=3)
            ttk.Label(t1, text=v, font=("Segoe UI", 9)).grid(row=idx, column=1, sticky="w", padx=15, py=3)

        # Tab 2: Security Assessment
        t2 = ttk.Frame(nb, padding=15)
        nb.add(t2, text="Security Analysis")

        ttk.Label(t2, text="Security Configuration:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=2)
        ttk.Label(t2, text=f"{self.network.security} ({self.network.encryption})", font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 10))

        ttk.Label(t2, text=f"Heuristic Risk Score: {config_analysis['risk_score']} / 100 ({config_analysis['risk_level']})", font=("Segoe UI", 11, "bold"), foreground="#C0392B" if config_analysis['risk_level'] in ("HIGH", "CRITICAL") else "#27AE60").pack(anchor="w", pady=5)

        ttk.Label(t2, text="Assessment Findings:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(10, 2))
        ttk.Label(t2, text=config_analysis["summary"], font=("Segoe UI", 9, "italic"), wraplength=550).pack(anchor="w", pady=(0, 10))

        ttk.Label(t2, text="Security Rule Evaluations:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=5)
        for rule in config_analysis["rule_findings"]:
            color = "#C0392B" if rule["status"] == "FAIL" else ("#E67E22" if rule["status"] == "WARNING" else "#27AE60")
            ttk.Label(t2, text=f"• [{rule['status']}] {rule['message']}", font=("Segoe UI", 9), foreground=color).pack(anchor="w", pady=1)

        # Tab 3: History & Events
        t3 = ttk.Frame(nb, padding=15)
        nb.add(t3, text="Events & Anomalies")

        events = profile.get("events", [])
        ttk.Label(t3, text=f"Security Events ({len(events)}):", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=4)

        tree = ttk.Treeview(t3, columns=("time", "type", "desc"), show="headings", height=8)
        tree.heading("time", text="Timestamp")
        tree.heading("type", text="Type")
        tree.heading("desc", text="Description")
        tree.column("time", width=120)
        tree.column("type", width=140)
        tree.column("desc", width=260)
        tree.pack(fill="both", expand=True, pady=(0, 10))

        for ev in events[:20]:
            tree.insert("", "end", values=(ev.get("timestamp", ""), ev.get("event_type", ""), ev.get("description", "")))

        # Close button
        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill="x")
        ttk.Button(btn_frame, text="Close", command=self.destroy, width=12).pack(side="right")
