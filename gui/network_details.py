import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, Any
from models.network import Network
from storage.database import DatabaseManager
from intelligence.bssid_analyzer import BSSIDAnalyzer
from security.configuration_analyzer import ConfigurationAnalyzer


class NetworkDetailsModal(tk.Toplevel):
    """
    Multi-section Network Details Modal Window.
    Displays Identity, Signal, Radio, Security, Weak Configuration Analysis, History, and Trusted AP controls.
    """

    def __init__(self, parent: tk.Widget, network: Network, db_manager: DatabaseManager):
        super().__init__(parent)
        self.network = network
        self.db = db_manager
        self.bssid_analyzer = BSSIDAnalyzer(self.db)

        self.title(f"BSSID Profile & Intelligence — {network.ssid}")
        self.geometry("680x760")
        self.resizable(True, True)
        self.transient(parent)
        self.grab_set()

        self.create_widgets()

    def create_widgets(self):
        profile = self.bssid_analyzer.get_bssid_profile(self.network.bssid)
        config_analysis = ConfigurationAnalyzer.analyze_network_configuration(self.network)
        is_trusted = self.db.repos.is_bssid_trusted(self.network.bssid)

        # Header
        hdr = ttk.Frame(self, padding=15)
        hdr.pack(fill="x")

        title_text = f"Network Profile: {self.network.ssid}" + (" [⭐ TRUSTED AP]" if is_trusted else "")
        ttk.Label(hdr, text=title_text, font=("Segoe UI", 14, "bold"), foreground="#27AE60" if is_trusted else "#000000").pack(anchor="w")
        ttk.Label(hdr, text=f"BSSID: {self.network.bssid} | Vendor: {profile.get('vendor', 'Unknown Vendor')}", font=("Segoe UI", 9), foreground="#666666").pack(anchor="w")

        # Notebook Tabs
        nb = ttk.Notebook(self, padding=10)
        nb.pack(fill="both", expand=True)

        # ---------------------------------------------------------
        # Tab 1: Parameters & Identity
        # ---------------------------------------------------------
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
            ("Total Observations:", str(profile.get("observation_count", 1))),
            ("Trusted Status:", "⭐ Trusted Network" if is_trusted else "Standard (Untrusted)")
        ]

        for idx, (k, v) in enumerate(params):
            ttk.Label(t1, text=k, font=("Segoe UI", 9, "bold")).grid(row=idx, column=0, sticky="w", py=3)
            ttk.Label(t1, text=v, font=("Segoe UI", 9)).grid(row=idx, column=1, sticky="w", padx=15, py=3)

        # ---------------------------------------------------------
        # Tab 2: Security & Weak-Configuration Checks (Feature 3)
        # ---------------------------------------------------------
        t2 = ttk.Frame(nb, padding=15)
        nb.add(t2, text="Security & Weak Config")

        ttk.Label(t2, text="Security Configuration:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=2)
        ttk.Label(t2, text=f"{self.network.security} ({self.network.encryption})", font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 6))

        ttk.Label(t2, text=f"Heuristic Risk Score: {config_analysis['risk_score']} / 100 ({config_analysis['risk_level']})",
                  font=("Segoe UI", 11, "bold"),
                  foreground="#C0392B" if config_analysis['risk_level'] in ("HIGH", "CRITICAL") else "#27AE60").pack(anchor="w", pady=4)

        # Feature 3: Weak Configuration Rules Triggered
        weak_findings = config_analysis.get("weak_config_findings", [])
        ttk.Label(t2, text=f"Weak-Configuration Checks ({len(weak_findings)}):", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(8, 2))

        if weak_findings:
            for wf in weak_findings:
                ttk.Label(t2, text=f"⚠️ {wf['name']} (+{wf['points']} pts): {wf['reason']}",
                          font=("Segoe UI", 8), foreground="#C0392B" if wf["severity"] in ("CRITICAL", "HIGH") else "#D35400",
                          wraplength=600).pack(anchor="w", pady=2)
        else:
            ttk.Label(t2, text="✓ No common weak-configuration patterns identified.", font=("Segoe UI", 8), foreground="#27AE60").pack(anchor="w", pady=2)

        ttk.Label(t2, text="* Note: WPS & PMF (802.11w) require monitor-mode raw frames (not netsh exposed).",
                  font=("Segoe UI", 7, "italic"), foreground="#888888").pack(anchor="w", pady=(4, 8))

        # Standard Security Rule Evaluations
        ttk.Label(t2, text="Security Baseline Rules:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(6, 2))
        for rule in config_analysis["rule_findings"]:
            color = "#C0392B" if rule["status"] == "FAIL" else ("#E67E22" if rule["status"] == "WARNING" else "#27AE60")
            ttk.Label(t2, text=f"• [{rule['status']}] {rule['message']}", font=("Segoe UI", 8), foreground=color).pack(anchor="w", pady=1)

        # ---------------------------------------------------------
        # Tab 3: History & Events
        # ---------------------------------------------------------
        t3 = ttk.Frame(nb, padding=15)
        nb.add(t3, text="Events & History")

        events = profile.get("events", [])
        ttk.Label(t3, text=f"Recorded Security Events ({len(events)}):", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=4)

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

        # Bottom Buttons Bar
        btn_frame = ttk.Frame(self, padding=10)
        btn_frame.pack(fill="x")

        if not is_trusted:
            ttk.Button(btn_frame, text="⭐ Mark as Trusted Network", command=self.mark_as_trusted).pack(side="left")
        else:
            ttk.Button(btn_frame, text="Remove from Trusted", command=self.remove_from_trusted).pack(side="left")

        ttk.Button(btn_frame, text="Close", command=self.destroy, width=12).pack(side="right")

    def mark_as_trusted(self):
        res = self.db.repos.add_trusted_network(
            ssid=self.network.ssid,
            bssid=self.network.bssid,
            vendor=self.network.vendor,
            security=self.network.security,
            channel=self.network.channel,
            notes="Marked as trusted from Network Details"
        )
        if res != -1:
            messagebox.showinfo("Success", f"Network '{self.network.ssid}' ({self.network.bssid}) added to Trusted Allowlist!")
            self.destroy()
        else:
            messagebox.showerror("Error", "Failed to mark network as trusted.")

    def remove_from_trusted(self):
        self.db.repos.remove_trusted_network(self.network.bssid)
        messagebox.showinfo("Untrusted", f"Network '{self.network.ssid}' removed from Trusted Allowlist.")
        self.destroy()
