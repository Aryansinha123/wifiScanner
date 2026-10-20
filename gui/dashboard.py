import threading
import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any, Callable
from models.network import Network
from storage.database import DatabaseManager
from monitoring.connection_integrity import ConnectionIntegrityMonitor


class DashboardView(ttk.Frame):
    """
    Executive Summary Dashboard view for the Wi-Fi Security Platform.
    Displays metric cards, Connection Health & Integrity panel (Feature 5),
    Security Distribution, Baseline Intelligence, and Live Alert Feed.
    """

    def __init__(self, parent: tk.Widget, db_manager: DatabaseManager, on_navigate: Callable[[str], None] = None):
        super().__init__(parent, padding=15)
        self.db = db_manager
        self.on_navigate = on_navigate
        self.conn_monitor = ConnectionIntegrityMonitor(self.db)

        self.networks: List[Network] = []

        # Configure weights
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

        self.create_widgets()
        self.refresh_dashboard()

    def create_widgets(self):
        # 1. Header Frame
        hdr_frame = ttk.Frame(self)
        hdr_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))

        title = ttk.Label(hdr_frame, text="Wi-Fi Security Intelligence Dashboard", font=("Segoe UI", 16, "bold"))
        title.pack(side="left")

        self.status_var = tk.StringVar(value="Monitoring: ACTIVE")
        self.status_lbl = ttk.Label(hdr_frame, textvariable=self.status_var, font=("Segoe UI", 10, "bold"), foreground="#27AE60")
        self.status_lbl.pack(side="right")

        # 2. Metric Cards Grid
        cards_frame = ttk.Frame(self)
        cards_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 12))

        for i in range(6):
            cards_frame.columnconfigure(i, weight=1)

        self.card_vars = {
            "total_nets": tk.StringVar(value="0"),
            "ssids": tk.StringVar(value="0"),
            "active_bssids": tk.StringVar(value="0"),
            "open_nets": tk.StringVar(value="0"),
            "high_events": tk.StringVar(value="0"),
            "anomalies": tk.StringVar(value="0")
        }

        card_defs = [
            ("TOTAL NETWORKS", self.card_vars["total_nets"], 0, "#2980B9"),
            ("UNIQUE SSIDs", self.card_vars["ssids"], 1, "#8E44AD"),
            ("ACTIVE BSSIDs", self.card_vars["active_bssids"], 2, "#16A085"),
            ("OPEN NETWORKS", self.card_vars["open_nets"], 3, "#C0392B"),
            ("HIGH ALERTS", self.card_vars["high_events"], 4, "#D35400"),
            ("ANOMALIES", self.card_vars["anomalies"], 5, "#E67E22")
        ]

        for title, var, col, color in card_defs:
            card = ttk.LabelFrame(cards_frame, text=f" {title} ", padding=8)
            card.grid(row=0, column=col, padx=3, sticky="nsew")
            lbl = ttk.Label(card, textvariable=var, font=("Segoe UI", 16, "bold"), foreground=color)
            lbl.pack(anchor="center")

        # 3. Main Split
        left_frame = ttk.Frame(self)
        left_frame.grid(row=2, column=0, sticky="nsew", padx=(0, 8))
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(0, weight=1)
        left_frame.rowconfigure(1, weight=1)
        left_frame.rowconfigure(2, weight=1)

        right_frame = ttk.Frame(self)
        right_frame.grid(row=2, column=1, sticky="nsew", padx=(8, 0))
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(0, weight=1)

        # ---------------------------------------------------------
        # 3.1 CONNECTION HEALTH & INTEGRITY PANEL (Feature 5)
        # ---------------------------------------------------------
        conn_box = ttk.LabelFrame(left_frame, text=" 🛡️ Connection Health & Integrity (Feature 5) ", padding=10)
        conn_box.grid(row=0, column=0, sticky="nsew", pady=(0, 8))
        conn_box.columnconfigure(1, weight=1)

        # Row 0: Connected Network
        ttk.Label(conn_box, text="Connected Link:", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", pady=2)
        self.conn_ssid_var = tk.StringVar(value="Detecting interface...")
        ttk.Label(conn_box, textvariable=self.conn_ssid_var, font=("Segoe UI", 9, "bold"), foreground="#2980B9").grid(row=0, column=1, sticky="w", padx=10)

        # Row 1: Gateway MAC
        ttk.Label(conn_box, text="Gateway MAC:", font=("Segoe UI", 9, "bold")).grid(row=1, column=0, sticky="w", pady=2)
        self.gw_mac_var = tk.StringVar(value="Gateway MAC: Resolving...")
        self.gw_status_lbl = ttk.Label(conn_box, textvariable=self.gw_mac_var, font=("Segoe UI", 9))
        self.gw_status_lbl.grid(row=1, column=1, sticky="w", padx=10)

        # Row 2: DNS Integrity
        ttk.Label(conn_box, text="DNS Integrity:", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky="w", pady=2)
        self.dns_var = tk.StringVar(value="DNS: Cross-checking canary DoH...")
        self.dns_status_lbl = ttk.Label(conn_box, textvariable=self.dns_var, font=("Segoe UI", 9))
        self.dns_status_lbl.grid(row=2, column=1, sticky="w", padx=10)

        # Row 3: Status Badge & Check Button
        status_sub = ttk.Frame(conn_box)
        status_sub.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0))

        ttk.Label(status_sub, text="Overall Health:", font=("Segoe UI", 9, "bold")).pack(side="left")
        self.health_status_var = tk.StringVar(value="SAFE")
        self.health_badge = ttk.Label(status_sub, textvariable=self.health_status_var, font=("Segoe UI", 10, "bold"), foreground="#27AE60")
        self.health_badge.pack(side="left", padx=8)

        ttk.Button(status_sub, text="Check Connection Health", command=self.check_connection_health_async).pack(side="right")

        # ---------------------------------------------------------
        # 3.2 Security Distribution Box
        # ---------------------------------------------------------
        sec_box = ttk.LabelFrame(left_frame, text=" Wireless Security Protocol Distribution ", padding=8)
        sec_box.grid(row=1, column=0, sticky="nsew", pady=(0, 8))

        self.sec_tree = ttk.Treeview(sec_box, columns=("protocol", "count", "pct"), show="headings", height=4)
        self.sec_tree.heading("protocol", text="Security Protocol")
        self.sec_tree.heading("count", text="Networks")
        self.sec_tree.heading("pct", text="Share")
        self.sec_tree.column("protocol", width=140)
        self.sec_tree.column("count", width=70, anchor="center")
        self.sec_tree.column("pct", width=70, anchor="center")
        self.sec_tree.pack(fill="both", expand=True)

        # ---------------------------------------------------------
        # 3.3 Baseline & Environment Status Box
        # ---------------------------------------------------------
        base_box = ttk.LabelFrame(left_frame, text=" Baseline & Environment Intelligence ", padding=8)
        base_box.grid(row=2, column=0, sticky="nsew")

        self.baseline_status_var = tk.StringVar(value="Active Baseline: None Established")
        ttk.Label(base_box, textvariable=self.baseline_status_var, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=1)

        self.env_summary_var = tk.StringVar(value="Establish an environment baseline to track rogue APs and anomalies.")
        ttk.Label(base_box, textvariable=self.env_summary_var, font=("Segoe UI", 8), wraplength=380).pack(anchor="w", pady=2)

        if self.on_navigate:
            ttk.Button(base_box, text="Manage Baselines & Trusted APs", command=lambda: self.on_navigate("Baseline")).pack(anchor="e", pady=(3, 0))

        # ---------------------------------------------------------
        # 3.4 Recent Security Events & Live Feed
        # ---------------------------------------------------------
        alerts_box = ttk.LabelFrame(right_frame, text=" Live Security Events & Alerts Feed ", padding=10)
        alerts_box.grid(row=0, column=0, sticky="nsew")
        alerts_box.rowconfigure(0, weight=1)
        alerts_box.columnconfigure(0, weight=1)

        self.events_tree = ttk.Treeview(alerts_box, columns=("time", "type", "sev", "desc"), show="headings")
        self.events_tree.heading("time", text="Timestamp")
        self.events_tree.heading("type", text="Event Type")
        self.events_tree.heading("sev", text="Severity")
        self.events_tree.heading("desc", text="Description")

        self.events_tree.column("time", width=100)
        self.events_tree.column("type", width=140)
        self.events_tree.column("sev", width=75, anchor="center")
        self.events_tree.column("desc", width=220)

        self.events_tree.pack(fill="both", expand=True)

    def check_connection_health_async(self):
        thread = threading.Thread(target=self._run_connection_check, daemon=True)
        thread.start()

    def _run_connection_check(self):
        res = self.conn_monitor.run_integrity_check()
        self.after(0, lambda: self._apply_connection_health(res))

    def _apply_connection_health(self, res: Dict[str, Any]):
        if not res.get("connected"):
            self.conn_ssid_var.set("Not Connected to Wi-Fi")
            self.gw_mac_var.set("N/A")
            self.dns_var.set("N/A")
            self.health_status_var.set("SAFE")
            self.health_badge.config(foreground="#7F8C8D")
            return

        ssid = res.get("ssid", "Unknown")
        bssid = res.get("bssid", "N/A")
        gw_ip = res.get("gateway_ip", "N/A")
        gw_mac = res.get("gateway_mac", "N/A")
        arp_status = res.get("arp_status", "STABLE")
        dns_status = res.get("dns_status", "CONSISTENT")
        overall = res.get("overall_health", "SAFE")

        self.conn_ssid_var.set(f"{ssid} ({bssid})")

        # Gateway MAC Status
        if arp_status == "SPOOF_DETECTED":
            self.gw_mac_var.set(f"⚠️ {gw_mac} (CHANGED / SPOOF DETECTED!)")
            self.gw_status_lbl.config(foreground="#C0392B")
        elif arp_status == "GATEWAY_CHANGED":
            self.gw_mac_var.set(f"ℹ️ {gw_mac} (Gateway IP Changed: {gw_ip})")
            self.gw_status_lbl.config(foreground="#D35400")
        else:
            self.gw_mac_var.set(f"✓ {gw_mac} (Stable, IP: {gw_ip})")
            self.gw_status_lbl.config(foreground="#27AE60")

        # DNS Integrity Status
        if dns_status == "MISMATCH":
            self.dns_var.set("⚠️ Mismatch / Poisoning Detected!")
            self.dns_status_lbl.config(foreground="#C0392B")
        elif dns_status == "OFFLINE_SKIPPED":
            self.dns_var.set("ℹ️ DoH Unreachable (Offline)")
            self.dns_status_lbl.config(foreground="#7F8C8D")
        else:
            self.dns_var.set("✓ Consistent with Cloudflare/Google DoH")
            self.dns_status_lbl.config(foreground="#27AE60")

        # Overall Status Badge
        self.health_status_var.set(overall)
        if overall == "CRITICAL":
            self.health_badge.config(foreground="#C0392B")
        elif overall == "WARNING":
            self.health_badge.config(foreground="#D35400")
        else:
            self.health_badge.config(foreground="#27AE60")

    def update_networks(self, networks: List[Network]):
        self.networks = networks
        self.refresh_dashboard()

    def refresh_dashboard(self):
        stats = self.db.get_monitoring_stats()

        total = len(self.networks) if self.networks else stats.get("tracked_bssids", 0)
        valid_ssids = len(set(n.ssid for n in self.networks if n.ssid and n.ssid != "<Hidden Network>")) if self.networks else 0
        open_cnt = sum(1 for n in self.networks if n.security.upper() == "OPEN") if self.networks else 0

        self.card_vars["total_nets"].set(str(total))
        self.card_vars["ssids"].set(str(valid_ssids))
        self.card_vars["active_bssids"].set(str(stats.get("active_bssids", 0)))
        self.card_vars["open_nets"].set(str(open_cnt))
        self.card_vars["high_events"].set(str(stats.get("high_severity_events", 0)))

        anomalies = self.db.repos.get_anomalies(limit=10)
        self.card_vars["anomalies"].set(str(len(anomalies)))

        # Update Security Distribution Treeview
        for item in self.sec_tree.get_children():
            self.sec_tree.delete(item)

        if self.networks:
            sec_counts = {}
            for n in self.networks:
                s = n.security.upper()
                sec_counts[s] = sec_counts.get(s, 0) + 1

            for s, cnt in sorted(sec_counts.items(), key=lambda x: x[1], reverse=True):
                pct = f"{(cnt / total) * 100:.1f}%" if total > 0 else "0%"
                self.sec_tree.insert("", "end", values=(s, cnt, pct))

        # Update Baseline status
        active_base = self.db.repos.get_active_baseline()
        if active_base:
            self.baseline_status_var.set(f"Active Baseline: {active_base['name']} ({active_base['item_count']} APs)")
            self.env_summary_var.set(f"Baseline established at {active_base['created_at']}. Deviation monitoring active.")
        else:
            self.baseline_status_var.set("Active Baseline: None Established")
            self.env_summary_var.set("Establish an environment baseline to detect unseen networks and configuration shifts.")

        # Update Events Treeview
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)

        events = self.db.get_events(limit=25)
        for ev in events:
            self.events_tree.insert("", "end", values=(
                ev.get("timestamp", "")[-8:],
                ev.get("event_type", ""),
                ev.get("severity", ""),
                ev.get("description", "")
            ))

        # Trigger connection health check asynchronously
        self.check_connection_health_async()
