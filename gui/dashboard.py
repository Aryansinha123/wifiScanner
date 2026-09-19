import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any, Callable
from models.network import Network
from storage.database import DatabaseManager


class DashboardView(ttk.Frame):
    """
    Executive Summary Dashboard view for the Wi-Fi Security Platform.
    Displays stat cards, security overview, monitoring status, channel density, and alerts.
    """

    def __init__(self, parent: tk.Widget, db_manager: DatabaseManager, on_navigate: Callable[[str], None] = None):
        super().__init__(parent, padding=15)
        self.db = db_manager
        self.on_navigate = on_navigate

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
        hdr_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 15))

        title = ttk.Label(hdr_frame, text="Wi-Fi Security Intelligence Dashboard", font=("Segoe UI", 16, "bold"))
        title.pack(side="left")

        self.status_var = tk.StringVar(value="Monitoring: ACTIVE")
        self.status_lbl = ttk.Label(hdr_frame, textvariable=self.status_var, font=("Segoe UI", 10, "bold"), foreground="#27AE60")
        self.status_lbl.pack(side="right")

        # 2. Metric Cards Grid
        cards_frame = ttk.Frame(self)
        cards_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 15))

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
            card = ttk.LabelFrame(cards_frame, text=f" {title} ", padding=10)
            card.grid(row=0, column=col, padx=4, sticky="nsew")
            lbl = ttk.Label(card, textvariable=var, font=("Segoe UI", 18, "bold"), foreground=color)
            lbl.pack(anchor="center")

        # 3. Main Content Split (Left: Security Distribution & Channel Summary, Right: Recent Alerts)
        left_frame = ttk.Frame(self)
        left_frame.grid(row=2, column=0, sticky="nsew", padx=(0, 10))
        left_frame.rowconfigure(0, weight=1)
        left_frame.rowconfigure(1, weight=1)
        left_frame.columnconfigure(0, weight=1)

        right_frame = ttk.Frame(self)
        right_frame.grid(row=2, column=1, sticky="nsew", padx=(10, 0))
        right_frame.rowconfigure(0, weight=1)
        right_frame.columnconfigure(0, weight=1)

        # 3.1 Security Distribution Box
        sec_box = ttk.LabelFrame(left_frame, text=" Wireless Security Distribution ", padding=10)
        sec_box.grid(row=0, column=0, sticky="nsew", pady=(0, 10))

        self.sec_tree = ttk.Treeview(sec_box, columns=("protocol", "count", "pct"), show="headings", height=5)
        self.sec_tree.heading("protocol", text="Security Protocol")
        self.sec_tree.heading("count", text="Networks")
        self.sec_tree.heading("pct", text="Share")
        self.sec_tree.column("protocol", width=140)
        self.sec_tree.column("count", width=80, anchor="center")
        self.sec_tree.column("pct", width=80, anchor="center")
        self.sec_tree.pack(fill="both", expand=True)

        # 3.2 Baseline & Environment Status Box
        base_box = ttk.LabelFrame(left_frame, text=" Baseline & Environment Intelligence ", padding=10)
        base_box.grid(row=1, column=0, sticky="nsew")

        self.baseline_status_var = tk.StringVar(value="Active Baseline: None Established")
        ttk.Label(base_box, textvariable=self.baseline_status_var, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=2)

        self.env_summary_var = tk.StringVar(value="Environment: Ready for scan evaluation.")
        ttk.Label(base_box, textvariable=self.env_summary_var, font=("Segoe UI", 9), wraplength=400).pack(anchor="w", pady=4)

        if self.on_navigate:
            ttk.Button(base_box, text="Manage Baselines", command=lambda: self.on_navigate("Baseline")).pack(anchor="e", pady=(5, 0))

        # 3.3 Recent Alerts & Anomalies Treeview
        alerts_box = ttk.LabelFrame(right_frame, text=" Recent Security Events & Anomalies ", padding=10)
        alerts_box.grid(row=0, column=0, sticky="nsew")
        alerts_box.rowconfigure(0, weight=1)
        alerts_box.columnconfigure(0, weight=1)

        self.events_tree = ttk.Treeview(alerts_box, columns=("time", "type", "sev", "desc"), show="headings")
        self.events_tree.heading("time", text="Timestamp")
        self.events_tree.heading("type", text="Event Type")
        self.events_tree.heading("sev", text="Severity")
        self.events_tree.heading("desc", text="Description")

        self.events_tree.column("time", width=120)
        self.events_tree.column("type", width=130)
        self.events_tree.column("sev", width=80, anchor="center")
        self.events_tree.column("desc", width=220)

        self.events_tree.pack(fill="both", expand=True)

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
