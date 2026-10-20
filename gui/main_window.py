import logging
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import ttk, messagebox, filedialog
from typing import List, Optional, Dict, Any

from scanner.scanner_manager import ScannerManager
from scanner.scan_scheduler import ScanScheduler
from scanner.adapter_manager import AdapterManager
from utils.parser import parse_networks
from utils.config import ConfigManager
from storage.csv_export import export_networks
from storage.database import DatabaseManager
from monitoring.scheduler import MonitoringPipeline
from monitoring.event_manager import EventManager
from security.analyzer import analyze_security
from security.risk_engine import MultiFactorRiskEngine
from intelligence.vendor_analyzer import lookup_vendor
from simulation.simulation_manager import SimulationManager
from models.network import Network

from gui.dashboard import DashboardView
from gui.monitoring_window import MonitoringWindow
from gui.history_window import HistoryWindow
from gui.baseline_window import BaselineWindow
from gui.analytics_window import AnalyticsWindow
from gui.events_window import EventsWindow
from gui.reports_window import ReportsWindow
from gui.settings_window import SettingsWindow
from gui.database_window import DatabaseWindow
from gui.diagnostics_window import DiagnosticsWindow
from gui.network_details import NetworkDetailsModal

logger = logging.getLogger(__name__)


class MainWindow:
    """
    Modular Desktop GUI for Wi-Fi Security Intelligence & Monitoring Platform.
    Features a sidebar navigation layout connecting Dashboard, Live Scanner, Security Monitor,
    History, Events, Analytics, Baseline Manager, Reports, Database, Settings, and Diagnostics.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Wi-Fi Security Intelligence & Monitoring Platform")
        self.root.geometry("1380x820")
        self.root.minsize(1200, 750)

        # Apply Theme Style
        self.style = ttk.Style()
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")

        # Initialize Core Components
        self.config_mgr = ConfigManager()
        self.db = DatabaseManager(db_path=self.config_mgr.get("db_path", "data/wifi_scanner.db"))
        self.event_mgr = EventManager(self.db)
        self.pipeline = MonitoringPipeline(self.db, self.event_mgr)
        self.scanner_mgr = ScannerManager()
        self.adapter_mgr = AdapterManager(self.scanner_mgr.scanner)
        self.scheduler = ScanScheduler(self.scanner_mgr)
        self.sim_mgr = SimulationManager()

        self.networks: List[Network] = []
        self.adapter_info: Dict[str, Any] = {}
        self.monitoring_win: Optional[MonitoringWindow] = None

        self.is_scanning: bool = False
        self.auto_refresh_enabled: bool = False
        self.refresh_interval_sec: int = self.config_mgr.get("scan_interval_sec", 30)

        self.last_scan_time: str = "N/A"
        self.last_scan_duration: float = 0.0

        self.active_nav: str = "Dashboard"
        self.nav_buttons: Dict[str, ttk.Button] = {}

        self.create_interface()
        self.update_adapter_panel()
        logger.info("GUI MainWindow initialized successfully.")

    # ---------------------------------------------------------
    # LAYOUT CREATION
    # ---------------------------------------------------------

    def create_interface(self):
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)

        # Custom ttk Styles
        self.style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        self.style.configure("Subtitle.TLabel", font=("Segoe UI", 9, "italic"), foreground="#555555")
        self.style.configure("CardTitle.TLabel", font=("Segoe UI", 8, "bold"), foreground="#444444")
        self.style.configure("CardValue.TLabel", font=("Segoe UI", 16, "bold"), foreground="#000000")
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        self.style.configure("Treeview", font=("Segoe UI", 9), rowheight=24)

        self.table_tags = {
            "CRITICAL": {"background": "#FADBD8"},
            "HIGH": {"background": "#FDEBD0"},
            "MEDIUM": {"background": "#FCF3CF"},
            "LOW": {"background": "#D4EFDF"},
            "UNKNOWN": {"background": "#E5E7E9"}
        }

        # ==========================================
        # 1. SIDEBAR NAVIGATION PANEL (LEFT)
        # ==========================================
        sidebar = ttk.Frame(self.root, padding=(10, 15), relief="groove")
        sidebar.grid(row=0, column=0, sticky="nsew")

        brand_lbl = ttk.Label(sidebar, text=" Wi-Fi Intelligence ", font=("Segoe UI", 12, "bold"))
        brand_lbl.pack(anchor="w", pady=(0, 15))

        nav_items = [
            ("Dashboard", "Dashboard"),
            ("Live Scanner", "Live Scanner"),
            ("Security Monitor", "Security Monitor"),
            ("Events", "Events"),
            ("Analytics", "Analytics"),
            ("Baseline", "Baseline"),
            ("Reports", "Reports"),
            ("Database", "Database"),
            ("Settings", "Settings"),
            ("Diagnostics", "Diagnostics")
        ]

        for label, nav_id in nav_items:
            btn = ttk.Button(sidebar, text=label, command=lambda n=nav_id: self.navigate_to(n), width=18)
            btn.pack(anchor="w", pady=3)
            self.nav_buttons[nav_id] = btn

        # Simulation Mode Indicator
        self.sim_indicator_var = tk.StringVar(value="")
        self.sim_lbl = ttk.Label(sidebar, textvariable=self.sim_indicator_var, font=("Segoe UI", 8, "bold"), foreground="#E67E22")
        self.sim_lbl.pack(anchor="w", pady=(20, 0))

        # ==========================================
        # 2. MAIN CONTENT AREA (RIGHT CONTAINER)
        # ==========================================
        self.content_container = ttk.Frame(self.root, padding=10)
        self.content_container.grid(row=0, column=1, sticky="nsew")
        self.content_container.rowconfigure(0, weight=1)
        self.content_container.columnconfigure(0, weight=1)

        # Instantiate View Frames
        self.views: Dict[str, ttk.Frame] = {}

        self.views["Dashboard"] = DashboardView(self.content_container, self.db, on_navigate=self.navigate_to)
        self.views["Live Scanner"] = self._create_live_scanner_view()
        self.views["Security Monitor"] = self._create_monitor_embed_view()
        self.views["Events"] = EventsWindow(self.content_container, self.db)
        self.views["Analytics"] = AnalyticsWindow(self.content_container)
        self.views["Baseline"] = BaselineWindow(self.content_container, self.db)
        self.views["Reports"] = ReportsWindow(self.content_container, self.db)
        self.views["Database"] = DatabaseWindow(self.content_container, self.db)
        self.views["Settings"] = SettingsWindow(self.content_container, self.config_mgr, self.db)
        self.views["Diagnostics"] = DiagnosticsWindow(self.content_container, self.db)

        # Show initial view
        self.navigate_to("Dashboard")

    # ---------------------------------------------------------
    # NAVIGATION CONTROLLER
    # ---------------------------------------------------------

    def navigate_to(self, nav_id: str):
        if nav_id not in self.views:
            return

        self.active_nav = nav_id
        for v in self.views.values():
            v.grid_forget()

        view_frame = self.views[nav_id]
        view_frame.grid(row=0, column=0, sticky="nsew")

        # Push networks update to views if supported
        if hasattr(view_frame, "update_networks"):
            view_frame.update_networks(self.networks)

        # Check simulation mode state
        if self.config_mgr.get("simulation_mode", False):
            self.sim_indicator_var.set("[ DEMO / SIMULATION MODE ]")
        else:
            self.sim_indicator_var.set("")

    # ---------------------------------------------------------
    # LIVE SCANNER VIEW CREATION
    # ---------------------------------------------------------

    def _create_live_scanner_view(self) -> ttk.Frame:
        view = ttk.Frame(self.content_container)
        view.rowconfigure(3, weight=1)
        view.columnconfigure(0, weight=1)

        # Header
        hdr = ttk.Frame(view, padding=(0, 5))
        hdr.grid(row=0, column=0, sticky="ew")

        ttk.Label(hdr, text="Passive Live Wi-Fi Network Discovery", font=("Segoe UI", 14, "bold")).pack(anchor="w")

        # Control Bar
        ctrl = ttk.Frame(view, padding=(0, 5))
        ctrl.grid(row=1, column=0, sticky="ew")

        self.scan_button = ttk.Button(ctrl, text="Scan Networks", command=self.start_scan)
        self.scan_button.pack(side="left", padx=(0, 5))

        self.refresh_button = ttk.Button(ctrl, text="Refresh", command=self.start_scan)
        self.refresh_button.pack(side="left", padx=5)

        self.auto_refresh_var = tk.BooleanVar(value=False)
        self.auto_refresh_cb = ttk.Checkbutton(ctrl, text="Auto Refresh (30s)", variable=self.auto_refresh_var, command=self.toggle_auto_refresh)
        self.auto_refresh_cb.pack(side="left", padx=(10, 15))

        ttk.Label(ctrl, text="Search:").pack(side="left", padx=(10, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_search)
        ttk.Entry(ctrl, textvariable=self.search_var, width=18).pack(side="left")

        ttk.Label(ctrl, text="Sort:").pack(side="left", padx=(15, 4))
        self.sort_var = tk.StringVar(value="Signal")
        sort_box = ttk.Combobox(ctrl, textvariable=self.sort_var, values=["Signal", "SSID", "Channel", "Security", "Risk", "Band"], state="readonly", width=10)
        sort_box.pack(side="left")
        sort_box.bind("<<ComboboxSelected>>", self.on_sort)

        meta_right = ttk.Frame(ctrl)
        meta_right.pack(side="right")

        self.status_var = tk.StringVar(value="Status: Ready")
        self.status_label = ttk.Label(meta_right, textvariable=self.status_var, font=("Segoe UI", 9, "bold"), foreground="#2E86C1")
        self.status_label.pack(anchor="e")

        self.metadata_var = tk.StringVar(value="Last Scan: Never | Duration: 0.00s")
        ttk.Label(meta_right, textvariable=self.metadata_var, font=("Segoe UI", 8, "italic"), foreground="#777777").pack(anchor="e")

        # Adapter Card Panel
        panels = ttk.Frame(view, padding=(0, 5))
        panels.grid(row=2, column=0, sticky="ew")

        adapter_card = ttk.LabelFrame(panels, text=" WLAN Adapter Information ", padding=8)
        adapter_card.pack(fill="x")

        self.adapter_name_var = tk.StringVar(value="Interface: Unknown")
        self.adapter_state_var = tk.StringVar(value="State: Unknown")
        self.adapter_ssid_var = tk.StringVar(value="Connected SSID: N/A")

        ttk.Label(adapter_card, textvariable=self.adapter_name_var, font=("Segoe UI", 9, "bold")).pack(side="left", padx=10)
        ttk.Label(adapter_card, textvariable=self.adapter_state_var, font=("Segoe UI", 9)).pack(side="left", padx=10)
        ttk.Label(adapter_card, textvariable=self.adapter_ssid_var, font=("Segoe UI", 9)).pack(side="left", padx=10)

        # Table Frame
        tbl_frame = ttk.Frame(view, padding=(0, 5))
        tbl_frame.grid(row=3, column=0, sticky="nsew")
        tbl_frame.rowconfigure(0, weight=1)
        tbl_frame.columnconfigure(0, weight=1)

        columns = ("ssid", "bssid", "vendor", "signal", "rssi", "channel", "band", "security", "encryption", "radio", "risk")
        self.table = ttk.Treeview(tbl_frame, columns=columns, show="headings", selectmode="browse")

        headings = {
            "ssid": "SSID", "bssid": "BSSID", "vendor": "Vendor", "signal": "Signal", "rssi": "Estimated RSSI",
            "channel": "Channel", "band": "Band", "security": "Security", "encryption": "Encryption",
            "radio": "Radio Standard", "risk": "Risk Level"
        }
        widths = {
            "ssid": 170, "bssid": 130, "vendor": 130, "signal": 70, "rssi": 100,
            "channel": 65, "band": 80, "security": 90, "encryption": 90, "radio": 90, "risk": 90
        }

        for col in columns:
            self.table.heading(col, text=headings[col])
            self.table.column(col, width=widths[col], anchor="center" if col != "ssid" else "w")

        for tag, kwargs in self.table_tags.items():
            self.table.tag_configure(tag, **kwargs)

        v_sb = ttk.Scrollbar(tbl_frame, orient="vertical", command=self.table.yview)
        h_sb = ttk.Scrollbar(tbl_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=v_sb.set, xscrollcommand=h_sb.set)

        self.table.grid(row=0, column=0, sticky="nsew")
        v_sb.grid(row=0, column=1, sticky="ns")
        h_sb.grid(row=1, column=0, sticky="ew")

        self.table.bind("<Double-1>", self.show_network_details)

        # Bottom Controls
        btm = ttk.Frame(view, padding=(0, 5))
        btm.grid(row=4, column=0, sticky="ew")

        ttk.Button(btm, text="Network Details", command=self.show_network_details).pack(side="left", padx=(0, 5))
        ttk.Button(btm, text="Export CSV", command=self.export_csv).pack(side="right")

        return view

    def _create_monitor_embed_view(self) -> ttk.Frame:
        view = ttk.Frame(self.content_container, padding=20)
        ttk.Label(view, text="Security Monitoring Center", font=("Segoe UI", 16, "bold")).pack(anchor="w", pady=(0, 15))

        card = ttk.LabelFrame(view, text=" Real-Time Monitoring Subsystem ", padding=15)
        card.pack(fill="x", pady=10)

        ttk.Label(card, text="The passive monitoring subsystem tracks background scan iterations, compares network state transitions (ACTIVE -> TEMPORARILY_MISSING -> NOT_DETECTED), detects security configuration downgrades, and logs security events to SQLite.", font=("Segoe UI", 9), wraplength=700).pack(anchor="w", pady=(0, 10))

        ttk.Button(card, text="Open Standalone Security Monitor Window", command=self.open_security_monitor).pack(anchor="w")

        return view

    # ---------------------------------------------------------
    # ADAPTER PANEL & SCAN PIPELINE
    # ---------------------------------------------------------

    def update_adapter_panel(self):
        try:
            info = self.scanner_mgr.get_interface_info()
            self.adapter_info = info
            self.adapter_name_var.set(f"Interface: {info.get('name', 'Unknown')}")
            self.adapter_state_var.set(f"State: {info.get('state', 'Unknown')}")
            self.adapter_ssid_var.set(f"Connected SSID: {info.get('ssid', 'Not Connected')}")
        except Exception as err:
            logger.warning("Error updating adapter panel: %s", err)

    def start_scan(self):
        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_button.config(state="disabled")
        self.refresh_button.config(state="disabled")
        self.status_var.set("Status: Scanning...")
        self.status_label.config(foreground="#E67E22")

        thread = threading.Thread(target=self._perform_scan_thread, daemon=True)
        thread.start()

    def _perform_scan_thread(self):
        start_time = time.time()
        try:
            if self.config_mgr.get("simulation_mode", False):
                networks = self.sim_mgr.generate_simulated_networks()
            else:
                raw_data = self.scanner_mgr.scan()
                networks = parse_networks(raw_data)

            # Assign OUI vendor names
            for net in networks:
                net.vendor = lookup_vendor(net.bssid)

            duration = time.time() - start_time
            self.root.after(0, lambda: self._scan_completed(networks, duration))
        except Exception as error:
            duration = time.time() - start_time
            self.root.after(0, lambda: self._scan_failed(str(error), duration))

    def _scan_completed(self, networks: List[Network], duration: float):
        self.networks = networks
        self.is_scanning = False

        self.scan_button.config(state="normal")
        self.refresh_button.config(state="normal")

        count = len(networks)
        self.status_var.set(f"Status: Scan completed — {count} network(s) found")
        self.status_label.config(foreground="#27AE60")

        self.last_scan_time = datetime.now().strftime("%H:%M:%S")
        self.last_scan_duration = duration
        self.metadata_var.set(f"Last Scan: {self.last_scan_time} | Duration: {duration:.2f}s")

        # Execute Monitoring Pipeline
        try:
            timestamp_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.pipeline.process_scan_results(networks, duration, timestamp_now)
        except Exception as err:
            logger.error("Error executing monitoring pipeline: %s", err)

        # Notify active view
        curr_view = self.views.get(self.active_nav)
        if hasattr(curr_view, "update_networks"):
            curr_view.update_networks(networks)

        # Refresh dashboard
        if "Dashboard" in self.views and hasattr(self.views["Dashboard"], "update_networks"):
            self.views["Dashboard"].update_networks(networks)

        self.update_adapter_panel()
        self.refresh_table()

    def _scan_failed(self, error_message: str, duration: float):
        self.is_scanning = False
        self.scan_button.config(state="normal")
        self.refresh_button.config(state="normal")

        short_reason = error_message.splitlines()[0] if error_message else "Unknown error"
        self.status_var.set(f"Status: Scan failed — {short_reason}")
        self.status_label.config(foreground="#C0392B")

        messagebox.showerror("Scan Error", f"Failed to scan wireless networks:\n\n{error_message}")

    # ---------------------------------------------------------
    # TABLE REFRESH & SEARCH
    # ---------------------------------------------------------

    def refresh_table(self):
        if not hasattr(self, "table"):
            return

        for item in self.table.get_children():
            self.table.delete(item)

        filtered = self.get_filtered_networks()

        for net in filtered:
            rssi_text = f"{net.signal_dbm} dBm" if net.signal_dbm is not None else "Unknown"
            channel_text = str(net.channel) if net.channel is not None else "Unknown"
            risk = net.risk_level()

            self.table.insert(
                "",
                "end",
                values=(
                    net.ssid,
                    net.bssid,
                    net.vendor,
                    f"{net.signal_percent}%",
                    rssi_text,
                    channel_text,
                    net.band,
                    net.security,
                    net.encryption,
                    net.radio_type,
                    risk
                ),
                tags=(risk,)
            )

    def get_filtered_networks(self) -> List[Network]:
        query = self.search_var.get().strip().lower()
        result = list(self.networks)

        if query:
            result = [
                n for n in result
                if query in n.ssid.lower()
                or query in n.bssid.lower()
                or query in n.security.lower()
                or query in n.encryption.lower()
                or query in n.band.lower()
                or (n.channel is not None and query in str(n.channel))
            ]

        sort_key = self.sort_var.get()
        if sort_key == "Signal":
            result.sort(key=lambda n: n.signal_percent, reverse=True)
        elif sort_key == "SSID":
            result.sort(key=lambda n: n.ssid.lower())
        elif sort_key == "Channel":
            result.sort(key=lambda n: (n.channel if n.channel is not None else 999))
        elif sort_key == "Security":
            sec_order = {"WPA3": 1, "WPA2": 2, "WPA": 3, "WEP": 4, "OPEN": 5, "UNKNOWN": 6}
            result.sort(key=lambda n: sec_order.get(n.security.upper(), 99))
        elif sort_key == "Risk":
            risk_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "UNKNOWN": 5}
            result.sort(key=lambda n: risk_order.get(n.risk_level(), 99))
        elif sort_key == "Band":
            band_order = {"2.4 GHz": 1, "5 GHz": 2, "Unknown": 3}
            result.sort(key=lambda n: band_order.get(n.band, 99))

        return result

    def on_search(self, *args):
        self.refresh_table()

    def on_sort(self, event=None):
        self.refresh_table()

    def show_network_details(self, event=None):
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo("Network Details", "Please select a network from the table first.")
            return

        bssid = self.table.item(selected[0], "values")[1]
        network = next((n for n in self.networks if n.bssid == bssid), None)
        if network:
            NetworkDetailsModal(self.root, network, self.db)

    def open_security_monitor(self):
        if self.monitoring_win and self.monitoring_win.win.winfo_exists():
            self.monitoring_win.win.lift()
            self.monitoring_win.refresh_dashboard()
        else:
            self.monitoring_win = MonitoringWindow(self.root, self.db, self.event_mgr)

    def export_csv(self):
        if not self.networks:
            messagebox.showinfo("Export", "Please perform a scan first.")
            return

        filename = filedialog.asksaveasfilename(title="Save CSV", defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filename:
            export_networks(self.networks, filename)
            messagebox.showinfo("Success", "Scan results exported successfully.")

    def toggle_auto_refresh(self):
        if self.auto_refresh_var.get():
            self.scheduler.start()
        else:
            self.scheduler.pause()