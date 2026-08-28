import logging
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List, Optional

from scanner.scanner_manager import ScannerManager
from utils.parser import parse_networks
from storage.csv_export import export_networks
from security.analyzer import analyze_security
from models.network import Network

logger = logging.getLogger(__name__)


class MainWindow:
    """
    Main GUI Window for Wi-Fi Network Security Scanner.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Wi-Fi Network Security Scanner")
        self.root.geometry("1250x720")
        self.root.minsize(1000, 600)

        # Apply modern style
        self.style = ttk.Style()
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")

        self.scanner = ScannerManager()
        self.networks: List[Network] = []

        self.is_scanning: bool = False
        self.auto_refresh_enabled: bool = False
        self.refresh_interval_sec: int = 30
        self.auto_refresh_timer_id: Optional[str] = None

        self.create_interface()
        logger.info("GUI MainWindow initialized successfully.")

    # ---------------------------------------------------------
    # GUI LAYOUT CREATION
    # ---------------------------------------------------------

    def create_interface(self):
        # Apply custom style configuration
        self.style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"))
        self.style.configure("Stat.TLabel", font=("Segoe UI", 10, "bold"))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        self.style.configure("Treeview", font=("Segoe UI", 9), rowheight=24)

        # Header Frame
        header = ttk.Frame(self.root, padding=(15, 12))
        header.pack(fill="x")

        title = ttk.Label(
            header,
            text="Wi-Fi Network Security Scanner",
            style="Header.TLabel"
        )
        title.pack(side="left")

        # Control Bar Frame
        controls = ttk.Frame(self.root, padding=(15, 5))
        controls.pack(fill="x")

        self.scan_button = ttk.Button(
            controls,
            text="Scan Networks",
            command=self.start_scan
        )
        self.scan_button.pack(side="left", padx=(0, 8))

        self.refresh_button = ttk.Button(
            controls,
            text="Refresh",
            command=self.start_scan
        )
        self.refresh_button.pack(side="left", padx=5)

        self.auto_refresh_var = tk.BooleanVar(value=False)
        auto_refresh_cb = ttk.Checkbutton(
            controls,
            text="Auto Refresh (30s)",
            variable=self.auto_refresh_var,
            command=self.toggle_auto_refresh
        )
        auto_refresh_cb.pack(side="left", padx=15)

        # Search Bar
        ttk.Label(controls, text="Search:").pack(side="left", padx=(20, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_search)
        search_entry = ttk.Entry(controls, textvariable=self.search_var, width=22)
        search_entry.pack(side="left")

        # Sort Dropdown
        ttk.Label(controls, text="Sort:").pack(side="left", padx=(20, 5))
        self.sort_var = tk.StringVar(value="Signal")
        sort_box = ttk.Combobox(
            controls,
            textvariable=self.sort_var,
            values=["Signal", "SSID", "Channel", "Security"],
            state="readonly",
            width=12
        )
        sort_box.pack(side="left")
        sort_box.bind("<<ComboboxSelected>>", self.on_sort)

        # Status Indicator
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(
            controls,
            textvariable=self.status_var,
            font=("Segoe UI", 9, "italic")
        )
        status_label.pack(side="right", padx=(10, 0))

        # Statistics Bar
        stats_frame = ttk.Frame(self.root, padding=(15, 8))
        stats_frame.pack(fill="x")

        self.total_var = tk.StringVar(value="Networks: 0")
        self.secure_var = tk.StringVar(value="WPA2/WPA3: 0")
        self.open_var = tk.StringVar(value="Open: 0")
        self.channel_var = tk.StringVar(value="Channels: 0")

        ttk.Label(stats_frame, textvariable=self.total_var, style="Stat.TLabel").pack(side="left", padx=(0, 25))
        ttk.Label(stats_frame, textvariable=self.secure_var, style="Stat.TLabel").pack(side="left", padx=25)
        ttk.Label(stats_frame, textvariable=self.open_var, style="Stat.TLabel").pack(side="left", padx=25)
        ttk.Label(stats_frame, textvariable=self.channel_var, style="Stat.TLabel").pack(side="left", padx=25)

        # Network Table (Treeview)
        table_frame = ttk.Frame(self.root, padding=(15, 5))
        table_frame.pack(fill="both", expand=True)

        columns = (
            "ssid", "bssid", "signal", "rssi",
            "channel", "frequency", "security",
            "encryption", "radio", "risk"
        )

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        headings = {
            "ssid": "SSID",
            "bssid": "BSSID",
            "signal": "Signal",
            "rssi": "Estimated RSSI",
            "channel": "Channel",
            "frequency": "Frequency",
            "security": "Security",
            "encryption": "Encryption",
            "radio": "Radio Type",
            "risk": "Risk Level"
        }

        widths = {
            "ssid": 180,
            "bssid": 140,
            "signal": 75,
            "rssi": 105,
            "channel": 75,
            "frequency": 95,
            "security": 95,
            "encryption": 95,
            "radio": 95,
            "risk": 95
        }

        for col in columns:
            self.table.heading(col, text=headings[col])
            self.table.column(col, width=widths[col], anchor="center" if col != "ssid" else "w")

        v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.table.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Bind double-click event
        self.table.bind("<Double-1>", self.show_network_details)

        # Bottom Controls
        bottom_frame = ttk.Frame(self.root, padding=(15, 12))
        bottom_frame.pack(fill="x")

        ttk.Button(
            bottom_frame,
            text="Network Details",
            command=self.show_network_details
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            bottom_frame,
            text="Channel Analysis",
            command=self.show_channel_analysis
        ).pack(side="left", padx=5)

        ttk.Button(
            bottom_frame,
            text="Export CSV",
            command=self.export_csv
        ).pack(side="right", padx=(5, 0))

    # ---------------------------------------------------------
    # BACKGROUND SCANNING LOGIC
    # ---------------------------------------------------------

    def start_scan(self):
        if self.is_scanning:
            logger.debug("Scan already in progress. Ignoring request.")
            return

        self.is_scanning = True
        self.scan_button.config(state="disabled")
        self.refresh_button.config(state="disabled")
        self.status_var.set("Scanning...")

        logger.info("Initiating background scan thread...")
        thread = threading.Thread(target=self._perform_scan_thread, daemon=True)
        thread.start()

    def _perform_scan_thread(self):
        try:
            raw_data = self.scanner.scan()
            networks = parse_networks(raw_data)
            self.root.after(0, lambda: self._scan_completed(networks))
        except Exception as error:
            logger.exception("Background scan encountered error: %s", error)
            self.root.after(0, lambda: self._scan_failed(str(error)))

    def _scan_completed(self, networks: List[Network]):
        self.networks = networks
        self.is_scanning = False

        self.scan_button.config(state="normal")
        self.refresh_button.config(state="normal")

        count = len(networks)
        self.status_var.set(f"Scan complete — {count} network(s) found")
        logger.info("Scan completed successfully. Found %d network(s).", count)

        self.update_statistics()
        self.refresh_table()

    def _scan_failed(self, error_message: str):
        self.is_scanning = False
        self.scan_button.config(state="normal")
        self.refresh_button.config(state="normal")
        self.status_var.set("Scan failed")
        logger.error("Scan failed: %s", error_message)

        messagebox.showerror(
            "Scan Error",
            f"Failed to scan Wi-Fi networks:\n\n{error_message}"
        )

    # ---------------------------------------------------------
    # TABLE REFRESH & FILTER / SORT
    # ---------------------------------------------------------

    def refresh_table(self):
        for item in self.table.get_children():
            self.table.delete(item)

        filtered = self.get_filtered_networks()

        for net in filtered:
            rssi_text = f"{net.signal_dbm} dBm" if net.signal_dbm is not None else "Unknown"
            channel_text = str(net.channel) if net.channel is not None else "Unknown"

            self.table.insert(
                "",
                "end",
                values=(
                    net.ssid,
                    net.bssid,
                    f"{net.signal_percent}%",
                    rssi_text,
                    channel_text,
                    net.frequency,
                    net.security,
                    net.encryption,
                    net.radio_type,
                    net.risk_level()
                )
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
            ]

        sort_key = self.sort_var.get()

        if sort_key == "Signal":
            result.sort(key=lambda n: n.signal_percent, reverse=True)
        elif sort_key == "SSID":
            result.sort(key=lambda n: n.ssid.lower())
        elif sort_key == "Channel":
            result.sort(key=lambda n: (n.channel if n.channel is not None else 999))
        elif sort_key == "Security":
            sec_order = {
                "WPA3": 1,
                "WPA2": 2,
                "WPA": 3,
                "WEP": 4,
                "OPEN": 5,
                "UNKNOWN": 6
            }
            result.sort(key=lambda n: sec_order.get(n.security.upper(), 99))

        return result

    def on_search(self, *args):
        self.refresh_table()

    def on_sort(self, event=None):
        self.refresh_table()

    # ---------------------------------------------------------
    # STATISTICS UPDATE
    # ---------------------------------------------------------

    def update_statistics(self):
        total = len(self.networks)
        secure_count = sum(1 for n in self.networks if n.security.upper() in ("WPA2", "WPA3"))
        open_count = sum(1 for n in self.networks if n.security.upper() == "OPEN")
        channels_count = len(set(n.channel for n in self.networks if n.channel is not None))

        self.total_var.set(f"Networks: {total}")
        self.secure_var.set(f"WPA2/WPA3: {secure_count}")
        self.open_var.set(f"Open: {open_count}")
        self.channel_var.set(f"Channels: {channels_count}")

    # ---------------------------------------------------------
    # DIALOG ACTIONS
    # ---------------------------------------------------------

    def show_network_details(self, event=None):
        selected_items = self.table.selection()
        if not selected_items:
            messagebox.showinfo("Network Details", "Select a network first.")
            return

        item = selected_items[0]
        values = self.table.item(item, "values")
        selected_bssid = values[1]

        network = next((n for n in self.networks if n.bssid == selected_bssid), None)
        if network is None:
            messagebox.showerror("Error", "Selected network details could not be found.")
            return

        assessment = analyze_security(network.security)

        details_msg = (
            f"SSID: {network.ssid}\n\n"
            f"BSSID: {network.bssid}\n\n"
            f"Signal: {network.signal_percent}%\n\n"
            f"Estimated RSSI: {network.signal_dbm} dBm\n\n"
            f"Channel: {network.channel if network.channel is not None else 'Unknown'}\n\n"
            f"Frequency: {network.frequency}\n\n"
            f"Security: {network.security}\n\n"
            f"Encryption: {network.encryption}\n\n"
            f"Radio Type: {network.radio_type}\n\n"
            f"Heuristic Security Score: {assessment['score']}/100\n\n"
            f"Risk Level: {assessment['level']}\n\n"
            f"Assessment:\n{assessment['description']}"
        )

        messagebox.showinfo(f"Network Details - {network.ssid}", details_msg)

    def show_channel_analysis(self):
        if not self.networks:
            messagebox.showinfo("Channel Analysis", "Perform a scan first.")
            return

        channel_counts = {}
        for net in self.networks:
            if net.channel is not None:
                channel_counts[net.channel] = channel_counts.get(net.channel, 0) + 1

        if not channel_counts:
            messagebox.showinfo("Channel Analysis", "No channel information available.")
            return

        lines = ["CHANNEL ANALYSIS", ""]
        for ch in sorted(channel_counts.keys()):
            cnt = channel_counts[ch]
            warning_tag = "  <-- HIGH CONGESTION" if cnt >= 4 else ""
            lines.append(f"Channel {ch}: {cnt} network(s){warning_tag}")

        messagebox.showinfo("Channel Analysis", "\n".join(lines))

    def export_csv(self):
        if not self.networks:
            messagebox.showinfo("Export", "Perform a scan first.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save Wi-Fi Scan Results",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )

        if not filename:
            return

        try:
            export_networks(self.networks, filename)
            logger.info("Exported scan results to: %s", filename)
            messagebox.showinfo("Export Successful", f"Scan results exported successfully to:\n{filename}")
        except Exception as error:
            logger.error("Export CSV failed: %s", error)
            messagebox.showerror("Export Error", f"Failed to export CSV file:\n{error}")

    # ---------------------------------------------------------
    # AUTO REFRESH SCHEDULER
    # ---------------------------------------------------------

    def toggle_auto_refresh(self):
        self.auto_refresh_enabled = self.auto_refresh_var.get()
        logger.info("Auto Refresh toggled: %s", self.auto_refresh_enabled)

        if self.auto_refresh_timer_id is not None:
            self.root.after_cancel(self.auto_refresh_timer_id)
            self.auto_refresh_timer_id = None

        if self.auto_refresh_enabled:
            self._schedule_auto_refresh()

    def _schedule_auto_refresh(self):
        if not self.auto_refresh_enabled:
            return

        if not self.is_scanning:
            self.start_scan()

        self.auto_refresh_timer_id = self.root.after(
            self.refresh_interval_sec * 1000,
            self._schedule_auto_refresh
        )