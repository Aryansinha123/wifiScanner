import threading
import tkinter as tk

from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog

from scanner.scanner_manager import ScannerManager
from utils.parser import parse_networks
from storage.csv_export import export_networks
from security.analyzer import analyze_security


class MainWindow:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Wi-Fi Network Security Scanner"
        )

        self.root.geometry(
            "1250x700"
        )

        self.root.minsize(
            1000,
            600
        )

        self.scanner = ScannerManager()

        self.networks = []

        self.auto_refresh_enabled = False

        self.refresh_interval = 30

        self.create_interface()

    # ---------------------------------------------------------
    # GUI
    # ---------------------------------------------------------

    def create_interface(self):

        # =========================
        # HEADER
        # =========================

        header = ttk.Frame(
            self.root,
            padding=15
        )

        header.pack(
            fill="x"
        )

        title = ttk.Label(
            header,
            text="Wi-Fi Network Security Scanner",
            font=("Segoe UI", 20, "bold")
        )

        title.pack(
            side="left"
        )

        # =========================
        # CONTROL BAR
        # =========================

        controls = ttk.Frame(
            self.root,
            padding=(15, 5)
        )

        controls.pack(
            fill="x"
        )

        self.scan_button = ttk.Button(
            controls,
            text="Scan Networks",
            command=self.start_scan
        )

        self.scan_button.pack(
            side="left",
            padx=(0, 10)
        )

        self.refresh_button = ttk.Button(
            controls,
            text="Refresh",
            command=self.start_scan
        )

        self.refresh_button.pack(
            side="left",
            padx=5
        )

        self.auto_refresh_var = tk.BooleanVar(
            value=False
        )

        auto_refresh = ttk.Checkbutton(
            controls,
            text="Auto Refresh",
            variable=self.auto_refresh_var,
            command=self.toggle_auto_refresh
        )

        auto_refresh.pack(
            side="left",
            padx=15
        )

        # =========================
        # SEARCH
        # =========================

        search_label = ttk.Label(
            controls,
            text="Search:"
        )

        search_label.pack(
            side="left",
            padx=(30, 5)
        )

        self.search_var = tk.StringVar()

        self.search_var.trace_add(
            "write",
            self.on_search
        )

        search_entry = ttk.Entry(
            controls,
            textvariable=self.search_var,
            width=25
        )

        search_entry.pack(
            side="left"
        )

        # =========================
        # SORT
        # =========================

        sort_label = ttk.Label(
            controls,
            text="Sort:"
        )

        sort_label.pack(
            side="left",
            padx=(20, 5)
        )

        self.sort_var = tk.StringVar(
            value="Signal"
        )

        sort_box = ttk.Combobox(
            controls,
            textvariable=self.sort_var,
            values=[
                "Signal",
                "SSID",
                "Channel",
                "Security"
            ],
            state="readonly",
            width=12
        )

        sort_box.pack(
            side="left"
        )

        sort_box.bind(
            "<<ComboboxSelected>>",
            self.on_sort
        )

        # =========================
        # STATUS
        # =========================

        self.status_var = tk.StringVar(
            value="Ready"
        )

        status = ttk.Label(
            controls,
            textvariable=self.status_var
        )

        status.pack(
            side="right"
        )

        # =========================
        # STATISTICS
        # =========================

        stats = ttk.Frame(
            self.root,
            padding=15
        )

        stats.pack(
            fill="x"
        )

        self.total_var = tk.StringVar(
            value="Networks: 0"
        )

        self.secure_var = tk.StringVar(
            value="WPA2/WPA3: 0"
        )

        self.open_var = tk.StringVar(
            value="Open: 0"
        )

        self.channel_var = tk.StringVar(
            value="Channels: 0"
        )

        ttk.Label(
            stats,
            textvariable=self.total_var,
            font=("Segoe UI", 11, "bold")
        ).pack(
            side="left",
            padx=20
        )

        ttk.Label(
            stats,
            textvariable=self.secure_var,
            font=("Segoe UI", 11, "bold")
        ).pack(
            side="left",
            padx=20
        )

        ttk.Label(
            stats,
            textvariable=self.open_var,
            font=("Segoe UI", 11, "bold")
        ).pack(
            side="left",
            padx=20
        )

        ttk.Label(
            stats,
            textvariable=self.channel_var,
            font=("Segoe UI", 11, "bold")
        ).pack(
            side="left",
            padx=20
        )

        # =========================
        # TABLE
        # =========================

        table_frame = ttk.Frame(
            self.root,
            padding=(15, 5)
        )

        table_frame.pack(
            fill="both",
            expand=True
        )

        columns = (
            "ssid",
            "bssid",
            "signal",
            "rssi",
            "channel",
            "frequency",
            "security",
            "encryption",
            "radio",
            "risk"
        )

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "ssid": "SSID",
            "bssid": "BSSID",
            "signal": "Signal",
            "rssi": "RSSI",
            "channel": "Channel",
            "frequency": "Frequency",
            "security": "Security",
            "encryption": "Encryption",
            "radio": "Radio",
            "risk": "Risk"
        }

        widths = {
            "ssid": 160,
            "bssid": 150,
            "signal": 80,
            "rssi": 80,
            "channel": 80,
            "frequency": 90,
            "security": 100,
            "encryption": 100,
            "radio": 100,
            "risk": 90
        }

        for column in columns:

            self.table.heading(
                column,
                text=headings[column]
            )

            self.table.column(
                column,
                width=widths[column],
                anchor="center"
            )

        vertical_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.table.yview
        )

        horizontal_scrollbar = ttk.Scrollbar(
            table_frame,
            orient="horizontal",
            command=self.table.xview
        )

        self.table.configure(
            yscrollcommand=vertical_scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set
        )

        self.table.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical_scrollbar.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        horizontal_scrollbar.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        table_frame.rowconfigure(
            0,
            weight=1
        )

        table_frame.columnconfigure(
            0,
            weight=1
        )

        # Double click network
        self.table.bind(
            "<Double-1>",
            self.show_network_details
        )

        # =========================
        # BOTTOM BUTTONS
        # =========================

        bottom = ttk.Frame(
            self.root,
            padding=15
        )

        bottom.pack(
            fill="x"
        )

        ttk.Button(
            bottom,
            text="Network Details",
            command=self.show_network_details
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            bottom,
            text="Channel Analysis",
            command=self.show_channel_analysis
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            bottom,
            text="Export CSV",
            command=self.export_csv
        ).pack(
            side="right",
            padx=5
        )

    # ---------------------------------------------------------
    # SCANNING
    # ---------------------------------------------------------

    def start_scan(self):

        self.scan_button.config(
            state="disabled"
        )

        self.refresh_button.config(
            state="disabled"
        )

        self.status_var.set(
            "Scanning..."
        )

        thread = threading.Thread(
            target=self.perform_scan,
            daemon=True
        )

        thread.start()

    def perform_scan(self):

        try:

            raw_data = self.scanner.scan()

            networks = parse_networks(
                raw_data
            )

            self.root.after(
                0,
                lambda: self.scan_completed(
                    networks
                )
            )

        except Exception as error:

            self.root.after(
                0,
                lambda: self.scan_failed(
                    str(error)
                )
            )

    def scan_completed(self, networks):

        self.networks = networks

        self.scan_button.config(
            state="normal"
        )

        self.refresh_button.config(
            state="normal"
        )

        self.status_var.set(
            f"Scan complete — {len(networks)} networks found"
        )

        self.update_statistics()

        self.refresh_table()

    def scan_failed(self, error):

        self.scan_button.config(
            state="normal"
        )

        self.refresh_button.config(
            state="normal"
        )

        self.status_var.set(
            "Scan failed"
        )

        messagebox.showerror(
            "Scan Error",
            error
        )

    # ---------------------------------------------------------
    # TABLE
    # ---------------------------------------------------------

    def refresh_table(self):

        for item in self.table.get_children():

            self.table.delete(item)

        networks = self.get_filtered_networks()

        for network in networks:

            self.table.insert(
                "",
                "end",
                values=(
                    network.ssid,
                    network.bssid,
                    f"{network.signal_percent}%",
                    f"{network.signal_dbm} dBm",
                    network.channel,
                    network.frequency,
                    network.security,
                    network.encryption,
                    network.radio_type,
                    network.risk_level()
                )
            )

    def get_filtered_networks(self):

        query = (
            self.search_var.get()
            .strip()
            .lower()
        )

        networks = self.networks

        if query:

            networks = [
                network
                for network in networks
                if query in network.ssid.lower()
                or query in network.bssid.lower()
                or query in network.security.lower()
            ]

        sort_type = self.sort_var.get()

        if sort_type == "Signal":

            networks = sorted(
                networks,
                key=lambda n: n.signal_percent,
                reverse=True
            )

        elif sort_type == "SSID":

            networks = sorted(
                networks,
                key=lambda n: n.ssid.lower()
            )

        elif sort_type == "Channel":

            networks = sorted(
                networks,
                key=lambda n: (
                    n.channel
                    if n.channel is not None
                    else 999
                )
            )

        elif sort_type == "Security":

            security_order = {
                "WPA3": 1,
                "WPA2": 2,
                "WPA": 3,
                "WEP": 4,
                "OPEN": 5,
                "UNKNOWN": 6
            }

            networks = sorted(
                networks,
                key=lambda n: security_order.get(
                    n.security,
                    99
                )
            )

        return networks

    # ---------------------------------------------------------
    # SEARCH / SORT
    # ---------------------------------------------------------

    def on_search(self, *args):

        self.refresh_table()

    def on_sort(self, event=None):

        self.refresh_table()

    # ---------------------------------------------------------
    # STATISTICS
    # ---------------------------------------------------------

    def update_statistics(self):

        total = len(
            self.networks
        )

        secure = sum(
            1
            for n in self.networks
            if n.security in ("WPA2", "WPA3")
        )

        open_networks = sum(
            1
            for n in self.networks
            if n.security == "OPEN"
        )

        channels = len(
            set(
                n.channel
                for n in self.networks
                if n.channel is not None
            )
        )

        self.total_var.set(
            f"Networks: {total}"
        )

        self.secure_var.set(
            f"WPA2/WPA3: {secure}"
        )

        self.open_var.set(
            f"Open: {open_networks}"
        )

        self.channel_var.set(
            f"Channels: {channels}"
        )

    # ---------------------------------------------------------
    # NETWORK DETAILS
    # ---------------------------------------------------------

    def show_network_details(self, event=None):

        selected = self.table.selection()

        if not selected:

            messagebox.showinfo(
                "Network Details",
                "Select a network first."
            )

            return

        item = selected[0]

        values = self.table.item(
            item,
            "values"
        )

        ssid = values[0]

        network = next(
            (
                n for n in self.networks
                if n.ssid == ssid
                and n.bssid == values[1]
            ),
            None
        )

        if network is None:
            return

        analysis = analyze_security(
            network.security
        )

        details = (
            f"SSID: {network.ssid}\n\n"
            f"BSSID: {network.bssid}\n\n"
            f"Signal: {network.signal_percent}%\n\n"
            f"Estimated RSSI: {network.signal_dbm} dBm\n\n"
            f"Channel: {network.channel}\n\n"
            f"Frequency: {network.frequency}\n\n"
            f"Security: {network.security}\n\n"
            f"Encryption: {network.encryption}\n\n"
            f"Radio: {network.radio_type}\n\n"
            f"Security Score: {analysis['score']}/100\n\n"
            f"Risk Level: {analysis['level']}\n\n"
            f"Analysis: {analysis['description']}"
        )

        messagebox.showinfo(
            "Network Details",
            details
        )

    # ---------------------------------------------------------
    # CHANNEL ANALYSIS
    # ---------------------------------------------------------

    def show_channel_analysis(self):

        if not self.networks:

            messagebox.showinfo(
                "Channel Analysis",
                "Perform a scan first."
            )

            return

        channel_counts = {}

        for network in self.networks:

            channel = network.channel

            if channel is None:
                continue

            channel_counts[channel] = (
                channel_counts.get(channel, 0) + 1
            )

        if not channel_counts:

            messagebox.showinfo(
                "Channel Analysis",
                "No channel information available."
            )

            return

        lines = [
            "CHANNEL ANALYSIS",
            "",
        ]

        for channel in sorted(
            channel_counts
        ):

            count = channel_counts[channel]

            warning = ""

            if count >= 4:
                warning = "  <-- HIGH CONGESTION"

            lines.append(
                f"Channel {channel}: "
                f"{count} network(s)"
                f"{warning}"
            )

        messagebox.showinfo(
            "Channel Analysis",
            "\n".join(lines)
        )

    # ---------------------------------------------------------
    # CSV
    # ---------------------------------------------------------

    def export_csv(self):

        if not self.networks:

            messagebox.showinfo(
                "Export",
                "Perform a scan first."
            )

            return

        filename = filedialog.asksaveasfilename(
            title="Save Wi-Fi Scan",
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ]
        )

        if not filename:
            return

        try:

            export_networks(
                self.networks,
                filename
            )

            messagebox.showinfo(
                "Export Successful",
                f"Scan exported to:\n{filename}"
            )

        except Exception as error:

            messagebox.showerror(
                "Export Error",
                str(error)
            )

    # ---------------------------------------------------------
    # AUTO REFRESH
    # ---------------------------------------------------------

    def toggle_auto_refresh(self):

        self.auto_refresh_enabled = (
            self.auto_refresh_var.get()
        )

        if self.auto_refresh_enabled:

            self.auto_refresh()

    def auto_refresh(self):

        if not self.auto_refresh_enabled:
            return

        self.start_scan()

        self.root.after(
            self.refresh_interval * 1000,
            self.auto_refresh
        )