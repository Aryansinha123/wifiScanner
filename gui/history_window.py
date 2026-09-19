import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any
from storage.database import DatabaseManager


class HistoryWindow:
    """
    Modal window displaying historical observation records for a specific network BSSID.
    """

    def __init__(self, parent: tk.Tk, db: DatabaseManager, bssid: str, ssid: str):
        self.parent = parent
        self.db = db
        self.bssid = bssid
        self.ssid = ssid

        self.win = tk.Toplevel(self.parent)
        self.win.title(f"Network History — {self.ssid} ({self.bssid})")
        self.win.geometry("850x500")
        self.win.minsize(750, 400)
        self.win.transient(self.parent)
        self.win.grab_set()

        self.create_interface()

    def create_interface(self):
        # Header
        top_frame = ttk.Frame(self.win, padding=15)
        top_frame.pack(fill="x")

        ttk.Label(top_frame, text=f"Network History: {self.ssid}", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(top_frame, text=f"BSSID MAC: {self.bssid}", font=("Segoe UI", 9), foreground="#555555").pack(anchor="w")

        # Fetch first_seen & last_seen from tracked networks table
        tracked_list = self.db.get_all_tracked_networks()
        net_entry = next((n for n in tracked_list if n["bssid"] == self.bssid), None)

        first_seen = net_entry["first_seen"] if net_entry else "Unknown"
        last_seen = net_entry["last_seen"] if net_entry else "Unknown"

        meta_frame = ttk.Frame(top_frame, padding=(0, 5))
        meta_frame.pack(anchor="w")
        ttk.Label(meta_frame, text=f"First Seen: {first_seen}   |   Last Seen: {last_seen}", font=("Segoe UI", 9, "italic"), foreground="#333333").pack(anchor="w")

        # History Table
        table_frame = ttk.Frame(self.win, padding=(15, 5))
        table_frame.pack(fill="both", expand=True)

        columns = ("timestamp", "signal", "rssi", "channel", "band", "security", "encryption", "radio")

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        headings = {
            "timestamp": "Timestamp",
            "signal": "Signal",
            "rssi": "Estimated RSSI",
            "channel": "Channel",
            "band": "Band",
            "security": "Security",
            "encryption": "Encryption",
            "radio": "Radio Type"
        }

        widths = {
            "timestamp": 150,
            "signal": 75,
            "rssi": 100,
            "channel": 75,
            "band": 85,
            "security": 95,
            "encryption": 95,
            "radio": 95
        }

        for col in columns:
            self.table.heading(col, text=headings[col])
            self.table.column(col, width=widths[col], anchor="center" if col != "timestamp" else "w")

        v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.table.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        # Load records
        history = self.db.get_network_history(self.bssid)
        for h in history:
            sig = h.get("signal_percent", 0)
            rssi = h.get("estimated_rssi")
            rssi_str = f"{rssi} dBm" if rssi is not None else "Unknown"

            self.table.insert(
                "",
                "end",
                values=(
                    h.get("timestamp", "N/A"),
                    f"{sig}%",
                    rssi_str,
                    h.get("channel", "N/A"),
                    h.get("band", "N/A"),
                    h.get("security", "N/A"),
                    h.get("encryption", "N/A"),
                    h.get("radio_type", "N/A")
                )
            )

        # Close button
        btn_frame = ttk.Frame(self.win, padding=10)
        btn_frame.pack(fill="x")
        ttk.Button(btn_frame, text="Close", command=self.win.destroy, width=12).pack(side="right")
