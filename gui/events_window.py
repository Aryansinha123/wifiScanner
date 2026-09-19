import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Dict, Any
from storage.database import DatabaseManager


class EventsWindow(ttk.Frame):
    """
    Security Events & Timeline Log view.
    Supports filtering by severity, event type, global search, and acknowledgment.
    """

    def __init__(self, parent: tk.Widget, db_manager: DatabaseManager):
        super().__init__(parent, padding=15)
        self.db = db_manager

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        self.create_widgets()
        self.refresh_events()

    def create_widgets(self):
        # Header
        hdr = ttk.Frame(self)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(hdr, text="Security Event Management & Timeline", font=("Segoe UI", 14, "bold")).pack(side="left")

        # Filters Bar
        flt_bar = ttk.Frame(self)
        flt_bar.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(flt_bar, text="Severity:").pack(side="left", padx=(0, 4))
        self.sev_var = tk.StringVar(value="ALL")
        sev_box = ttk.Combobox(flt_bar, textvariable=self.sev_var, values=["ALL", "INFO", "MEDIUM", "HIGH", "CRITICAL"], state="readonly", width=10)
        sev_box.pack(side="left", padx=(0, 10))
        sev_box.bind("<<ComboboxSelected>>", self.on_filter_change)

        ttk.Label(flt_bar, text="Event Type:").pack(side="left", padx=(0, 4))
        self.type_var = tk.StringVar(value="ALL")
        type_box = ttk.Combobox(flt_bar, textvariable=self.type_var, values=[
            "ALL", "NEW_NETWORK", "NETWORK_NOT_DETECTED", "NETWORK_REAPPEARED",
            "SECURITY_CHANGE", "SECURITY_DOWNGRADE", "SECURITY_UPGRADE",
            "CHANNEL_CHANGE", "SSID_CHANGE", "SIGNAL_CHANGE", "BASELINE_DEVIATION"
        ], state="readonly", width=22)
        type_box.pack(side="left", padx=(0, 10))
        type_box.bind("<<ComboboxSelected>>", self.on_filter_change)

        ttk.Label(flt_bar, text="Search:").pack(side="left", padx=(0, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_filter_change)
        search_entry = ttk.Entry(flt_bar, textvariable=self.search_var, width=18)
        search_entry.pack(side="left")

        ttk.Button(flt_bar, text="Acknowledge Selected", command=self.acknowledge_selected).pack(side="right", padx=4)
        ttk.Button(flt_bar, text="Refresh", command=self.refresh_events).pack(side="right")

        # Treeview Table
        table_frame = ttk.Frame(self)
        table_frame.grid(row=2, column=0, sticky="nsew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        columns = ("id", "timestamp", "type", "severity", "ssid", "bssid", "description", "ack")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        self.table.heading("id", text="ID")
        self.table.heading("timestamp", text="Timestamp")
        self.table.heading("type", text="Event Type")
        self.table.heading("severity", text="Severity")
        self.table.heading("ssid", text="SSID")
        self.table.heading("bssid", text="BSSID")
        self.table.heading("description", text="Description")
        self.table.heading("ack", text="Ack")

        self.table.column("id", width=45, anchor="center")
        self.table.column("timestamp", width=140)
        self.table.column("type", width=160)
        self.table.column("severity", width=80, anchor="center")
        self.table.column("ssid", width=140)
        self.table.column("bssid", width=130)
        self.table.column("description", width=260)
        self.table.column("ack", width=50, anchor="center")

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=sb.set)

        self.table.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")

    def refresh_events(self):
        for item in self.table.get_children():
            self.table.delete(item)

        events = self.db.get_events(
            severity=self.sev_var.get(),
            event_type=self.type_var.get(),
            search=self.search_var.get().strip(),
            limit=300
        )

        for ev in events:
            ack_str = "Yes" if ev.get("acknowledged", 0) == 1 else "No"
            self.table.insert("", "end", values=(
                ev["id"],
                ev["timestamp"],
                ev["event_type"],
                ev["severity"],
                ev.get("ssid", ""),
                ev.get("bssid", ""),
                ev.get("description", ""),
                ack_str
            ))

    def on_filter_change(self, *args):
        self.refresh_events()

    def acknowledge_selected(self):
        selected = self.table.selection()
        if not selected:
            return

        ev_id = int(self.table.item(selected[0], "values")[0])
        self.db.mark_event_acknowledged(ev_id)
        self.refresh_events()
