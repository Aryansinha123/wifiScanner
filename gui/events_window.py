import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Dict, Any
from storage.database import DatabaseManager


class EventsWindow(ttk.Frame):
    """
    Security Event Management & Real-Time Alerts View (Feature 2).
    Includes dedicated tabs for Real-Time Alerts and Security Event Timeline.
    """

    def __init__(self, parent: tk.Widget, db_manager: DatabaseManager):
        super().__init__(parent, padding=15)
        self.db = db_manager

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self.create_widgets()
        self.refresh_alerts()
        self.refresh_events()

    def create_widgets(self):
        # Header
        hdr = ttk.Frame(self)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(hdr, text="Security Alerts & Event Management Timeline", font=("Segoe UI", 14, "bold")).pack(side="left")

        # Tabs
        self.tabs = ttk.Notebook(self)
        self.tabs.grid(row=1, column=0, sticky="nsew")

        # -------------------------------------------------------------
        # TAB 1: REAL-TIME ALERTS (Feature 2)
        # -------------------------------------------------------------
        alerts_tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(alerts_tab, text=" 🚨 Real-Time Security Alerts ")
        alerts_tab.columnconfigure(0, weight=1)
        alerts_tab.rowconfigure(1, weight=1)

        # Filters Bar for Alerts
        a_flt = ttk.Frame(alerts_tab)
        a_flt.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        ttk.Label(a_flt, text="Severity:").pack(side="left", padx=(0, 4))
        self.alert_sev_var = tk.StringVar(value="ALL")
        a_sev_box = ttk.Combobox(a_flt, textvariable=self.alert_sev_var, values=["ALL", "CRITICAL", "HIGH", "MEDIUM", "INFO"], state="readonly", width=10)
        a_sev_box.pack(side="left", padx=(0, 10))
        a_sev_box.bind("<<ComboboxSelected>>", lambda e: self.refresh_alerts())

        ttk.Label(a_flt, text="Status:").pack(side="left", padx=(0, 4))
        self.alert_status_var = tk.StringVar(value="ALL")
        a_st_box = ttk.Combobox(a_flt, textvariable=self.alert_status_var, values=["ALL", "NEW", "ACKNOWLEDGED"], state="readonly", width=14)
        a_st_box.pack(side="left", padx=(0, 10))
        a_st_box.bind("<<ComboboxSelected>>", lambda e: self.refresh_alerts())

        # Acknowledge Button
        ttk.Button(a_flt, text="✓ Acknowledge Selected Alert", command=self.acknowledge_selected_alert).pack(side="right", padx=4)
        ttk.Button(a_flt, text="Refresh Alerts", command=self.refresh_alerts).pack(side="right", padx=4)

        # Alerts Treeview
        a_frame = ttk.Frame(alerts_tab)
        a_frame.grid(row=1, column=0, sticky="nsew")
        a_frame.rowconfigure(0, weight=1)
        a_frame.columnconfigure(0, weight=1)

        a_cols = ("id", "type", "severity", "ssid", "bssid", "message", "status", "created_at", "last_sent_at")
        self.alerts_table = ttk.Treeview(a_frame, columns=a_cols, show="headings", selectmode="browse")

        self.alerts_table.heading("id", text="ID")
        self.alerts_table.heading("type", text="Alert Type")
        self.alerts_table.heading("severity", text="Severity")
        self.alerts_table.heading("ssid", text="SSID")
        self.alerts_table.heading("bssid", text="BSSID")
        self.alerts_table.heading("message", text="Alert Message / Evidence")
        self.alerts_table.heading("status", text="Status")
        self.alerts_table.heading("created_at", text="Created At")
        self.alerts_table.heading("last_sent_at", text="Last Sent")

        self.alerts_table.column("id", width=40, anchor="center")
        self.alerts_table.column("type", width=160)
        self.alerts_table.column("severity", width=80, anchor="center")
        self.alerts_table.column("ssid", width=130)
        self.alerts_table.column("bssid", width=130)
        self.alerts_table.column("message", width=300)
        self.alerts_table.column("status", width=95, anchor="center")
        self.alerts_table.column("created_at", width=130)
        self.alerts_table.column("last_sent_at", width=130)

        a_sb = ttk.Scrollbar(a_frame, orient="vertical", command=self.alerts_table.yview)
        self.alerts_table.configure(yscrollcommand=a_sb.set)

        self.alerts_table.grid(row=0, column=0, sticky="nsew")
        a_sb.grid(row=0, column=1, sticky="ns")

        # -------------------------------------------------------------
        # TAB 2: SECURITY EVENTS TIMELINE LOG
        # -------------------------------------------------------------
        events_tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(events_tab, text=" 📜 Security Events Timeline ")
        events_tab.columnconfigure(0, weight=1)
        events_tab.rowconfigure(1, weight=1)

        flt_bar = ttk.Frame(events_tab)
        flt_bar.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        ttk.Label(flt_bar, text="Severity:").pack(side="left", padx=(0, 4))
        self.sev_var = tk.StringVar(value="ALL")
        sev_box = ttk.Combobox(flt_bar, textvariable=self.sev_var, values=["ALL", "INFO", "MEDIUM", "HIGH", "CRITICAL"], state="readonly", width=10)
        sev_box.pack(side="left", padx=(0, 10))
        sev_box.bind("<<ComboboxSelected>>", self.on_filter_change)

        ttk.Label(flt_bar, text="Event Type:").pack(side="left", padx=(0, 4))
        self.type_var = tk.StringVar(value="ALL")
        type_box = ttk.Combobox(flt_bar, textvariable=self.type_var, values=[
            "ALL", "EVIL_TWIN_DETECTED", "ARP_SPOOFING_DETECTED", "DNS_HIJACKING_DETECTED",
            "SECURITY_DOWNGRADE", "SECURITY_CHANGE", "SECURITY_UPGRADE", "NEW_NETWORK",
            "NETWORK_NOT_DETECTED", "NETWORK_REAPPEARED", "CHANNEL_CHANGE", "SSID_CHANGE", "BASELINE_DEVIATION"
        ], state="readonly", width=22)
        type_box.pack(side="left", padx=(0, 10))
        type_box.bind("<<ComboboxSelected>>", self.on_filter_change)

        ttk.Label(flt_bar, text="Search:").pack(side="left", padx=(0, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_filter_change)
        search_entry = ttk.Entry(flt_bar, textvariable=self.search_var, width=18)
        search_entry.pack(side="left")

        ttk.Button(flt_bar, text="Acknowledge Selected", command=self.acknowledge_selected_event).pack(side="right", padx=4)
        ttk.Button(flt_bar, text="Refresh Events", command=self.refresh_events).pack(side="right")

        table_frame = ttk.Frame(events_tab)
        table_frame.grid(row=1, column=0, sticky="nsew")
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
        self.table.column("timestamp", width=130)
        self.table.column("type", width=160)
        self.table.column("severity", width=80, anchor="center")
        self.table.column("ssid", width=130)
        self.table.column("bssid", width=130)
        self.table.column("description", width=260)
        self.table.column("ack", width=50, anchor="center")

        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=sb.set)

        self.table.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")

    # -------------------------------------------------------------
    # ALERTS LOGIC (Feature 2)
    # -------------------------------------------------------------

    def refresh_alerts(self):
        for item in self.alerts_table.get_children():
            self.alerts_table.delete(item)

        alerts = self.db.repos.get_alerts(
            severity=self.alert_sev_var.get(),
            status=self.alert_status_var.get(),
            limit=300
        )

        for a in alerts:
            self.alerts_table.insert("", "end", values=(
                a["id"],
                a["alert_type"],
                a["severity"],
                a.get("ssid", "Unknown"),
                a.get("bssid", "Unknown"),
                a.get("message", ""),
                a.get("status", "NEW"),
                a.get("created_at", ""),
                a.get("last_sent_at", "")
            ))

    def acknowledge_selected_alert(self):
        selected = self.alerts_table.selection()
        if not selected:
            messagebox.showinfo("Acknowledge", "Please select an alert from the table first.")
            return

        alert_id = int(self.alerts_table.item(selected[0], "values")[0])
        self.db.repos.mark_alert_acknowledged(alert_id)
        self.refresh_alerts()
        messagebox.showinfo("Success", f"Alert #{alert_id} acknowledged. Repeated alerts for this event are now stopped.")

    # -------------------------------------------------------------
    # EVENTS LOGIC
    # -------------------------------------------------------------

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

    def acknowledge_selected_event(self):
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo("Acknowledge", "Please select an event from the table first.")
            return

        event_id = int(self.table.item(selected[0], "values")[0])
        self.db.mark_event_acknowledged(event_id)
        self.refresh_events()
        messagebox.showinfo("Success", f"Event #{event_id} marked as acknowledged.")
