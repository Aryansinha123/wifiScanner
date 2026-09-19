import logging
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import List, Dict, Any, Optional

from storage.database import DatabaseManager
from monitoring.event_manager import EventManager
from gui.history_window import HistoryWindow

logger = logging.getLogger(__name__)


class MonitoringWindow:
    """
    GUI Window for Wi-Fi Security Monitor Dashboard.
    """

    def __init__(self, parent: tk.Tk, db: DatabaseManager, event_mgr: EventManager):
        self.parent = parent
        self.db = db
        self.event_mgr = event_mgr

        self.win = tk.Toplevel(self.parent)
        self.win.title("Wi-Fi Security Monitor & Change Detection Dashboard")
        self.win.geometry("1100x700")
        self.win.minsize(950, 600)
        self.win.transient(self.parent)

        self.create_interface()
        self.refresh_dashboard()

    def create_interface(self):
        self.win.rowconfigure(3, weight=1)  # Table expands
        self.win.columnconfigure(0, weight=1)

        # Style Configuration
        self.style = ttk.Style()

        # Row Tag Colors for Events
        self.event_tags = {
            "CRITICAL": {"background": "#FADBD8"},
            "HIGH": {"background": "#FDEBD0"},
            "MEDIUM": {"background": "#FCF3CF"},
            "INFO": {"background": "#EBF5FB"}
        }

        # ==========================================
        # 1. HEADER SECTION
        # ==========================================
        header_frame = ttk.Frame(self.win, padding=(15, 10))
        header_frame.grid(row=0, column=0, sticky="ew")

        ttk.Label(header_frame, text="Wi-Fi Security Monitor", font=("Segoe UI", 16, "bold")).pack(side="left")

        status_frame = ttk.Frame(header_frame)
        status_frame.pack(side="right")
        ttk.Label(status_frame, text="Monitoring Status: ", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Label(status_frame, text="ACTIVE", font=("Segoe UI", 10, "bold"), foreground="#27AE60").pack(side="left")

        # ==========================================
        # 2. STATISTIC CARDS PANEL
        # ==========================================
        stats_frame = ttk.Frame(self.win, padding=(15, 5))
        stats_frame.grid(row=1, column=0, sticky="ew")

        self.stat_vars = {
            "scans": tk.StringVar(value="0"),
            "tracked": tk.StringVar(value="0"),
            "active": tk.StringVar(value="0"),
            "new_nets": tk.StringVar(value="0"),
            "not_detected": tk.StringVar(value="0"),
            "sec_changes": tk.StringVar(value="0"),
            "high_severity": tk.StringVar(value="0")
        }

        card_defs = [
            ("TOTAL SCANS", self.stat_vars["scans"], 0),
            ("TRACKED BSSIDs", self.stat_vars["tracked"], 1),
            ("ACTIVE BSSIDs", self.stat_vars["active"], 2),
            ("NEW BSSIDs", self.stat_vars["new_nets"], 3),
            ("CONFIRMED MISSING", self.stat_vars["not_detected"], 4),
            ("SECURITY CHANGES", self.stat_vars["sec_changes"], 5),
            ("HIGH SEVERITY", self.stat_vars["high_severity"], 6)
        ]

        for title, var, col in card_defs:
            card = ttk.Frame(stats_frame, relief="groove", padding=(8, 4))
            card.grid(row=0, column=col, padx=3, sticky="nsew")
            stats_frame.columnconfigure(col, weight=1)

            ttk.Label(card, text=title, font=("Segoe UI", 7, "bold"), foreground="#555555").pack(anchor="w")
            ttk.Label(card, textvariable=var, font=("Segoe UI", 14, "bold"), foreground="#000000").pack(anchor="w")

        # ==========================================
        # 3. EVENT FILTERING BAR
        # ==========================================
        filter_frame = ttk.Frame(self.win, padding=(15, 5))
        filter_frame.grid(row=2, column=0, sticky="ew")

        # Severity Filter
        ttk.Label(filter_frame, text="Severity:").pack(side="left", padx=(0, 4))
        self.sev_filter_var = tk.StringVar(value="All")
        sev_box = ttk.Combobox(
            filter_frame,
            textvariable=self.sev_filter_var,
            values=["All", "INFO", "MEDIUM", "HIGH", "CRITICAL"],
            state="readonly",
            width=10
        )
        sev_box.pack(side="left", padx=(0, 10))
        sev_box.bind("<<ComboboxSelected>>", self.on_filter_change)

        # Event Type Filter
        ttk.Label(filter_frame, text="Event Type:").pack(side="left", padx=(5, 4))
        self.type_filter_var = tk.StringVar(value="All")
        type_box = ttk.Combobox(
            filter_frame,
            textvariable=self.type_filter_var,
            values=[
                "All",
                "NEW_NETWORK",
                "NETWORK_NOT_DETECTED",
                "NETWORK_REAPPEARED",
                "SECURITY_CHANGE",
                "SECURITY_DOWNGRADE",
                "SECURITY_UPGRADE",
                "CHANNEL_CHANGE",
                "SSID_CHANGE",
                "SIGNAL_CHANGE"
            ],
            state="readonly",
            width=18
        )
        type_box.pack(side="left", padx=(0, 10))
        type_box.bind("<<ComboboxSelected>>", self.on_filter_change)

        # Search Bar
        ttk.Label(filter_frame, text="Search:").pack(side="left", padx=(5, 4))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.on_filter_change)
        search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=22)
        search_entry.pack(side="left")

        # Refresh button right
        ttk.Button(filter_frame, text="Refresh Logs", command=self.refresh_dashboard).pack(side="right")

        # ==========================================
        # 4. RECENT EVENTS LOG TABLE
        # ==========================================
        table_frame = ttk.Frame(self.win, padding=(15, 5))
        table_frame.grid(row=3, column=0, sticky="nsew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        columns = ("time", "type", "severity", "ssid", "bssid", "description", "status")

        self.table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        headings = {
            "time": "Time",
            "type": "Event Type",
            "severity": "Severity",
            "ssid": "SSID",
            "bssid": "BSSID",
            "description": "Description",
            "status": "Status"
        }

        widths = {
            "time": 140,
            "type": 150,
            "severity": 80,
            "ssid": 160,
            "bssid": 140,
            "description": 240,
            "status": 90
        }

        for col in columns:
            self.table.heading(col, text=headings[col])
            self.table.column(col, width=widths[col], anchor="center" if col in ("time", "severity", "status") else "w")

        # Apply Tag colors
        for tag, kwargs in self.event_tags.items():
            self.table.tag_configure(tag, **kwargs)

        v_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        h_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.table.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        self.table.bind("<Double-1>", self.show_event_details)

        # ==========================================
        # 5. MONITORING LIMITATIONS NOTICE
        # ==========================================
        notice_frame = ttk.Frame(self.win, padding=(15, 4))
        notice_frame.grid(row=4, column=0, sticky="ew")

        notice_text = (
            "Monitoring Limitations: This application performs passive wireless observation using operating system WLAN endpoints. "
            "A network appearing, disappearing, or changing configuration does not by itself indicate malicious activity. Events should be treated as indicators for further investigation."
        )
        ttk.Label(notice_frame, text=notice_text, font=("Segoe UI", 8, "italic"), foreground="#666666", wraplength=1040).pack(anchor="w")

        # ==========================================
        # 6. BOTTOM CONTROLS
        # ==========================================
        bottom_frame = ttk.Frame(self.win, padding=(15, 10))
        bottom_frame.grid(row=5, column=0, sticky="ew")

        ttk.Button(
            bottom_frame,
            text="Event Details",
            command=self.show_event_details
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            bottom_frame,
            text="Network History",
            command=self.show_network_history
        ).pack(side="left", padx=4)

        ttk.Button(
            bottom_frame,
            text="Export Events CSV",
            command=self.export_events_csv
        ).pack(side="left", padx=4)

        ttk.Button(
            bottom_frame,
            text="Clear History",
            command=self.clear_history
        ).pack(side="left", padx=15)

        ttk.Button(
            bottom_frame,
            text="Close",
            command=self.win.destroy,
            width=12
        ).pack(side="right")

    # ---------------------------------------------------------
    # REFRESH DATA & EVENTS TABLE
    # ---------------------------------------------------------

    def refresh_dashboard(self):
        # Update Stats Cards
        st = self.db.get_monitoring_stats()
        self.stat_vars["scans"].set(str(st.get("total_scans", 0)))
        self.stat_vars["tracked"].set(str(st.get("tracked_bssids", 0)))
        self.stat_vars["active"].set(str(st.get("active_bssids", 0)))
        self.stat_vars["new_nets"].set(str(st.get("new_networks_count", 0)))
        self.stat_vars["not_detected"].set(str(st.get("not_detected_count", 0)))
        self.stat_vars["sec_changes"].set(str(st.get("security_changes_count", 0)))
        self.stat_vars["high_severity"].set(str(st.get("high_severity_events", 0)))

        # Refresh Event Table
        for item in self.table.get_children():
            self.table.delete(item)

        sev = self.sev_filter_var.get()
        ev_type = self.type_filter_var.get()
        search_query = self.search_var.get()

        events = self.event_mgr.get_events(
            severity=sev,
            event_type=ev_type,
            search=search_query,
            limit=250
        )

        for ev in events:
            ev_id = ev["id"]
            sev_level = ev.get("severity", "INFO")
            status_text = "ACKNOWLEDGED" if ev.get("acknowledged") else "ACTIVE"

            self.table.insert(
                "",
                "end",
                iid=str(ev_id),
                values=(
                    ev.get("timestamp", ""),
                    ev.get("event_type", ""),
                    sev_level,
                    ev.get("ssid", ""),
                    ev.get("bssid", ""),
                    ev.get("description", ""),
                    status_text
                ),
                tags=(sev_level,)
            )

    def on_filter_change(self, *args):
        self.refresh_dashboard()

    # ---------------------------------------------------------
    # DIALOG: EVENT DETAILS
    # ---------------------------------------------------------

    def show_event_details(self, event=None):
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo("Event Details", "Please select an event from the table first.")
            return

        ev_id = int(selected[0])
        events = self.event_mgr.get_events(limit=500)
        ev_data = next((e for e in events if e["id"] == ev_id), None)

        if not ev_data:
            messagebox.showerror("Error", "Event details could not be found.")
            return

        # Event Modal
        win = tk.Toplevel(self.win)
        win.title(f"Event Details — #{ev_id} ({ev_data['event_type']})")
        win.geometry("520x480")
        win.resizable(False, False)
        win.transient(self.win)
        win.grab_set()

        top = ttk.Frame(win, padding=15)
        top.pack(fill="x")
        ttk.Label(top, text=f"Event: {ev_data['event_type']}", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        ttk.Label(top, text=f"Timestamp: {ev_data['timestamp']}", font=("Segoe UI", 9), foreground="#666666").pack(anchor="w")

        grid_frame = ttk.LabelFrame(win, text=" Event Parameters ", padding=12)
        grid_frame.pack(fill="x", padx=15, pady=5)

        params = [
            ("Severity Level:", ev_data["severity"]),
            ("Network SSID:", ev_data["ssid"]),
            ("Access Point BSSID:", ev_data["bssid"]),
            ("Previous State:", ev_data["old_value"] if ev_data["old_value"] else "N/A"),
            ("New State:", ev_data["new_value"] if ev_data["new_value"] else "N/A"),
            ("Status:", "ACKNOWLEDGED" if ev_data["acknowledged"] else "ACTIVE")
        ]

        for idx, (k, v) in enumerate(params):
            ttk.Label(grid_frame, text=k, font=("Segoe UI", 9, "bold")).grid(row=idx, column=0, sticky="w", py=3)
            ttk.Label(grid_frame, text=v, font=("Segoe UI", 9)).grid(row=idx, column=1, sticky="w", px=15, py=3)

        desc_frame = ttk.LabelFrame(win, text=" Explanation ", padding=12)
        desc_frame.pack(fill="x", padx=15, pady=10)
        ttk.Label(desc_frame, text=ev_data["description"], font=("Segoe UI", 9, "italic"), wraplength=440).pack(anchor="w")

        btn_frame = ttk.Frame(win, padding=10)
        btn_frame.pack(fill="x")

        def ack_action():
            self.event_mgr.mark_event_acknowledged(ev_id)
            self.refresh_dashboard()
            win.destroy()

        if not ev_data["acknowledged"]:
            ttk.Button(btn_frame, text="Acknowledge", command=ack_action, width=14).pack(side="left")

        ttk.Button(btn_frame, text="Close", command=win.destroy, width=12).pack(side="right")

    # ---------------------------------------------------------
    # DIALOG: NETWORK HISTORY FROM EVENT
    # ---------------------------------------------------------

    def show_network_history(self):
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo("Network History", "Please select an event from the table first.")
            return

        ev_id = int(selected[0])
        events = self.event_mgr.get_events(limit=500)
        ev_data = next((e for e in events if e["id"] == ev_id), None)

        if not ev_data or not ev_data["bssid"]:
            messagebox.showinfo("Network History", "Selected event has no valid BSSID.")
            return

        HistoryWindow(self.win, self.db, ev_data["bssid"], ev_data["ssid"])

    # ---------------------------------------------------------
    # EXPORT EVENTS CSV
    # ---------------------------------------------------------

    def export_events_csv(self):
        events = self.event_mgr.get_events(limit=1000)
        if not events:
            messagebox.showinfo("Export Events", "No security events available to export.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save Security Events to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )

        if not filename:
            return

        try:
            with open(filename, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow([
                    "Timestamp",
                    "Event Type",
                    "Severity",
                    "SSID",
                    "BSSID",
                    "Description",
                    "Old Value",
                    "New Value",
                    "Acknowledged"
                ])

                for ev in events:
                    writer.writerow([
                        ev.get("timestamp", ""),
                        ev.get("event_type", ""),
                        ev.get("severity", ""),
                        ev.get("ssid", ""),
                        ev.get("bssid", ""),
                        ev.get("description", ""),
                        ev.get("old_value", ""),
                        ev.get("new_value", ""),
                        "YES" if ev.get("acknowledged") else "NO"
                    ])

            logger.info("Exported events to %s", filename)
            messagebox.showinfo("Export Successful", f"Security events exported successfully to:\n\n{filename}")
        except Exception as err:
            logger.error("Export events CSV failed: %s", err)
            messagebox.showerror("Export Error", f"Failed to export events CSV:\n\n{err}")

    # ---------------------------------------------------------
    # CLEAR DATABASE HISTORY
    # ---------------------------------------------------------

    def clear_history(self):
        confirm = messagebox.askyesno(
            "Confirm Clear History",
            "Are you sure you want to clear all scan history, tracked networks, and security events?\n\nThis action cannot be undone.",
            icon="warning"
        )
        if confirm:
            if self.db.clear_history():
                self.refresh_dashboard()
                messagebox.showinfo("History Cleared", "Database history and event log have been cleared successfully.")
            else:
                messagebox.showerror("Error", "Failed to clear database history.")
