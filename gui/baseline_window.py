import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import List, Dict, Any, Optional
from storage.database import DatabaseManager
from monitoring.baseline_manager import BaselineManager


class BaselineWindow(ttk.Frame):
    """
    Baseline Management view for establishing environment baselines
    and managing Trusted Networks for Evil Twin / Rogue AP Detection.
    """

    def __init__(self, parent: tk.Widget, db_manager: DatabaseManager):
        super().__init__(parent, padding=15)
        self.db = db_manager
        self.baseline_mgr = BaselineManager(self.db)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self.create_widgets()
        self.refresh_baselines()
        self.refresh_trusted_networks()

    def create_widgets(self):
        # Header
        hdr = ttk.Frame(self)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(hdr, text="Wireless Baseline & Trusted Network Profiles", font=("Segoe UI", 14, "bold")).pack(side="left")

        ttk.Button(hdr, text="Create New Baseline", command=self.create_baseline).pack(side="right", padx=5)

        # Notebook tabs: Tab 1 = Baselines, Tab 2 = Trusted Networks (Evil Twin Protection)
        self.tabs = ttk.Notebook(self)
        self.tabs.grid(row=1, column=0, sticky="nsew")

        # -------------------------------------------------------------
        # TAB 1: ENVIRONMENT BASELINES
        # -------------------------------------------------------------
        base_tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(base_tab, text=" Environment Baselines ")
        base_tab.columnconfigure(0, weight=1)
        base_tab.rowconfigure(0, weight=1)

        split = ttk.PanedWindow(base_tab, orient="horizontal")
        split.grid(row=0, column=0, sticky="nsew")

        # Left: Baseline List
        left_frame = ttk.LabelFrame(split, text=" Saved Baselines ", padding=10)
        split.add(left_frame, weight=1)

        self.base_tree = ttk.Treeview(left_frame, columns=("id", "name", "created", "count", "active"), show="headings", selectmode="browse")
        self.base_tree.heading("id", text="ID")
        self.base_tree.heading("name", text="Baseline Name")
        self.base_tree.heading("created", text="Created At")
        self.base_tree.heading("count", text="APs")
        self.base_tree.heading("active", text="Status")

        self.base_tree.column("id", width=40, anchor="center")
        self.base_tree.column("name", width=150)
        self.base_tree.column("created", width=130)
        self.base_tree.column("count", width=45, anchor="center")
        self.base_tree.column("active", width=75, anchor="center")

        self.base_tree.pack(fill="both", expand=True)
        self.base_tree.bind("<<TreeviewSelect>>", self.on_select_baseline)

        btn_bar = ttk.Frame(left_frame)
        btn_bar.pack(fill="x", pady=(10, 0))

        ttk.Button(btn_bar, text="Set Active", command=self.set_active_baseline).pack(side="left", padx=2)
        ttk.Button(btn_bar, text="Delete", command=self.delete_baseline).pack(side="left", padx=2)

        # Right: Baseline Items Detail
        right_frame = ttk.LabelFrame(split, text=" Baseline Profile Details ", padding=10)
        split.add(right_frame, weight=2)

        self.items_tree = ttk.Treeview(right_frame, columns=("ssid", "bssid", "security", "ch", "band", "avg_sig", "vendor"), show="headings", selectmode="browse")
        self.items_tree.heading("ssid", text="SSID")
        self.items_tree.heading("bssid", text="BSSID")
        self.items_tree.heading("security", text="Security")
        self.items_tree.heading("ch", text="Ch")
        self.items_tree.heading("band", text="Band")
        self.items_tree.heading("avg_sig", text="Avg Sig")
        self.items_tree.heading("vendor", text="Vendor")

        self.items_tree.column("ssid", width=130)
        self.items_tree.column("bssid", width=125)
        self.items_tree.column("security", width=80)
        self.items_tree.column("ch", width=35, anchor="center")
        self.items_tree.column("band", width=65)
        self.items_tree.column("avg_sig", width=60, anchor="center")
        self.items_tree.column("vendor", width=110)

        self.items_tree.pack(fill="both", expand=True)

        items_btn_bar = ttk.Frame(right_frame)
        items_btn_bar.pack(fill="x", pady=(8, 0))

        # "Mark as trusted" button on the Baseline page
        mark_btn = ttk.Button(items_btn_bar, text="⭐ Mark Selected as Trusted", command=self.mark_baseline_item_as_trusted)
        mark_btn.pack(side="left", padx=4)

        ttk.Label(items_btn_bar, text="Selecting an AP and marking it as trusted enables Evil Twin defense.", font=("Segoe UI", 8, "italic"), foreground="#666666").pack(side="left", padx=10)

        # -------------------------------------------------------------
        # TAB 2: TRUSTED NETWORKS (Feature 1: Evil Twin / Rogue AP Detection)
        # -------------------------------------------------------------
        trusted_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(trusted_tab, text=" ⭐ Trusted Networks (Evil Twin Baseline) ")
        trusted_tab.columnconfigure(0, weight=1)
        trusted_tab.rowconfigure(1, weight=1)

        t_ctrl = ttk.Frame(trusted_tab)
        t_ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(t_ctrl, text="Trusted Access Point Allowlist", font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Label(t_ctrl, text="(Scans flag unknown BSSIDs or security downgrades claiming these SSIDs)", font=("Segoe UI", 8, "italic"), foreground="#555555").pack(side="left", padx=10)

        ttk.Button(t_ctrl, text="Remove from Trusted", command=self.remove_selected_trusted).pack(side="right", padx=4)
        ttk.Button(t_ctrl, text="Add Trusted Manually", command=self.add_trusted_manually).pack(side="right", padx=4)
        ttk.Button(t_ctrl, text="Refresh", command=self.refresh_trusted_networks).pack(side="right", padx=4)

        t_tree_frame = ttk.Frame(trusted_tab)
        t_tree_frame.grid(row=1, column=0, sticky="nsew")
        t_tree_frame.rowconfigure(0, weight=1)
        t_tree_frame.columnconfigure(0, weight=1)

        columns = ("id", "ssid", "bssid", "vendor", "security", "channel", "added_at")
        self.trusted_tree = ttk.Treeview(t_tree_frame, columns=columns, show="headings", selectmode="browse")

        self.trusted_tree.heading("id", text="ID")
        self.trusted_tree.heading("ssid", text="Trusted SSID")
        self.trusted_tree.heading("bssid", text="Known BSSID")
        self.trusted_tree.heading("vendor", text="Hardware Vendor")
        self.trusted_tree.heading("security", text="Security")
        self.trusted_tree.heading("channel", text="Channel")
        self.trusted_tree.heading("added_at", text="Added Date")

        self.trusted_tree.column("id", width=45, anchor="center")
        self.trusted_tree.column("ssid", width=160)
        self.trusted_tree.column("bssid", width=140)
        self.trusted_tree.column("vendor", width=150)
        self.trusted_tree.column("security", width=100)
        self.trusted_tree.column("channel", width=60, anchor="center")
        self.trusted_tree.column("added_at", width=140)

        sb = ttk.Scrollbar(t_tree_frame, orient="vertical", command=self.trusted_tree.yview)
        self.trusted_tree.configure(yscrollcommand=sb.set)

        self.trusted_tree.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")

    # -------------------------------------------------------------
    # BASELINE LOGIC
    # -------------------------------------------------------------

    def refresh_baselines(self):
        for item in self.base_tree.get_children():
            self.base_tree.delete(item)

        baselines = self.db.repos.get_all_baselines()
        for b in baselines:
            status = "ACTIVE" if b.get("is_active") == 1 else "Inactive"
            self.base_tree.insert("", "end", values=(
                b["id"],
                b["name"],
                b["created_at"],
                b.get("item_count", 0),
                status
            ))

    def on_select_baseline(self, event=None):
        selected = self.base_tree.selection()
        if not selected:
            return

        item_vals = self.base_tree.item(selected[0], "values")
        baseline_id = int(item_vals[0])

        for item in self.items_tree.get_children():
            self.items_tree.delete(item)

        all_baselines = self.db.repos.get_all_baselines()
        target = next((b for b in all_baselines if b["id"] == baseline_id), None)
        if not target:
            return

        # Fetch baseline items directly
        try:
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM baseline_items WHERE baseline_id = ?;", (baseline_id,))
                items = [dict(r) for r in cursor.fetchall()]
                for it in items:
                    self.items_tree.insert("", "end", values=(
                        it.get("ssid"),
                        it.get("bssid"),
                        it.get("security"),
                        it.get("channel"),
                        it.get("band"),
                        f"{it.get('avg_signal', 0):.1f}%",
                        it.get("vendor", "Unknown Vendor")
                    ))
        except Exception as err:
            messagebox.showerror("Error", f"Failed to load baseline items: {err}")

    def create_baseline(self):
        name = simpledialog.askstring("Create Baseline", "Enter name for new baseline profile:")
        if not name:
            return

        desc = simpledialog.askstring("Create Baseline", "Enter description (optional):") or "Manual baseline snapshot."

        b_id = self.baseline_mgr.create_baseline_from_current_state(name, desc)
        if b_id:
            messagebox.showinfo("Success", f"Baseline '{name}' successfully established!")
            self.refresh_baselines()
        else:
            messagebox.showwarning("Warning", "Could not create baseline: No active networks found in database.")

    def set_active_baseline(self):
        selected = self.base_tree.selection()
        if not selected:
            return

        baseline_id = int(self.base_tree.item(selected[0], "values")[0])
        self.db.repos.set_active_baseline(baseline_id)
        self.refresh_baselines()
        messagebox.showinfo("Success", "Active baseline updated.")

    def delete_baseline(self):
        selected = self.base_tree.selection()
        if not selected:
            return

        baseline_id = int(self.base_tree.item(selected[0], "values")[0])
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this baseline profile?"):
            self.db.repos.delete_baseline(baseline_id)
            self.refresh_baselines()

    # -------------------------------------------------------------
    # TRUSTED NETWORKS LOGIC (Feature 1)
    # -------------------------------------------------------------

    def mark_baseline_item_as_trusted(self):
        selected = self.items_tree.selection()
        if not selected:
            messagebox.showinfo("Mark as Trusted", "Please select an access point from the Baseline Profile Details table first.")
            return

        vals = self.items_tree.item(selected[0], "values")
        ssid, bssid, security, ch_val, band, sig, vendor = vals

        ch = int(ch_val) if (ch_val and str(ch_val).isdigit()) else None

        res = self.db.repos.add_trusted_network(
            ssid=ssid,
            bssid=bssid,
            vendor=vendor,
            security=security,
            channel=ch,
            notes="Added from Baseline profile"
        )

        if res != -1:
            messagebox.showinfo("Success", f"Network '{ssid}' ({bssid}) marked as TRUSTED!\n\nThe scanner will alert if an unknown BSSID or downgraded security impersonates this SSID.")
            self.refresh_trusted_networks()
        else:
            messagebox.showerror("Error", "Failed to add network to trusted list.")

    def refresh_trusted_networks(self):
        for item in self.trusted_tree.get_children():
            self.trusted_tree.delete(item)

        trusted = self.db.repos.get_trusted_networks()
        for t in trusted:
            self.trusted_tree.insert("", "end", values=(
                t["id"],
                t["ssid"],
                t["bssid"],
                t.get("vendor", "Unknown Vendor"),
                t.get("security", "WPA2"),
                t.get("channel") if t.get("channel") is not None else "N/A",
                t.get("added_at", "N/A")
            ))

    def remove_selected_trusted(self):
        selected = self.trusted_tree.selection()
        if not selected:
            messagebox.showinfo("Remove Trusted", "Please select a trusted network to remove.")
            return

        vals = self.trusted_tree.item(selected[0], "values")
        bssid = vals[2]
        ssid = vals[1]

        if messagebox.askyesno("Confirm Untrust", f"Remove '{ssid}' ({bssid}) from trusted networks?"):
            self.db.repos.remove_trusted_network(bssid)
            self.refresh_trusted_networks()

    def add_trusted_manually(self):
        ssid = simpledialog.askstring("Add Trusted Network", "Enter Trusted SSID (e.g. HomeWiFi):")
        if not ssid:
            return

        bssid = simpledialog.askstring("Add Trusted Network", "Enter Known BSSID MAC (e.g. AA:BB:CC:11:22:33):")
        if not bssid:
            return

        security = simpledialog.askstring("Add Trusted Network", "Enter Security Type (e.g. WPA2 or WPA3):") or "WPA2"
        channel_str = simpledialog.askstring("Add Trusted Network", "Enter Channel (optional):") or ""
        ch = int(channel_str) if channel_str.isdigit() else None

        res = self.db.repos.add_trusted_network(
            ssid=ssid.strip(),
            bssid=bssid.strip().upper(),
            security=security.strip().upper(),
            channel=ch,
            notes="Manually defined trusted AP"
        )
        if res != -1:
            messagebox.showinfo("Success", f"Trusted network '{ssid}' established successfully!")
            self.refresh_trusted_networks()
        else:
            messagebox.showerror("Error", "Failed to save trusted network.")
