import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import List, Dict, Any
from storage.database import DatabaseManager
from monitoring.baseline_manager import BaselineManager


class BaselineWindow(ttk.Frame):
    """
    Baseline Management view for establishing and comparing environment baselines.
    """

    def __init__(self, parent: tk.Widget, db_manager: DatabaseManager):
        super().__init__(parent, padding=15)
        self.db = db_manager
        self.baseline_mgr = BaselineManager(self.db)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self.create_widgets()
        self.refresh_baselines()

    def create_widgets(self):
        # Header
        hdr = ttk.Frame(self)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 15))

        ttk.Label(hdr, text="Wireless Environment Baseline Manager", font=("Segoe UI", 14, "bold")).pack(side="left")

        ttk.Button(hdr, text="Create New Baseline", command=self.create_baseline).pack(side="right", padx=5)

        # Main Table split
        split = ttk.PanedWindow(self, orient="horizontal")
        split.grid(row=1, column=0, sticky="nsew")

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
        self.base_tree.column("name", width=160)
        self.base_tree.column("created", width=140)
        self.base_tree.column("count", width=50, anchor="center")
        self.base_tree.column("active", width=80, anchor="center")

        self.base_tree.pack(fill="both", expand=True)
        self.base_tree.bind("<<TreeviewSelect>>", self.on_select_baseline)

        btn_bar = ttk.Frame(left_frame)
        btn_bar.pack(fill="x", pady=(10, 0))

        ttk.Button(btn_bar, text="Set Active", command=self.set_active_baseline).pack(side="left", padx=2)
        ttk.Button(btn_bar, text="Delete", command=self.delete_baseline).pack(side="left", padx=2)

        # Right: Baseline Items Detail
        right_frame = ttk.LabelFrame(split, text=" Baseline Profile Details ", padding=10)
        split.add(right_frame, weight=2)

        self.items_tree = ttk.Treeview(right_frame, columns=("ssid", "bssid", "security", "ch", "band", "avg_sig"), show="headings")
        self.items_tree.heading("ssid", text="SSID")
        self.items_tree.heading("bssid", text="BSSID")
        self.items_tree.heading("security", text="Security")
        self.items_tree.heading("ch", text="Ch")
        self.items_tree.heading("band", text="Band")
        self.items_tree.heading("avg_sig", text="Avg Sig")

        self.items_tree.column("ssid", width=140)
        self.items_tree.column("bssid", width=130)
        self.items_tree.column("security", width=90)
        self.items_tree.column("ch", width=40, anchor="center")
        self.items_tree.column("band", width=70)
        self.items_tree.column("avg_sig", width=70, anchor="center")

        self.items_tree.pack(fill="both", expand=True)

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

        active_b = self.db.repos.get_active_baseline()
        if active_b and active_b["id"] == baseline_id:
            items = active_b.get("items", [])
            for it in items:
                self.items_tree.insert("", "end", values=(
                    it.get("ssid"),
                    it.get("bssid"),
                    it.get("security"),
                    it.get("channel"),
                    it.get("band"),
                    f"{it.get('avg_signal', 0):.1f}%"
                ))

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
