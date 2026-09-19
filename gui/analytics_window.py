import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any
from models.network import Network
from analytics.channel_analyzer import ChannelAnalyzer
from analytics.signal_analyzer import SignalAnalyzer


class AnalyticsWindow(ttk.Frame):
    """
    Channel and Signal Analytics View.
    Visualizes channel density, signal distributions, and frequency metrics.
    """

    def __init__(self, parent: tk.Widget):
        super().__init__(parent, padding=15)
        self.networks: List[Network] = []

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self.create_widgets()

    def create_widgets(self):
        hdr = ttk.Frame(self)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 15))

        ttk.Label(hdr, text="Wireless Channel & Signal Analytics", font=("Segoe UI", 14, "bold")).pack(side="left")

        # Split Container
        split = ttk.PanedWindow(self, orient="horizontal")
        split.grid(row=1, column=0, sticky="nsew")

        # Left: Channel Density Table & Visual Canvas
        ch_frame = ttk.LabelFrame(split, text=" Channel Density Analysis ", padding=10)
        split.add(ch_frame, weight=1)

        self.ch_tree = ttk.Treeview(ch_frame, columns=("channel", "nets", "ssids", "avg_sig", "density"), show="headings")
        self.ch_tree.heading("channel", text="Channel")
        self.ch_tree.heading("nets", text="Networks")
        self.ch_tree.heading("ssids", text="Unique SSIDs")
        self.ch_tree.heading("avg_sig", text="Avg Signal")
        self.ch_tree.heading("density", text="Density Level")

        self.ch_tree.column("channel", width=70, anchor="center")
        self.ch_tree.column("nets", width=80, anchor="center")
        self.ch_tree.column("ssids", width=90, anchor="center")
        self.ch_tree.column("avg_sig", width=90, anchor="center")
        self.ch_tree.column("density", width=100, anchor="center")

        self.ch_tree.pack(fill="both", expand=True, pady=(0, 10))

        # Canvas for Channel Visual Bars
        self.ch_canvas = tk.Canvas(ch_frame, height=160, bg="#1e293b", highlightthickness=0)
        self.ch_canvas.pack(fill="x")

        # Right: Signal Metrics & Summary
        sig_frame = ttk.LabelFrame(split, text=" Signal & Frequency Distribution ", padding=10)
        split.add(sig_frame, weight=1)

        self.sig_summary_var = tk.StringVar(value="Perform a scan to populate signal metrics.")
        ttk.Label(sig_frame, textvariable=self.sig_summary_var, font=("Segoe UI", 9), wraplength=400).pack(anchor="w", pady=5)

        self.rec_var = tk.StringVar(value="")
        ttk.Label(sig_frame, textvariable=self.rec_var, font=("Segoe UI", 9, "italic"), foreground="#2980B9", wraplength=400).pack(anchor="w", pady=10)

    def update_networks(self, networks: List[Network]):
        self.networks = networks
        self.refresh_analytics()

    def refresh_analytics(self):
        for item in self.ch_tree.get_children():
            self.ch_tree.delete(item)

        if not self.networks:
            return

        res = ChannelAnalyzer.analyze_channels(self.networks)
        all_ch = res["channels_24ghz"] + res["channels_5ghz"]

        for item in all_ch:
            self.ch_tree.insert("", "end", values=(
                f"Ch {item['channel']}",
                item["network_count"],
                item["unique_ssid_count"],
                f"{item['avg_signal']}%",
                item["density_label"]
            ))

        # Render Visual Bars on Canvas
        self.ch_canvas.delete("all")
        if all_ch:
            w = self.ch_canvas.winfo_width() or 400
            h = 160
            max_cnt = max(item["network_count"] for item in all_ch) or 1
            bar_w = max(15, (w - 40) // max(len(all_ch), 1))

            self.ch_canvas.create_text(20, 15, text="Passive Channel Density (Networks per Channel)", fill="#94a3b8", anchor="w", font=("Segoe UI", 8))

            for idx, item in enumerate(all_ch[:16]):
                x0 = 20 + idx * (bar_w + 5)
                bar_h = int((item["network_count"] / max_cnt) * 90)
                y0 = h - 25 - bar_h
                y1 = h - 25

                color = "#f87171" if item["density_label"] == "High" else ("#fbbf24" if item["density_label"] == "Medium" else "#38bdf8")
                self.ch_canvas.create_rectangle(x0, y0, x0 + bar_w, y1, fill=color, outline="")
                self.ch_canvas.create_text(x0 + bar_w // 2, h - 12, text=str(item["channel"]), fill="#f8fafc", font=("Segoe UI", 8))
                self.ch_canvas.create_text(x0 + bar_w // 2, y0 - 8, text=str(item["network_count"]), fill="#f8fafc", font=("Segoe UI", 7))

        # Update Signal Summary
        signals = [n.signal_percent for n in self.networks]
        sig_stats = SignalAnalyzer.calculate_signal_stats(signals)

        self.sig_summary_var.set(
            f"Observed Networks: {len(self.networks)}\n"
            f"2.4 GHz Networks: {res['count_24ghz']}\n"
            f"5 GHz Networks: {res['count_5ghz']}\n"
            f"Average Signal: {sig_stats['avg']}%\n"
            f"Strongest Signal: {sig_stats['max']}%\n"
            f"Weakest Signal: {sig_stats['min']}%\n"
            f"Signal Std Dev: {sig_stats['std_dev']}"
        )

        rec = res.get("recommended_24ghz_channel")
        if rec:
            self.rec_var.set(f"Recommendation: In the 2.4 GHz band, Channel {rec} currently has fewer observed networks in scan data.")
        else:
            self.rec_var.set("")
