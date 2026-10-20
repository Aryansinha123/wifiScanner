import tkinter as tk
from tkinter import ttk
from typing import List, Dict, Any
from models.network import Network
from analytics.channel_analyzer import ChannelAnalyzer
from analytics.signal_analyzer import SignalAnalyzer


class AnalyticsWindow(ttk.Frame):
    """
    Channel Recommendation & Signal Analytics View.
    Visualizes spectrum utilization, interference congestion scores, and
    calculates optimal channel recommendations for 2.4 GHz and 5 GHz.
    """

    def __init__(self, parent: tk.Widget):
        super().__init__(parent, padding=15)
        self.networks: List[Network] = []

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self.create_widgets()

    def create_widgets(self):
        # Header
        hdr = ttk.Frame(self)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        ttk.Label(hdr, text="Wireless Spectrum Analytics & Channel Recommendation Engine", font=("Segoe UI", 14, "bold")).pack(side="left")

        # Split Container
        split = ttk.PanedWindow(self, orient="horizontal")
        split.grid(row=1, column=0, sticky="nsew")

        # =========================================================
        # LEFT: CHANNEL RECOMMENDATION ENGINE (Feature 4)
        # =========================================================
        rec_frame = ttk.LabelFrame(split, text=" ⭐ Channel Recommendation Engine (Feature 4) ", padding=12)
        split.add(rec_frame, weight=1)

        # Highlight Badges Container
        badge_box = ttk.Frame(rec_frame)
        badge_box.pack(fill="x", pady=(0, 10))
        badge_box.columnconfigure(0, weight=1)
        badge_box.columnconfigure(1, weight=1)

        card_24 = ttk.LabelFrame(badge_box, text=" Recommended 2.4 GHz ", padding=8)
        card_24.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        self.rec_24_lbl = ttk.Label(card_24, text="Channel --", font=("Segoe UI", 16, "bold"), foreground="#27AE60")
        self.rec_24_lbl.pack(anchor="center")
        self.rec_24_sub = ttk.Label(card_24, text="Perform scan to analyze", font=("Segoe UI", 8, "italic"), foreground="#555555")
        self.rec_24_sub.pack(anchor="center")

        card_5 = ttk.LabelFrame(badge_box, text=" Recommended 5 GHz ", padding=8)
        card_5.grid(row=0, column=1, sticky="nsew", padx=(5, 0))
        self.rec_5_lbl = ttk.Label(card_5, text="Channel --", font=("Segoe UI", 16, "bold"), foreground="#2980B9")
        self.rec_5_lbl.pack(anchor="center")
        self.rec_5_sub = ttk.Label(card_5, text="Perform scan to analyze", font=("Segoe UI", 8, "italic"), foreground="#555555")
        self.rec_5_sub.pack(anchor="center")

        # Congestion Bar Chart Canvas (Channels 1, 6, 11)
        ttk.Label(rec_frame, text="2.4 GHz Congestion Comparison (Channels 1, 6, 11):", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(5, 2))
        self.rec_canvas = tk.Canvas(rec_frame, height=130, bg="#0f172a", highlightthickness=0)
        self.rec_canvas.pack(fill="x", pady=(0, 10))

        # Recommendation Text Details
        self.rec_details_var = tk.StringVar(value="Perform a wireless scan to generate spectrum congestion scoring and recommendations.")
        ttk.Label(rec_frame, textvariable=self.rec_details_var, font=("Segoe UI", 9), wraplength=420, justify="left").pack(anchor="w", pady=(0, 5))

        # Channel Density Table
        ttk.Label(rec_frame, text="All Observed Channels Density:", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(8, 2))
        self.ch_tree = ttk.Treeview(rec_frame, columns=("channel", "nets", "ssids", "avg_sig", "density"), show="headings", height=6)
        self.ch_tree.heading("channel", text="Channel")
        self.ch_tree.heading("nets", text="Networks")
        self.ch_tree.heading("ssids", text="Unique SSIDs")
        self.ch_tree.heading("avg_sig", text="Avg Signal")
        self.ch_tree.heading("density", text="Density Level")

        self.ch_tree.column("channel", width=70, anchor="center")
        self.ch_tree.column("nets", width=75, anchor="center")
        self.ch_tree.column("ssids", width=85, anchor="center")
        self.ch_tree.column("avg_sig", width=80, anchor="center")
        self.ch_tree.column("density", width=95, anchor="center")

        self.ch_tree.pack(fill="both", expand=True)

        # =========================================================
        # RIGHT: FULL SPECTRUM DISTRIBUTION & SIGNAL STATS
        # =========================================================
        right_frame = ttk.LabelFrame(split, text=" Full Spectrum Density & Signal Distribution ", padding=12)
        split.add(right_frame, weight=1)

        # Canvas for All Channel Visual Bars
        self.ch_canvas = tk.Canvas(right_frame, height=160, bg="#1e293b", highlightthickness=0)
        self.ch_canvas.pack(fill="x", pady=(0, 10))

        # Signal Statistics Summary Box
        sig_box = ttk.LabelFrame(right_frame, text=" Signal & RF Environment Metrics ", padding=10)
        sig_box.pack(fill="both", expand=True)

        self.sig_summary_var = tk.StringVar(value="Perform a scan to populate signal metrics.")
        ttk.Label(sig_box, textvariable=self.sig_summary_var, font=("Segoe UI", 9), wraplength=400, justify="left").pack(anchor="w", pady=5)

    def update_networks(self, networks: List[Network]):
        self.networks = networks
        self.refresh_analytics()

    def refresh_analytics(self):
        for item in self.ch_tree.get_children():
            self.ch_tree.delete(item)

        if not self.networks:
            return

        res = ChannelAnalyzer.analyze_channels(self.networks)
        recs = res.get("recommendations", {})
        band_24_info = recs.get("band_24ghz", {})
        band_5_info = recs.get("band_5ghz", {})

        # 1. Update Recommendations Badges
        rec_ch_24 = band_24_info.get("recommended_channel")
        rec_ch_5 = band_5_info.get("recommended_channel")

        if rec_ch_24:
            sc_24 = band_24_info.get("scores", {}).get(rec_ch_24, {})
            self.rec_24_lbl.config(text=f"Channel {rec_ch_24}")
            self.rec_24_sub.config(text=f"Congestion Score: {int(sc_24.get('congestion_score', 0))} ({sc_24.get('crowd_label', 'Clear')})")

        if rec_ch_5:
            sc_5 = band_5_info.get("scores", {}).get(rec_ch_5, {})
            self.rec_5_lbl.config(text=f"Channel {rec_ch_5}")
            self.rec_5_sub.config(text=f"Congestion Score: {int(sc_5.get('congestion_score', 0))} ({sc_5.get('crowd_label', 'Clear')})")

        # 2. Render 2.4 GHz Congestion Bar Chart (Channels 1, 6, 11)
        self.rec_canvas.delete("all")
        scores_24 = band_24_info.get("scores", {})
        if scores_24:
            w = self.rec_canvas.winfo_width() or 400
            h = 130
            channels = [1, 6, 11]
            max_score = max(scores_24[c]["congestion_score"] for c in channels) or 1
            col_width = (w - 60) // 3

            for idx, ch in enumerate(channels):
                sc = scores_24[ch]
                score_val = sc["congestion_score"]
                bar_h = int((score_val / max_score) * 75) if max_score > 0 else 5
                x0 = 30 + idx * col_width + 15
                x1 = x0 + col_width - 30
                y1 = h - 25
                y0 = y1 - bar_h

                is_rec = (ch == rec_ch_24)
                color = "#22c55e" if is_rec else ("#ef4444" if sc["crowd_label"] == "Very Crowded" else "#f59e0b")

                self.rec_canvas.create_rectangle(x0, y0, x1, y1, fill=color, outline="")
                label_txt = f"Ch {ch} ★" if is_rec else f"Ch {ch}"
                self.rec_canvas.create_text((x0 + x1) // 2, h - 12, text=label_txt, fill="#f8fafc", font=("Segoe UI", 8, "bold" if is_rec else "normal"))
                self.rec_canvas.create_text((x0 + x1) // 2, y0 - 8, text=f"{int(score_val)} pts", fill="#94a3b8", font=("Segoe UI", 7))

        # 3. Update Explanation Text
        exp_24 = band_24_info.get("explanation", "")
        exp_5 = band_5_info.get("explanation", "")
        self.rec_details_var.set(f"2.4 GHz: {exp_24}\n\n5 GHz: {exp_5}")

        # 4. Populate Channel Density Table
        all_ch = res["channels_24ghz"] + res["channels_5ghz"]
        for item in all_ch:
            self.ch_tree.insert("", "end", values=(
                f"Ch {item['channel']}",
                item["network_count"],
                item["unique_ssid_count"],
                f"{item['avg_signal']}%",
                item["density_label"]
            ))

        # 5. Render Full Spectrum Visual Bars on Canvas
        self.ch_canvas.delete("all")
        if all_ch:
            w = self.ch_canvas.winfo_width() or 400
            h = 160
            max_cnt = max(item["network_count"] for item in all_ch) or 1
            bar_w = max(15, (w - 40) // max(len(all_ch), 1))

            self.ch_canvas.create_text(20, 15, text="All Active Spectrum Channels (Networks per Channel)", fill="#94a3b8", anchor="w", font=("Segoe UI", 8))

            for idx, item in enumerate(all_ch[:16]):
                x0 = 20 + idx * (bar_w + 5)
                bar_h = int((item["network_count"] / max_cnt) * 90)
                y0 = h - 25 - bar_h
                y1 = h - 25

                color = "#f87171" if item["density_label"] == "High" else ("#fbbf24" if item["density_label"] == "Medium" else "#38bdf8")
                self.ch_canvas.create_rectangle(x0, y0, x0 + bar_w, y1, fill=color, outline="")
                self.ch_canvas.create_text(x0 + bar_w // 2, h - 12, text=str(item["channel"]), fill="#f8fafc", font=("Segoe UI", 8))
                self.ch_canvas.create_text(x0 + bar_w // 2, y0 - 8, text=str(item["network_count"]), fill="#f8fafc", font=("Segoe UI", 7))

        # 6. Update Signal Summary
        signals = [n.signal_percent for n in self.networks]
        sig_stats = SignalAnalyzer.calculate_signal_stats(signals)

        self.sig_summary_var.set(
            f"Observed Networks: {len(self.networks)}\n"
            f"2.4 GHz Networks: {res['count_24ghz']}\n"
            f"5 GHz Networks: {res['count_5ghz']}\n"
            f"Average Signal: {sig_stats['avg']}%\n"
            f"Strongest Signal: {sig_stats['max']}%\n"
            f"Weakest Signal: {sig_stats['min']}%\n"
            f"Signal Std Dev: {sig_stats['std_dev']}\n\n"
            f"Spectrum Summary:\n"
            f"• 2.4 GHz is susceptible to 20 MHz overlapping neighbor interference.\n"
            f"• 5 GHz offers wider non-overlapping channel capacity with lower density."
        )
