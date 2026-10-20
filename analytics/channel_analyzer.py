import logging
from typing import List, Dict, Any, Optional
from models.network import Network
from utils.parser import get_frequency

logger = logging.getLogger(__name__)


class ChannelAnalyzer:
    """
    Channel Recommendation & Spectrum Congestion Engine.
    Analyzes Wi-Fi channel utilization, co-channel & adjacent-channel interference,
    and calculates optimal router channel recommendations for 2.4 GHz and 5 GHz.
    """

    STANDARD_24GHZ_CHANNELS = [1, 6, 11]
    STANDARD_5GHZ_CHANNELS = [36, 40, 44, 48, 149, 153, 157, 161]

    @classmethod
    def get_channel_recommendations(cls, networks: List[Network]) -> Dict[str, Any]:
        """
        Calculates optimal channel recommendations based on overlapping spectrum
        interference and signal-weighted congestion scoring.
        """
        # Separate networks by band
        nets_24: List[Network] = []
        nets_5: List[Network] = []

        for net in networks:
            if net.channel is None:
                continue
            band = get_frequency(net.channel, net.band)
            if band == "2.4 GHz":
                nets_24.append(net)
            elif band == "5 GHz":
                nets_5.append(net)

        # ------------------------------------------------------------------
        # 1. 2.4 GHz Scoring (Non-overlapping channels 1, 6, 11 with neighbor overlap)
        # ------------------------------------------------------------------
        # Channel 1 overlap range:  1..3
        # Channel 6 overlap range:  4..8
        # Channel 11 overlap range: 9..13
        overlap_map = {
            1: [1, 2, 3],
            6: [4, 5, 6, 7, 8],
            11: [9, 10, 11, 12, 13]
        }

        scores_24: Dict[int, Dict[str, Any]] = {}
        for candidate in cls.STANDARD_24GHZ_CHANNELS:
            overlapping_ch = overlap_map[candidate]
            co_channel_nets = [n for n in nets_24 if n.channel == candidate]
            adjacent_nets = [n for n in nets_24 if n.channel in overlapping_ch and n.channel != candidate]

            co_sig_sum = sum(n.signal_percent for n in co_channel_nets)
            adj_sig_sum = sum(n.signal_percent for n in adjacent_nets)

            # Adjacent channel interference weighted at 0.7 vs co-channel at 1.0
            congestion_score = round(co_sig_sum + 0.7 * adj_sig_sum, 1)
            total_overlapping_cnt = len(co_channel_nets) + len(adjacent_nets)

            if total_overlapping_cnt >= 8 or congestion_score >= 400:
                crowd_label = "Very Crowded"
            elif total_overlapping_cnt >= 4 or congestion_score >= 180:
                crowd_label = "Crowded"
            elif total_overlapping_cnt >= 1:
                crowd_label = "Moderate"
            else:
                crowd_label = "Clear"

            scores_24[candidate] = {
                "channel": candidate,
                "co_channel_count": len(co_channel_nets),
                "adjacent_count": len(adjacent_nets),
                "total_overlapping_count": total_overlapping_cnt,
                "congestion_score": congestion_score,
                "crowd_label": crowd_label,
                "co_signals": [n.signal_percent for n in co_channel_nets]
            }

        # Lowest congestion score wins
        rec_24 = min(cls.STANDARD_24GHZ_CHANNELS, key=lambda c: (scores_24[c]["congestion_score"], scores_24[c]["total_overlapping_count"]))

        # Build readable 2.4 GHz explanation
        parts_24 = []
        for ch in cls.STANDARD_24GHZ_CHANNELS:
            sc = scores_24[ch]
            parts_24.append(f"Channel {ch} has {sc['co_channel_count']} direct network(s) ({sc['crowd_label'].lower()}, score {int(sc['congestion_score'])})")
        explanation_24 = ". ".join(parts_24) + f". Recommended: Channel {rec_24}."

        # ------------------------------------------------------------------
        # 2. 5 GHz Scoring (Discrete non-overlapping channels)
        # ------------------------------------------------------------------
        all_5_channels_seen = set(n.channel for n in nets_5 if n.channel is not None)
        candidate_5_channels = sorted(list(set(cls.STANDARD_5GHZ_CHANNELS).union(all_5_channels_seen)))

        scores_5: Dict[int, Dict[str, Any]] = {}
        for ch in candidate_5_channels:
            ch_nets = [n for n in nets_5 if n.channel == ch]
            sig_sum = sum(n.signal_percent for n in ch_nets)
            scores_5[ch] = {
                "channel": ch,
                "count": len(ch_nets),
                "congestion_score": round(float(sig_sum), 1),
                "crowd_label": "Crowded" if len(ch_nets) >= 4 else ("Moderate" if len(ch_nets) >= 1 else "Clear")
            }

        rec_5 = min(candidate_5_channels, key=lambda c: (scores_5[c]["congestion_score"], scores_5[c]["count"]))
        sc_rec_5 = scores_5[rec_5]
        explanation_5 = f"Channel {rec_5} has {sc_rec_5['count']} network(s) (congestion score {int(sc_rec_5['congestion_score'])}). Recommended: Channel {rec_5}."

        return {
            "band_24ghz": {
                "recommended_channel": rec_24,
                "scores": scores_24,
                "explanation": explanation_24
            },
            "band_5ghz": {
                "recommended_channel": rec_5,
                "scores": scores_5,
                "explanation": explanation_5
            },
            "overall_summary": f"Optimal Channels -> 2.4 GHz: Channel {rec_24} | 5 GHz: Channel {rec_5}"
        }

    @classmethod
    def analyze_channels(cls, networks: List[Network]) -> Dict[str, Any]:
        """
        Calculates channel metrics grouped by frequency band, including
        complete channel recommendation details.
        """
        band_24: Dict[int, List[Network]] = {}
        band_5: Dict[int, List[Network]] = {}
        unknown_ch: List[Network] = []

        for net in networks:
            ch = net.channel
            if ch is None:
                unknown_ch.append(net)
                continue

            band = get_frequency(ch, net.band)
            if band == "2.4 GHz":
                band_24.setdefault(ch, []).append(net)
            elif band == "5 GHz":
                band_5.setdefault(ch, []).append(net)
            else:
                band_24.setdefault(ch, []).append(net)

        def build_channel_summary(ch_map: Dict[int, List[Network]]) -> List[Dict[str, Any]]:
            summary = []
            for ch in sorted(ch_map.keys()):
                nets = ch_map[ch]
                net_cnt = len(nets)
                unique_ssids = len(set(n.ssid for n in nets if n.ssid and n.ssid != "<Hidden Network>"))
                signals = [n.signal_percent for n in nets]
                avg_sig = sum(signals) / net_cnt if net_cnt > 0 else 0.0

                strongest = max(nets, key=lambda n: n.signal_percent)
                weakest = min(nets, key=lambda n: n.signal_percent)

                density_label = "Low"
                if net_cnt >= 8:
                    density_label = "High"
                elif net_cnt >= 4:
                    density_label = "Medium"

                summary.append({
                    "channel": ch,
                    "network_count": net_cnt,
                    "unique_ssid_count": unique_ssids,
                    "avg_signal": round(avg_sig, 1),
                    "density_label": density_label,
                    "strongest_ssid": strongest.ssid,
                    "strongest_signal": strongest.signal_percent,
                    "weakest_ssid": weakest.ssid,
                    "weakest_signal": weakest.signal_percent,
                })
            return summary

        ch_24_summary = build_channel_summary(band_24)
        ch_5_summary = build_channel_summary(band_5)

        total_24 = sum(item["network_count"] for item in ch_24_summary)
        total_5 = sum(item["network_count"] for item in ch_5_summary)

        # Full Channel Recommendation Engine
        recommendations = cls.get_channel_recommendations(networks)
        rec_24 = recommendations["band_24ghz"]["recommended_channel"]
        rec_5 = recommendations["band_5ghz"]["recommended_channel"]

        return {
            "total_networks_with_channel": total_24 + total_5,
            "count_24ghz": total_24,
            "count_5ghz": total_5,
            "channels_24ghz": ch_24_summary,
            "channels_5ghz": ch_5_summary,
            "recommended_24ghz_channel": rec_24,
            "recommended_5ghz_channel": rec_5,
            "recommendations": recommendations,
            "disclaimer": "Metrics represent passive scan-based network visibility and density, not direct RF spectrum interference."
        }
