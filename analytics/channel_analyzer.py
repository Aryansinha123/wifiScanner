import logging
from typing import List, Dict, Any
from models.network import Network
from utils.parser import get_frequency

logger = logging.getLogger(__name__)


class ChannelAnalyzer:
    """
    Analyzes Wi-Fi channel utilization, channel density, and frequency band distribution.
    """

    @staticmethod
    def analyze_channels(networks: List[Network]) -> Dict[str, Any]:
        """
        Calculates channel metrics grouped by frequency band.
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

        # Basic channel recommendation for 2.4 GHz non-overlapping channels (1, 6, 11)
        rec_24 = None
        if ch_24_summary:
            standard_24 = {1: 0, 6: 0, 11: 0}
            for item in ch_24_summary:
                if item["channel"] in standard_24:
                    standard_24[item["channel"]] = item["network_count"]
            rec_24 = min(standard_24, key=standard_24.get)

        return {
            "total_networks_with_channel": total_24 + total_5,
            "count_24ghz": total_24,
            "count_5ghz": total_5,
            "channels_24ghz": ch_24_summary,
            "channels_5ghz": ch_5_summary,
            "recommended_24ghz_channel": rec_24,
            "disclaimer": "Metrics represent passive scan-based network visibility and density, not direct RF spectrum interference."
        }
