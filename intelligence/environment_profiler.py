import logging
from typing import Dict, Any, List
from models.network import Network
from intelligence.vendor_analyzer import lookup_vendor

logger = logging.getLogger(__name__)


class EnvironmentProfiler:
    """
    Generates high-level Wireless Environment Intelligence Profiles.
    """

    @staticmethod
    def profile_environment(networks: List[Network]) -> Dict[str, Any]:
        """
        Calculates environment-wide summary statistics from a list of Networks.
        """
        total_bssids = len(networks)
        valid_ssids = set(n.ssid for n in networks if n.ssid and n.ssid != "<Hidden Network>")

        count_24 = sum(1 for n in networks if "2.4" in n.band)
        count_5 = sum(1 for n in networks if "5" in n.band)
        count_unknown_band = total_bssids - (count_24 + count_5)

        sec_counts = {
            "OPEN": 0,
            "WEP": 0,
            "WPA": 0,
            "WPA2": 0,
            "WPA3": 0,
            "UNKNOWN": 0
        }

        for n in networks:
            sec = n.security.upper()
            if "WPA3" in sec:
                sec_counts["WPA3"] += 1
            elif "WPA2" in sec:
                sec_counts["WPA2"] += 1
            elif "WPA" in sec:
                sec_counts["WPA"] += 1
            elif "WEP" in sec:
                sec_counts["WEP"] += 1
            elif "OPEN" in sec:
                sec_counts["OPEN"] += 1
            else:
                sec_counts["UNKNOWN"] += 1

        signals = [n.signal_percent for n in networks]
        avg_sig = sum(signals) / total_bssids if total_bssids > 0 else 0.0

        strongest = max(networks, key=lambda n: n.signal_percent) if networks else None
        weakest = min(networks, key=lambda n: n.signal_percent) if networks else None

        channels = {}
        for n in networks:
            if n.channel is not None:
                channels[n.channel] = channels.get(n.channel, 0) + 1

        vendors = {}
        for n in networks:
            v = lookup_vendor(n.bssid)
            vendors[v] = vendors.get(v, 0) + 1

        return {
            "total_observed_bssids": total_bssids,
            "unique_ssids": len(valid_ssids),
            "count_24ghz": count_24,
            "count_5ghz": count_5,
            "count_unknown_band": count_unknown_band,
            "security_distribution": sec_counts,
            "average_signal": round(avg_sig, 1),
            "strongest_network": {
                "ssid": strongest.ssid,
                "bssid": strongest.bssid,
                "signal": strongest.signal_percent,
                "channel": strongest.channel
            } if strongest else None,
            "weakest_network": {
                "ssid": weakest.ssid,
                "bssid": weakest.bssid,
                "signal": weakest.signal_percent,
                "channel": weakest.channel
            } if weakest else None,
            "channel_distribution": channels,
            "vendor_distribution": vendors
        }
