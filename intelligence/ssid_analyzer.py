import logging
from typing import Dict, Any, List
from storage.database import DatabaseManager
from intelligence.vendor_analyzer import lookup_vendor

logger = logging.getLogger(__name__)


class SSIDAnalyzer:
    """
    Analyzes SSID -> Multi-BSSID relationships and constructs SSID Profiles.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def get_ssid_profile(self, ssid: str) -> Dict[str, Any]:
        """
        Builds a comprehensive relationship profile for a given SSID.
        """
        all_networks = self.db.get_all_tracked_networks()
        matching_nets = [n for n in all_networks if n.get("ssid") == ssid]

        if not matching_nets:
            return {"ssid": ssid, "found": False, "message": f"No records found for SSID '{ssid}'."}

        bssids_info = []
        all_signals = []
        channels = set()
        bands = set()
        sec_types = set()
        enc_types = set()

        first_seens = []
        last_seens = []

        for net in matching_nets:
            bssid = net["bssid"]
            vendor = lookup_vendor(bssid)
            sig = net.get("last_signal")
            if sig is not None:
                all_signals.append(sig)

            ch = net.get("last_channel")
            if ch is not None:
                channels.add(ch)

            band = net.get("last_band")
            if band:
                bands.add(band)

            sec = net.get("last_security")
            if sec:
                sec_types.add(sec)

            enc = net.get("last_encryption")
            if enc:
                enc_types.add(enc)

            if net.get("first_seen"):
                first_seens.append(net["first_seen"])
            if net.get("last_seen"):
                last_seens.append(net["last_seen"])

            bssids_info.append({
                "bssid": bssid,
                "vendor": vendor,
                "signal": sig,
                "channel": ch,
                "band": band,
                "security": sec,
                "is_active": bool(net.get("is_active", 1))
            })

        avg_sig = sum(all_signals) / len(all_signals) if all_signals else 0.0
        min_sig = min(all_signals) if all_signals else 0
        max_sig = max(all_signals) if all_signals else 0

        first_seen = min(first_seens) if first_seens else "Unknown"
        last_seen = max(last_seens) if last_seens else "Unknown"

        return {
            "ssid": ssid,
            "found": True,
            "bssid_count": len(bssids_info),
            "bssids": bssids_info,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "channels_used": sorted(list(channels)),
            "bands_used": sorted(list(bands)),
            "security_types": sorted(list(sec_types)),
            "encryption_types": sorted(list(enc_types)),
            "avg_signal": round(avg_sig, 1),
            "strongest_signal": max_sig,
            "weakest_signal": min_sig
        }
