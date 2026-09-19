import logging
from typing import Dict, Any, List, Optional
from storage.database import DatabaseManager
from intelligence.vendor_analyzer import lookup_vendor
from analytics.signal_analyzer import SignalAnalyzer

logger = logging.getLogger(__name__)


class BSSIDAnalyzer:
    """
    Constructs detailed Intelligence Profiles for individual BSSIDs.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def get_bssid_profile(self, bssid: str) -> Dict[str, Any]:
        """
        Retrieves observation history, security timeline, vendor, and signal metrics for a BSSID.
        """
        bssid_upper = bssid.upper()
        history = self.db.get_network_history(bssid_upper)
        tracked_networks = self.db.get_all_tracked_networks()
        net_entry = next((n for n in tracked_networks if n["bssid"] == bssid_upper), None)

        if not net_entry and not history:
            return {"bssid": bssid_upper, "found": False, "message": "BSSID not found in database."}

        # Vendor lookup
        vendor = lookup_vendor(bssid_upper)

        # Aggregate signal metrics
        signals = [h["signal_percent"] for h in history if h.get("signal_percent") is not None]
        sig_stats = SignalAnalyzer.calculate_signal_stats(signals)

        # Aggregate channels, bands, security types
        channels_used = sorted(list(set(h["channel"] for h in history if h.get("channel") is not None)))
        bands_used = sorted(list(set(h["band"] for h in history if h.get("band"))))
        sec_history = sorted(list(set(h["security"] for h in history if h.get("security"))))
        enc_history = sorted(list(set(h["encryption"] for h in history if h.get("encryption"))))
        radios = sorted(list(set(h["radio_type"] for h in history if h.get("radio_type"))))

        # Fetch associated security events
        all_events = self.db.get_events(search=bssid_upper, limit=100)

        # Fetch associated anomalies if available
        anomalies = self.db.repos.get_anomalies(search=bssid_upper, limit=50)

        first_seen = net_entry.get("first_seen", "Unknown") if net_entry else (history[-1]["timestamp"] if history else "Unknown")
        last_seen = net_entry.get("last_seen", "Unknown") if net_entry else (history[0]["timestamp"] if history else "Unknown")
        ssid = net_entry.get("ssid", "Unknown") if net_entry else (history[0]["ssid"] if history else "Unknown")
        risk_level = net_entry.get("last_risk_level", "UNKNOWN") if net_entry else "UNKNOWN"

        return {
            "bssid": bssid_upper,
            "found": True,
            "ssid": ssid,
            "vendor": vendor,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "observation_count": len(history),
            "is_active": bool(net_entry.get("is_active", 1)) if net_entry else False,
            "current_signal": sig_stats["current"],
            "avg_signal": sig_stats["avg"],
            "min_signal": sig_stats["min"],
            "max_signal": sig_stats["max"],
            "estimated_rssi_dbm": sig_stats["estimated_rssi_dbm"],
            "channels_used": channels_used,
            "bands_used": bands_used,
            "security_history": sec_history,
            "encryption_history": enc_history,
            "radio_types": radios,
            "current_risk_level": risk_level,
            "events_count": len(all_events),
            "events": all_events,
            "anomalies_count": len(anomalies),
            "anomalies": anomalies
        }
