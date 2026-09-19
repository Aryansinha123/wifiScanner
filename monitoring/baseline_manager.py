import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from models.network import Network
from models.baseline import EnvironmentBaseline, BaselineItem
from storage.database import DatabaseManager

logger = logging.getLogger(__name__)


class BaselineManager:
    """
    Manages wireless environment baselines and deviation detection.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def create_baseline_from_current_state(self, name: str, description: str) -> Optional[int]:
        """
        Snapshots all currently active tracked networks into a new Baseline.
        """
        tracked_networks = self.db.get_all_tracked_networks()
        active_networks = [n for n in tracked_networks if n.get("is_active", 1) == 1]

        if not active_networks:
            logger.warning("Cannot create baseline: No active networks found.")
            return None

        items = []
        for net in active_networks:
            # Query signal min/max/avg from history if available
            bssid = net["bssid"]
            history = self.db.get_network_history(bssid)

            if history:
                signals = [h["signal_percent"] for h in history if h.get("signal_percent") is not None]
                min_sig = min(signals) if signals else net.get("last_signal", 50)
                max_sig = max(signals) if signals else net.get("last_signal", 50)
                avg_sig = sum(signals) / len(signals) if signals else float(net.get("last_signal", 50))
            else:
                last_sig = net.get("last_signal", 50) or 50
                min_sig, max_sig, avg_sig = last_sig, last_sig, float(last_sig)

            items.append({
                "bssid": bssid,
                "ssid": net.get("ssid", "<Hidden Network>"),
                "security": net.get("last_security", "UNKNOWN"),
                "encryption": net.get("last_encryption", "Unknown"),
                "channel": net.get("last_channel"),
                "band": net.get("last_band", "Unknown"),
                "min_signal": min_sig,
                "max_signal": max_sig,
                "avg_signal": avg_sig,
                "vendor": net.get("vendor", "Unknown Vendor")
            })

        baseline_id = self.db.repos.save_baseline(name, description, items)
        logger.info("Created baseline '%s' (ID: %d) with %d items.", name, baseline_id, len(items))
        return baseline_id

    def check_baseline_deviations(self, current_networks: List[Network]) -> List[Dict[str, Any]]:
        """
        Compares current scan against active baseline and returns detected deviation events.
        """
        active_baseline = self.db.repos.get_active_baseline()
        if not active_baseline:
            return []

        baseline_items = active_baseline.get("items", [])
        baseline_bssid_map = {item["bssid"]: item for item in baseline_items}
        baseline_ssids = set(item["ssid"] for item in baseline_items if item["ssid"])

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        deviations: List[Dict[str, Any]] = []

        for net in current_networks:
            bssid = net.bssid

            # 1. Unknown BSSID Deviation
            if bssid not in baseline_bssid_map:
                deviations.append({
                    "event_type": "BASELINE_DEVIATION",
                    "severity": "MEDIUM",
                    "ssid": net.ssid,
                    "bssid": bssid,
                    "description": f"Previously unseen BSSID detected (Not in baseline '{active_baseline['name']}').",
                    "old_value": "Baseline BSSIDs",
                    "new_value": f"New BSSID: {bssid} ({net.ssid})",
                    "timestamp": timestamp
                })
            else:
                base_item = baseline_bssid_map[bssid]

                # 2. Security Change from Baseline
                base_sec = (base_item.get("security") or "").upper()
                curr_sec = net.security.upper()

                if base_sec and curr_sec != base_sec:
                    severity = "HIGH" if ("OPEN" in curr_sec or "WEP" in curr_sec) else "MEDIUM"
                    deviations.append({
                        "event_type": "BASELINE_DEVIATION",
                        "severity": severity,
                        "ssid": net.ssid,
                        "bssid": bssid,
                        "description": f"Security configuration differs from active baseline ('{base_sec}' -> '{curr_sec}').",
                        "old_value": base_sec,
                        "new_value": curr_sec,
                        "timestamp": timestamp
                    })

                # 3. Channel Change from Baseline
                base_ch = base_item.get("channel")
                if base_ch is not None and net.channel is not None and base_ch != net.channel:
                    deviations.append({
                        "event_type": "BASELINE_DEVIATION",
                        "severity": "INFO",
                        "ssid": net.ssid,
                        "bssid": bssid,
                        "description": f"Channel differs from active baseline (Ch {base_ch} -> Ch {net.channel}).",
                        "old_value": f"Ch {base_ch}",
                        "new_value": f"Ch {net.channel}",
                        "timestamp": timestamp
                    })

            # 4. Unknown SSID Deviation
            if net.ssid and net.ssid != "<Hidden Network>" and net.ssid not in baseline_ssids:
                # Only log once per scan pass
                if not any(d["new_value"] == f"New SSID: {net.ssid}" for d in deviations):
                    deviations.append({
                        "event_type": "BASELINE_DEVIATION",
                        "severity": "INFO",
                        "ssid": net.ssid,
                        "bssid": bssid,
                        "description": f"Unseen SSID detected (Not recorded in active baseline '{active_baseline['name']}').",
                        "old_value": "Baseline SSIDs",
                        "new_value": f"New SSID: {net.ssid}",
                        "timestamp": timestamp
                    })

        return deviations
