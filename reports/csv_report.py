import csv
import logging
from typing import List, Dict, Any
from models.network import Network

logger = logging.getLogger(__name__)


def export_networks_to_csv(networks: List[Network], filepath: str) -> bool:
    """
    Exports a list of discovered Network objects to CSV format.
    """
    fieldnames = [
        "SSID", "BSSID", "Signal_Percent", "Estimated_RSSI_dBm",
        "Channel", "Band", "Security", "Encryption", "Radio_Type", "Risk_Level"
    ]

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for net in networks:
                writer.writerow({
                    "SSID": net.ssid,
                    "BSSID": net.bssid,
                    "Signal_Percent": net.signal_percent,
                    "Estimated_RSSI_dBm": net.signal_dbm if net.signal_dbm is not None else "",
                    "Channel": net.channel if net.channel is not None else "",
                    "Band": net.band,
                    "Security": net.security,
                    "Encryption": net.encryption,
                    "Radio_Type": net.radio_type,
                    "Risk_Level": net.risk_level()
                })
        logger.info("Exported networks to CSV: %s", filepath)
        return True
    except Exception as err:
        logger.error("Failed to export networks CSV: %s", err)
        return False


def export_events_to_csv(events: List[Dict[str, Any]], filepath: str) -> bool:
    """
    Exports security events to CSV format.
    """
    fieldnames = ["ID", "Timestamp", "Event_Type", "Severity", "SSID", "BSSID", "Description", "Old_Value", "New_Value", "Acknowledged"]

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for ev in events:
                writer.writerow({
                    "ID": ev.get("id", ""),
                    "Timestamp": ev.get("timestamp", ""),
                    "Event_Type": ev.get("event_type", ""),
                    "Severity": ev.get("severity", ""),
                    "SSID": ev.get("ssid", ""),
                    "BSSID": ev.get("bssid", ""),
                    "Description": ev.get("description", ""),
                    "Old_Value": ev.get("old_value", ""),
                    "New_Value": ev.get("new_value", ""),
                    "Acknowledged": ev.get("acknowledged", 0)
                })
        logger.info("Exported events to CSV: %s", filepath)
        return True
    except Exception as err:
        logger.error("Failed to export events CSV: %s", err)
        return False


def export_anomalies_to_csv(anomalies: List[Dict[str, Any]], filepath: str) -> bool:
    """
    Exports anomaly findings to CSV format.
    """
    fieldnames = ["ID", "Timestamp", "Anomaly_Type", "Severity", "SSID", "BSSID", "What", "When_Detected", "Evidence", "Why_Flagged", "Confidence"]

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for an in anomalies:
                writer.writerow({
                    "ID": an.get("id", ""),
                    "Timestamp": an.get("timestamp", ""),
                    "Anomaly_Type": an.get("anomaly_type", ""),
                    "Severity": an.get("severity", ""),
                    "SSID": an.get("ssid", ""),
                    "BSSID": an.get("bssid", ""),
                    "What": an.get("what", ""),
                    "When_Detected": an.get("when_detected", ""),
                    "Evidence": an.get("evidence", ""),
                    "Why_Flagged": an.get("why_flagged", ""),
                    "Confidence": an.get("confidence", 0.8)
                })
        logger.info("Exported anomalies to CSV: %s", filepath)
        return True
    except Exception as err:
        logger.error("Failed to export anomalies CSV: %s", err)
        return False
