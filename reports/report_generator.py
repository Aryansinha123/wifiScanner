import json
import logging
from typing import List, Dict, Any, Optional
from models.network import Network
from reports.html_report import HTMLReportGenerator
from reports.csv_report import export_networks_to_csv, export_events_to_csv, export_anomalies_to_csv
from storage.database import DatabaseManager

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Unified Report Generator manager for HTML, CSV, and JSON security exports.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def generate_html_report(self, networks: List[Network], filepath: str) -> bool:
        events = self.db.get_events(limit=100)
        anomalies = self.db.repos.get_anomalies(limit=100)
        stats = self.db.get_monitoring_stats()

        return HTMLReportGenerator.generate_html_report(
            networks=networks,
            events=events,
            anomalies=anomalies,
            stats=stats,
            output_filepath=filepath
        )

    def generate_csv_report(self, dataset_type: str, filepath: str, networks: Optional[List[Network]] = None) -> bool:
        ds = dataset_type.lower()
        if ds == "networks":
            if networks is None:
                tracked = self.db.get_all_tracked_networks()
                networks = [
                    Network(
                        ssid=t.get("ssid", ""),
                        bssid=t.get("bssid", ""),
                        signal_percent=t.get("last_signal", 0) or 0,
                        signal_dbm=t.get("last_rssi"),
                        channel=t.get("last_channel"),
                        band=t.get("last_band", "Unknown"),
                        security=t.get("last_security", "UNKNOWN"),
                        encryption=t.get("last_encryption", "Unknown"),
                        radio_type=t.get("last_radio_type", "Unknown")
                    )
                    for t in tracked
                ]
            return export_networks_to_csv(networks, filepath)
        elif ds == "events":
            events = self.db.get_events(limit=500)
            return export_events_to_csv(events, filepath)
        elif ds == "anomalies":
            anomalies = self.db.repos.get_anomalies(limit=500)
            return export_anomalies_to_csv(anomalies, filepath)

        return False

    def generate_json_export(self, dataset_type: str, filepath: str, networks: Optional[List[Network]] = None) -> bool:
        ds = dataset_type.lower()
        data_to_export: Any = {}

        if ds == "networks":
            if networks:
                data_to_export = [
                    {
                        "ssid": n.ssid,
                        "bssid": n.bssid,
                        "signal_percent": n.signal_percent,
                        "signal_dbm": n.signal_dbm,
                        "channel": n.channel,
                        "band": n.band,
                        "security": n.security,
                        "encryption": n.encryption,
                        "radio_type": n.radio_type,
                        "risk_level": n.risk_level()
                    }
                    for n in networks
                ]
            else:
                data_to_export = self.db.get_all_tracked_networks()
        elif ds == "events":
            data_to_export = self.db.get_events(limit=500)
        elif ds == "anomalies":
            data_to_export = self.db.repos.get_anomalies(limit=500)
        elif ds == "baseline":
            data_to_export = self.db.repos.get_active_baseline()

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data_to_export, f, indent=2)
            logger.info("JSON export completed: %s", filepath)
            return True
        except Exception as err:
            logger.error("Failed to generate JSON export: %s", err)
            return False
