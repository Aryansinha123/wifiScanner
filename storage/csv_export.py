import csv
import logging
from datetime import datetime
from typing import List, Optional
from models.network import Network

logger = logging.getLogger(__name__)


def export_networks(networks: List[Network], filename: Optional[str] = None) -> str:
    """
    Exports list of Network objects to a CSV file.
    """
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if filename is None:
        timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"wifi_scan_{timestamp_file}.csv"

    logger.info("Exporting %d network(s) to CSV file: %s", len(networks), filename)

    try:
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            writer.writerow([
                "Timestamp",
                "SSID",
                "BSSID",
                "Signal (%)",
                "Estimated RSSI (dBm)",
                "Channel",
                "Band",
                "Security",
                "Encryption",
                "Radio Type",
                "Security Score",
                "Risk Level"
            ])

            for network in networks:
                writer.writerow([
                    now_str,
                    network.ssid,
                    network.bssid,
                    network.signal_percent,
                    network.signal_dbm if network.signal_dbm is not None else "Unknown",
                    network.channel if network.channel is not None else "Unknown",
                    network.band,
                    network.security,
                    network.encryption,
                    network.radio_type,
                    network.security_score(),
                    network.risk_level()
                ])

        logger.info("CSV export successfully written to %s", filename)
        return filename

    except Exception as err:
        logger.error("CSV export failed for file %s: %s", filename, err)
        raise RuntimeError(f"CSV export failed: {err}") from err