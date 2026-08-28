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
    if filename is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"wifi_scan_{timestamp}.csv"

    logger.info("Exporting %d network(s) to CSV file: %s", len(networks), filename)

    try:
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            writer.writerow([
                "SSID",
                "BSSID",
                "Signal (%)",
                "Estimated RSSI (dBm)",
                "Channel",
                "Frequency",
                "Security",
                "Encryption",
                "Radio Type",
                "Risk"
            ])

            for network in networks:
                writer.writerow([
                    network.ssid,
                    network.bssid,
                    network.signal_percent,
                    network.signal_dbm if network.signal_dbm is not None else "Unknown",
                    network.channel if network.channel is not None else "Unknown",
                    network.frequency,
                    network.security,
                    network.encryption,
                    network.radio_type,
                    network.risk_level()
                ])

        logger.info("CSV export successfully written to %s", filename)
        return filename

    except Exception as err:
        logger.error("CSV export failed for file %s: %s", filename, err)
        raise RuntimeError(f"CSV export failed: {err}") from err