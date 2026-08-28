import csv
from datetime import datetime


def export_networks(networks, filename=None):

    if filename is None:

        timestamp = datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )

        filename = f"wifi_scan_{timestamp}.csv"

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

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
                network.signal_dbm,
                network.channel,
                network.frequency,
                network.security,
                network.encryption,
                network.radio_type,
                network.risk_level()
            ])

    return filename