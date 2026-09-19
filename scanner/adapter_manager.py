import logging
from typing import List, Dict, Any
from scanner.windows_scanner import WindowsScanner
from utils.parser import parse_interface

logger = logging.getLogger(__name__)


class AdapterManager:
    """
    Manages wireless network adapter discovery and status retrieval.
    """

    def __init__(self, scanner: WindowsScanner = None):
        self.scanner = scanner or WindowsScanner()

    def get_all_adapters(self) -> List[Dict[str, Any]]:
        """
        Retrieves status information for all available wireless interfaces.
        """
        try:
            raw_text = self.scanner.get_interfaces()
            adapters = self._parse_multiple_interfaces(raw_text)
            if not adapters:
                # Fallback to single parsed interface if parsing multiple returned empty
                adapters = [parse_interface(raw_text)]
            return adapters
        except Exception as err:
            logger.warning("Failed to retrieve wireless adapters: %s", err)
            return [{
                "name": "Unknown",
                "description": "Unknown Wireless Adapter",
                "state": "Unavailable",
                "ssid": "Not Connected",
                "bssid": "N/A",
                "channel": None,
                "signal_percent": None,
                "radio_type": "Unknown",
                "band": "Unknown"
            }]

    def _parse_multiple_interfaces(self, raw_data: str) -> List[Dict[str, Any]]:
        """
        Parses output containing potential multiple interface blocks.
        """
        blocks = raw_data.split("\nName")
        adapters = []

        for idx, block in enumerate(blocks):
            if idx > 0:
                block = "Name" + block
            stripped = block.strip()
            if not stripped:
                continue

            info = parse_interface(stripped)
            if info and info.get("name") != "Unknown":
                adapters.append(info)

        return adapters
