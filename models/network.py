from dataclasses import dataclass
from typing import Optional


@dataclass
class Network:
    """
    Data model representing a single discovered Wi-Fi Access Point (BSSID).
    """
    ssid: str
    bssid: str
    signal_percent: int
    signal_dbm: Optional[int]
    channel: Optional[int]
    frequency: str
    security: str
    encryption: str
    radio_type: str

    def security_score(self) -> int:
        """
        Calculates a simplified educational security score (0-100).
        """
        sec = self.security.upper()

        if "WPA3" in sec:
            return 100
        if "WPA2" in sec:
            return 85
        if "WPA" in sec:
            return 60
        if "WEP" in sec:
            return 20
        if "OPEN" in sec:
            return 0
        return 50

    def risk_level(self) -> str:
        """
        Returns the risk classification label based on normalized security type.
        """
        sec = self.security.upper()

        if "WPA3" in sec or "WPA2" in sec:
            return "LOW"
        if "WPA" in sec:
            return "MEDIUM"
        if "WEP" in sec:
            return "HIGH"
        if "OPEN" in sec:
            return "CRITICAL"
        return "UNKNOWN"