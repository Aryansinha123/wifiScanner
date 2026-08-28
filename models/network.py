from dataclasses import dataclass
from typing import Optional


@dataclass
class Network:
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
        security = self.security.upper()

        if "WPA3" in security:
            return 100

        if "WPA2" in security:
            return 85

        if "WPA" in security:
            return 60

        if "WEP" in security:
            return 20

        if "OPEN" in security:
            return 0

        return 50

    def risk_level(self) -> str:
        score = self.security_score()

        if score >= 85:
            return "LOW"

        if score >= 60:
            return "MEDIUM"

        if score >= 30:
            return "HIGH"

        return "CRITICAL"