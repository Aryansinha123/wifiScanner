from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class NetworkObservation:
    """
    Data model representing a historical observation point for a BSSID.
    """
    id: Optional[int]
    scan_id: int
    bssid: str
    ssid: str
    signal_percent: int
    estimated_rssi: int
    channel: Optional[int]
    band: str
    security: str
    encryption: str
    radio_type: str
    security_score: int
    risk_level: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "bssid": self.bssid,
            "ssid": self.ssid,
            "signal_percent": self.signal_percent,
            "estimated_rssi": self.estimated_rssi,
            "channel": self.channel,
            "band": self.band,
            "security": self.security,
            "encryption": self.encryption,
            "radio_type": self.radio_type,
            "security_score": self.security_score,
            "risk_level": self.risk_level,
            "timestamp": self.timestamp
        }
