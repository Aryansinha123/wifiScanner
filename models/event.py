from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class SecurityEvent:
    """
    Data model representing a passive security monitoring event.
    """
    id: Optional[int]
    timestamp: str
    event_type: str
    severity: str
    ssid: str
    bssid: str
    description: str
    old_value: str = ""
    new_value: str = ""
    acknowledged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "severity": self.severity,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "description": self.description,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "acknowledged": self.acknowledged
        }
