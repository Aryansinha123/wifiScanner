from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class ScanSession:
    """
    Data model representing a completed Wi-Fi scan pass.
    """
    id: Optional[int]
    timestamp: str
    duration: float
    network_count: int
    unique_ssid_count: int
    open_count: int
    secured_count: int
    channel_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "duration": self.duration,
            "network_count": self.network_count,
            "unique_ssid_count": self.unique_ssid_count,
            "open_count": self.open_count,
            "secured_count": self.secured_count,
            "channel_count": self.channel_count
        }
