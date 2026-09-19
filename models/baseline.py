from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class BaselineItem:
    """
    Individual baseline record for a BSSID.
    """
    bssid: str
    ssid: str
    security: str
    encryption: str
    channel: Optional[int]
    band: str
    avg_signal: float
    min_signal: int
    max_signal: int
    vendor: str = "Unknown Vendor"


@dataclass
class EnvironmentBaseline:
    """
    Data model representing a saved baseline snapshot of the wireless environment.
    """
    id: Optional[int]
    name: str
    created_at: str
    description: str
    item_count: int
    items: List[BaselineItem] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "created_at": self.created_at,
            "description": self.description,
            "item_count": self.item_count,
            "items": [
                {
                    "bssid": item.bssid,
                    "ssid": item.ssid,
                    "security": item.security,
                    "encryption": item.encryption,
                    "channel": item.channel,
                    "band": item.band,
                    "avg_signal": item.avg_signal,
                    "min_signal": item.min_signal,
                    "max_signal": item.max_signal,
                    "vendor": item.vendor
                }
                for item in self.items
            ]
        }
