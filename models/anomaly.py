from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class AnomalyFinding:
    """
    Data model representing a passive wireless anomaly detection finding.
    """
    id: Optional[int]
    timestamp: str
    anomaly_type: str
    severity: str
    ssid: str
    bssid: str
    what: str
    when_detected: str
    evidence: str
    why_flagged: str
    confidence: float
    acknowledged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "anomaly_type": self.anomaly_type,
            "severity": self.severity,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "what": self.what,
            "when_detected": self.when_detected,
            "evidence": self.evidence,
            "why_flagged": self.why_flagged,
            "confidence": self.confidence,
            "acknowledged": self.acknowledged
        }
