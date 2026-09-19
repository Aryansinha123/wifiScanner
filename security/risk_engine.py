import logging
from typing import Dict, Any, List, Optional
from models.network import Network

logger = logging.getLogger(__name__)


class MultiFactorRiskEngine:
    """
    Multi-Factor Heuristic Risk Engine for passive Wi-Fi security scoring (0-100).

    Risk Score Calculation:
      Base Score (Protocol):
        - WPA3: 0 points
        - WPA2: 10 points
        - WPA: 35 points
        - WEP: 75 points
        - OPEN: 85 points
        - UNKNOWN: 40 points

      Cipher Modifiers:
        - Encryption NONE: +15 points
        - Encryption TKIP: +20 points
        - Encryption WEP: +15 points

      Behavioral & Observational Modifiers:
        - Security Downgrade observed: +30 points
        - Baseline Deviation detected: +20 points
        - Multiple BSSIDs for SSID anomaly: +15 points
        - Rapid appearance/disappearance: +10 points
        - Unusual channel change: +10 points
        - Large signal deviation: +10 points

      Risk Classification Thresholds:
        - 0 - 20: LOW
        - 21 - 45: MEDIUM
        - 46 - 70: HIGH
        - 71 - 100: CRITICAL
    """

    @staticmethod
    def calculate_risk(
        network: Network,
        has_security_downgrade: bool = False,
        has_baseline_deviation: bool = False,
        has_bssid_anomaly: bool = False,
        has_channel_anomaly: bool = False,
        has_signal_anomaly: bool = False
    ) -> Dict[str, Any]:
        """
        Calculates a deterministic risk score (0-100) and provides an explainable breakdown.
        """
        score = 0
        factors: List[Dict[str, Any]] = []

        sec = network.security.upper()
        enc = network.encryption.upper()

        # 1. Base Security Protocol Points
        if "WPA3" in sec:
            score += 0
            factors.append({"factor": "WPA3 Authentication", "points": 0, "type": "protocol"})
        elif "WPA2" in sec:
            score += 10
            factors.append({"factor": "WPA2 Authentication", "points": 10, "type": "protocol"})
        elif "WPA" in sec:
            score += 35
            factors.append({"factor": "Legacy WPA1 Authentication", "points": 35, "type": "protocol"})
        elif "WEP" in sec:
            score += 75
            factors.append({"factor": "Legacy WEP Security", "points": 75, "type": "protocol"})
        elif "OPEN" in sec:
            score += 85
            factors.append({"factor": "Open Unencrypted Network", "points": 85, "type": "protocol"})
        else:
            score += 40
            factors.append({"factor": "Unknown Security Protocol", "points": 40, "type": "protocol"})

        # 2. Cipher Weaknesses
        if enc in ("NONE", "NULL"):
            if "OPEN" not in sec:
                score += 15
                factors.append({"factor": "No Cipher Encryption", "points": 15, "type": "cipher"})
        elif "TKIP" in enc:
            score += 20
            factors.append({"factor": "Deprecated TKIP Cipher Detected", "points": 20, "type": "cipher"})
        elif "WEP" in enc:
            score += 15
            factors.append({"factor": "Deprecated WEP Cipher", "points": 15, "type": "cipher"})

        # 3. Observational & Behavioral Risk Factors
        if has_security_downgrade:
            score += 30
            factors.append({"factor": "Security Configuration Downgrade", "points": 30, "type": "behavior"})

        if has_baseline_deviation:
            score += 20
            factors.append({"factor": "Baseline Environment Deviation", "points": 20, "type": "behavior"})

        if has_bssid_anomaly:
            score += 15
            factors.append({"factor": "Unusual BSSID/SSID Relationship", "points": 15, "type": "behavior"})

        if has_channel_anomaly:
            score += 10
            factors.append({"factor": "Unexpected Channel Shift", "points": 10, "type": "behavior"})

        if has_signal_anomaly:
            score += 10
            factors.append({"factor": "Large Signal Deviation", "points": 10, "type": "behavior"})

        final_score = max(0, min(100, score))

        if final_score <= 20:
            level = "LOW"
        elif final_score <= 45:
            level = "MEDIUM"
        elif final_score <= 70:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return {
            "score": final_score,
            "level": level,
            "factors": factors,
            "explanation": f"Heuristic risk score {final_score}/100 ({level}) based on {len(factors)} contributing factors."
        }
