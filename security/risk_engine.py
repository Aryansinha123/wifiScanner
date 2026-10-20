import logging
from typing import Dict, Any, List, Optional
from models.network import Network
from security.weak_config_rules import WEAK_CONFIG_RULES, evaluate_weak_configurations, is_default_router_name

logger = logging.getLogger(__name__)


class MultiFactorRiskEngine:
    """
    Multi-Factor Heuristic Risk Engine for passive Wi-Fi security scoring (0-100).
    Integrates protocol rules, cipher weaknesses, weak-configuration checks,
    and behavioral/baseline deviations.
    """

    weak_config_rules = WEAK_CONFIG_RULES

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

        # 3. Weak Configuration Modifiers (Hidden SSID, Default Router Names)
        if not network.ssid or network.ssid.strip() in ("", "<Hidden Network>"):
            score += 15
            factors.append({"factor": "Hidden SSID Broadcast (+15)", "points": 15, "type": "weak_config"})

        if is_default_router_name(network.ssid):
            score += 15
            factors.append({"factor": "Default Router Naming Pattern (+15)", "points": 15, "type": "weak_config"})

        # 4. Observational & Behavioral Risk Factors
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

        weak_findings = evaluate_weak_configurations(network)

        return {
            "score": final_score,
            "level": level,
            "factors": factors,
            "weak_config_findings": weak_findings,
            "explanation": f"Heuristic risk score {final_score}/100 ({level}) based on {len(factors)} contributing factors."
        }
