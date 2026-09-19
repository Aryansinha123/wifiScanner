from typing import Dict, Any
from models.network import Network
from security.risk_engine import MultiFactorRiskEngine
from security.security_rules import evaluate_security_rules


class ConfigurationAnalyzer:
    """
    Performs comprehensive configuration inspection on discovered networks.
    """

    @staticmethod
    def analyze_network_configuration(network: Network) -> Dict[str, Any]:
        risk_data = MultiFactorRiskEngine.calculate_risk(network)
        rules = evaluate_security_rules(network)

        sec = network.security.upper()
        if "WPA3" in sec:
            summary = "Modern wireless authentication with strong security characteristics."
        elif "WPA2" in sec:
            summary = "Commonly used modern wireless security configuration."
        elif "WPA" in sec:
            summary = "Older legacy wireless security configuration."
        elif "WEP" in sec:
            summary = "Deprecated legacy wireless security with known vulnerabilities."
        elif "OPEN" in sec:
            summary = "No wireless authentication or encryption was detected."
        else:
            summary = "Security configuration could not be conclusively determined."

        return {
            "ssid": network.ssid,
            "bssid": network.bssid,
            "security": network.security,
            "encryption": network.encryption,
            "risk_score": risk_data["score"],
            "risk_level": risk_data["level"],
            "risk_factors": risk_data["factors"],
            "summary": summary,
            "rule_findings": rules
        }
