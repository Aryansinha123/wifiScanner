import logging
from datetime import datetime
from typing import List, Dict, Any
from models.network import Network

logger = logging.getLogger(__name__)


class SuspiciousPatternDetector:
    """
    Rule-based engine for correlating multiple passive security indicators.
    """

    @staticmethod
    def correlate_indicators(
        events: List[Dict[str, Any]],
        current_networks: List[Network]
    ) -> List[Dict[str, Any]]:
        """
        Correlates events and network observations to generate synthesized security findings.
        """
        correlated_findings: List[Dict[str, Any]] = []

        new_net_events = [e for e in events if e.get("event_type") == "NEW_NETWORK"]
        open_nets = [n for n in current_networks if n.security.upper() == "OPEN"]
        baseline_events = [e for e in events if e.get("event_type") == "BASELINE_DEVIATION"]

        # Pattern 1: New Open Network + Baseline Deviation
        for ev in new_net_events:
            bssid = ev.get("bssid")
            net = next((n for n in open_nets if n.bssid == bssid), None)
            if net:
                correlated_findings.append({
                    "indicator": "NEW_UNENCRYPTED_NETWORK_OBSERVED",
                    "severity": "HIGH",
                    "ssid": net.ssid,
                    "bssid": bssid,
                    "title": "Correlated Security Indicators: New Unencrypted AP",
                    "evidence": f"New network '{net.ssid}' detected with OPEN security protocol.",
                    "explanation": "A newly detected access point operates without encryption. Verify whether this AP is an authorized deployment.",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

        # Pattern 2: Security Downgrade + Baseline Deviation Correlation
        downgrades = [e for e in events if e.get("event_type") == "SECURITY_DOWNGRADE"]
        if downgrades and baseline_events:
            for dw in downgrades:
                correlated_findings.append({
                    "indicator": "SECURITY_DOWNGRADE_WITH_BASELINE_DEVIATION",
                    "severity": "CRITICAL",
                    "ssid": dw.get("ssid"),
                    "bssid": dw.get("bssid"),
                    "title": "Correlated Security Indicators: Security Downgrade & Baseline Shift",
                    "evidence": f"Security downgrade from '{dw.get('old_value')}' to '{dw.get('new_value')}' coincides with baseline deviation.",
                    "explanation": "Multiple correlated indicators detected. Security configuration changed significantly from baseline expectations.",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

        return correlated_findings
