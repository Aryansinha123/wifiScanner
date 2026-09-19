from typing import List, Dict, Any
from models.network import Network


def evaluate_security_rules(network: Network) -> List[Dict[str, Any]]:
    """
    Evaluates rule-based security checks for a discovered Wi-Fi network.
    """
    findings = []
    sec = network.security.upper()
    enc = network.encryption.upper()

    # Rule 1: Encryption Check
    if sec == "OPEN" or enc in ("NONE", "NULL"):
        findings.append({
            "rule": "RULE_ENCRYPTION_REQUIRED",
            "status": "FAIL",
            "severity": "CRITICAL",
            "message": "No wireless encryption detected. Network traffic is unencrypted."
        })
    else:
        findings.append({
            "rule": "RULE_ENCRYPTION_REQUIRED",
            "status": "PASS",
            "severity": "INFO",
            "message": f"Wireless encryption enabled ({network.encryption})."
        })

    # Rule 2: Legacy WEP Protocol Check
    if "WEP" in sec or "WEP" in enc:
        findings.append({
            "rule": "RULE_NO_LEGACY_WEP",
            "status": "FAIL",
            "severity": "HIGH",
            "message": "Legacy WEP security detected. WEP is deprecated and vulnerable."
        })
    else:
        findings.append({
            "rule": "RULE_NO_LEGACY_WEP",
            "status": "PASS",
            "severity": "INFO",
            "message": "No WEP legacy protocol detected."
        })

    # Rule 3: Legacy TKIP Cipher Check
    if "TKIP" in enc:
        findings.append({
            "rule": "RULE_NO_DEPRECATED_CIPHER",
            "status": "WARNING",
            "severity": "MEDIUM",
            "message": "TKIP cipher detected. TKIP is deprecated; CCMP/AES is recommended."
        })
    else:
        findings.append({
            "rule": "RULE_NO_DEPRECATED_CIPHER",
            "status": "PASS",
            "severity": "INFO",
            "message": "Modern cipher configuration detected."
        })

    # Rule 4: Modern WPA3 Support
    if "WPA3" in sec:
        findings.append({
            "rule": "RULE_MODERN_SECURITY",
            "status": "PASS",
            "severity": "INFO",
            "message": "Modern WPA3 wireless authentication detected."
        })

    return findings
