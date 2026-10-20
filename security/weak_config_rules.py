import re
from typing import List, Dict, Any
from models.network import Network

DEFAULT_ROUTER_PATTERNS = [
    r"^TP-Link_[0-9A-Fa-f]{4,6}$",
    r"^TP-LINK_[0-9A-Fa-f]{4,6}$",
    r"^TPLink_[0-9A-Fa-f]{4,6}$",
    r"^JioFiber-[0-9A-Za-z]{4,6}$",
    r"^JioPrivate_[0-9A-Za-z]{4,6}$",
    r"^D-Link_[0-9A-Za-z]{4,6}$",
    r"^DIR-[0-9A-Za-z]{4,6}$",
    r"^dlink-[0-9A-Za-z]{4,6}$",
    r"^NETGEAR[0-9]{2,3}$",
    r"^Netgear_[0-9A-Za-z]{4,6}$",
    r"^Tenda_[0-9A-Za-z]{4,6}$",
    r"^TENDA_[0-9A-Za-z]{4,6}$",
    r"^Linksys[0-9]{4,5}$",
    r"^LINKSYS_[0-9A-Za-z]{4,6}$",
    r"^ASUS_[0-9A-Za-z]{4,6}$",
    r"^Asus_[0-9A-Za-z]{4,6}$",
    r"^HUAWEI-[0-9A-Za-z]{4,6}$",
    r"^Huawei_[0-9A-Za-z]{4,6}$",
    r"^ZTE-[0-9A-Za-z]{4,6}$",
    r"^Airtel_[0-9A-Za-z]{4,6}$",
    r"^FASTWEB-[0-9A-Za-z]{4,6}$",
    r"^Vodafone-[0-9A-Za-z]{4,6}$",
    r"^Bbox-[0-9A-Za-z]{4,6}$",
    r"^Livebox-[0-9A-Za-z]{4,6}$",
    r"^FRITZ!Box.*"
]

DEFAULT_COMPILED_REGEX = [re.compile(p, re.IGNORECASE) for p in DEFAULT_ROUTER_PATTERNS]


def is_default_router_name(ssid: str) -> bool:
    """
    Checks if an SSID matches common factory default router naming conventions.
    """
    if not ssid or ssid == "<Hidden Network>":
        return False
    ssid_clean = ssid.strip()
    return any(rx.match(ssid_clean) for rx in DEFAULT_COMPILED_REGEX)


# Registry of passive weak configuration checks detectable via Windows WLAN netsh API.
# Note: WPS (Wi-Fi Protected Setup) and PMF (Protected Management Frames 802.11w)
# are not exposed by Windows netsh and require monitor-mode raw beacon capture.
WEAK_CONFIG_RULES: List[Dict[str, Any]] = [
    {
        "id": "RULE_OPEN_NETWORK",
        "name": "Open Network (No Password)",
        "points": 85,
        "severity": "CRITICAL",
        "check": lambda net: net.security.upper() == "OPEN" or net.encryption.upper() in ("NONE", "NULL"),
        "reason": "Open unencrypted network (+85): No authentication or cipher encryption. Wireless traffic is broadcast in plaintext and susceptible to eavesdropping."
    },
    {
        "id": "RULE_WEP_ENCRYPTION",
        "name": "Deprecated WEP Security",
        "points": 75,
        "severity": "HIGH",
        "check": lambda net: "WEP" in net.security.upper() or "WEP" in net.encryption.upper(),
        "reason": "Legacy WEP encryption detected (+75): WEP is cryptographically broken and vulnerable to rapid offline key recovery."
    },
    {
        "id": "RULE_WPA1_LEGACY",
        "name": "Legacy WPA1 Protocol",
        "points": 35,
        "severity": "MEDIUM",
        "check": lambda net: net.security.upper() == "WPA",
        "reason": "Legacy WPA1 authentication detected (+35): Outdated security standard. Modern networks should deploy WPA2 or WPA3."
    },
    {
        "id": "RULE_TKIP_CIPHER",
        "name": "Deprecated TKIP Cipher",
        "points": 20,
        "severity": "MEDIUM",
        "check": lambda net: "TKIP" in net.encryption.upper(),
        "reason": "TKIP cipher is deprecated (+20): Vulnerable to Michael message integrity attacks; CCMP/AES is required."
    },
    {
        "id": "RULE_HIDDEN_SSID",
        "name": "Hidden SSID Broadcast",
        "points": 15,
        "severity": "LOW",
        "check": lambda net: not net.ssid or net.ssid.strip() in ("", "<Hidden Network>"),
        "reason": "Hidden SSID detected (+15): Employs security through obscurity and induces client probe vulnerabilities."
    },
    {
        "id": "RULE_DEFAULT_ROUTER_SSID",
        "name": "Default Router Naming Pattern",
        "points": 15,
        "severity": "LOW",
        "check": lambda net: is_default_router_name(net.ssid),
        "reason": "Default router manufacturer name pattern detected (+15): Network name matches factory naming convention, frequently left with default administrative credentials."
    }
]


def evaluate_weak_configurations(network: Network) -> List[Dict[str, Any]]:
    """
    Evaluates all weak-configuration rules against a network observation.
    Returns list of triggered findings with score points, severity, and human-readable reason.
    """
    findings: List[Dict[str, Any]] = []
    for rule in WEAK_CONFIG_RULES:
        try:
            if rule["check"](network):
                findings.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "points": rule["points"],
                    "severity": rule["severity"],
                    "reason": rule["reason"]
                })
        except Exception:
            continue
    return findings
