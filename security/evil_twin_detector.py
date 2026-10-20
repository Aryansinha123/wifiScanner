import re
import logging
from typing import List, Dict, Any, Optional
from models.network import Network
from storage.database import DatabaseManager

logger = logging.getLogger(__name__)


class EvilTwinDetector:
    """
    Rogue AP & Evil Twin Detection Engine.
    Compares active scan observations against the user's trusted networks profile.
    Uses an explainable heuristic evidence scoring model:
      - Same SSID, BSSID not in trusted list:   +40 pts
      - Security weaker than trusted version:   +30 pts
      - Different vendor (OUI):                 +15 pts
      - Different channel:                       +5 pts
      - Locally administered (fake/random) MAC: +10 pts
    """

    SECURITY_HIERARCHY = {
        "WPA3": 4,
        "WPA2": 3,
        "WPA": 2,
        "WEP": 1,
        "OPEN": 0,
        "NONE": 0,
        "UNKNOWN": 2
    }

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    @staticmethod
    def is_locally_administered_mac(mac: str) -> bool:
        """
        Checks if the MAC address has the IEEE 802 locally administered bit set (bit 1 of octet 0).
        Frequently indicates spoofed, virtual, or randomized MAC addresses.
        """
        if not mac:
            return False
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac)
        if len(clean) < 2:
            return False
        try:
            first_byte = int(clean[:2], 16)
            return bool(first_byte & 0x02)
        except ValueError:
            return False

    @classmethod
    def get_security_rank(cls, sec_str: str) -> int:
        sec = (sec_str or "").upper()
        if "WPA3" in sec:
            return cls.SECURITY_HIERARCHY["WPA3"]
        if "WPA2" in sec:
            return cls.SECURITY_HIERARCHY["WPA2"]
        if "WPA" in sec:
            return cls.SECURITY_HIERARCHY["WPA"]
        if "WEP" in sec:
            return cls.SECURITY_HIERARCHY["WEP"]
        if "OPEN" in sec or "NONE" in sec:
            return cls.SECURITY_HIERARCHY["OPEN"]
        return cls.SECURITY_HIERARCHY["UNKNOWN"]

    @classmethod
    def is_security_weaker(cls, current_sec: str, trusted_sec: str) -> bool:
        curr_rank = cls.get_security_rank(current_sec)
        trusted_rank = cls.get_security_rank(trusted_sec)
        return curr_rank < trusted_rank

    def evaluate_network(
        self,
        network: Network,
        trusted_list: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates a single network against the trusted networks list.
        Returns finding dictionary if an Evil Twin / Rogue AP pattern is detected, else None.
        """
        if not network.ssid or network.ssid == "<Hidden Network>":
            return None

        if trusted_list is None:
            trusted_list = self.db.repos.get_trusted_networks()

        net_ssid_lower = network.ssid.strip().lower()
        matching_trusted = [t for t in trusted_list if (t.get("ssid") or "").strip().lower() == net_ssid_lower]

        if not matching_trusted:
            # Network does not claim to be a known trusted SSID
            return None

        # Check if this BSSID is one of the trusted BSSIDs for this SSID
        net_bssid_upper = network.bssid.strip().upper()
        trusted_bssids = {t["bssid"].strip().upper(): t for t in matching_trusted}

        if net_bssid_upper in trusted_bssids:
            # Legitimate trusted AP
            return None

        # --- ROGUE AP / EVIL TWIN DETECTED ---
        ref = matching_trusted[0]
        score = 0
        evidence_factors: List[Dict[str, Any]] = []

        # 1. Same SSID, BSSID not in trusted list (+40)
        score += 40
        evidence_factors.append({
            "evidence": "Same SSID, BSSID not in trusted list",
            "points": 40,
            "details": f"SSID '{network.ssid}' is trusted, but BSSID {network.bssid} is unknown."
        })

        # 2. Security weaker than trusted version (+30)
        ref_sec = ref.get("security", "WPA2")
        if self.is_security_weaker(network.security, ref_sec):
            score += 30
            evidence_factors.append({
                "evidence": "Security weaker than trusted version",
                "points": 30,
                "details": f"Security downgraded: trusted '{ref_sec}' -> observed '{network.security}'"
            })

        # 3. Different vendor (OUI) (+15)
        ref_vendor = (ref.get("vendor") or "Unknown Vendor").strip().lower()
        curr_vendor = (network.vendor or "Unknown Vendor").strip().lower()
        if ref_vendor != "unknown vendor" and curr_vendor != "unknown vendor" and ref_vendor != curr_vendor:
            score += 15
            evidence_factors.append({
                "evidence": "Different vendor (OUI)",
                "points": 15,
                "details": f"Vendor mismatch: trusted '{ref.get('vendor')}' vs rogue '{network.vendor}'"
            })

        # 4. Different channel (+5)
        ref_channel = ref.get("channel")
        if ref_channel is not None and network.channel is not None and ref_channel != network.channel:
            score += 5
            evidence_factors.append({
                "evidence": "Different channel",
                "points": 5,
                "details": f"Channel displacement: trusted Ch {ref_channel} vs rogue Ch {network.channel}"
            })

        # 5. Locally administered (fake/randomized) MAC (+10)
        is_local_mac = self.is_locally_administered_mac(network.bssid)
        if is_local_mac:
            score += 10
            evidence_factors.append({
                "evidence": "Locally administered (fake-looking) MAC",
                "points": 10,
                "details": f"MAC address {network.bssid} has locally administered/randomized bit set."
            })

        # Severity Determination
        is_weaker = any(f["evidence"] == "Security weaker than trusted version" for f in evidence_factors)
        severity = "CRITICAL" if (score >= 70 or is_weaker) else "HIGH"

        # Build readable summary message
        downgrade_str = f", security downgraded {ref_sec} -> {network.security}" if is_weaker else ""
        msg = f"Potential Evil Twin: Same SSID '{network.ssid}', unknown BSSID {network.bssid}{downgrade_str} (Score: {score}/100)"

        return {
            "is_rogue": True,
            "ssid": network.ssid,
            "bssid": network.bssid,
            "score": score,
            "severity": severity,
            "trusted_bssid": ref.get("bssid"),
            "trusted_security": ref_sec,
            "current_security": network.security,
            "trusted_vendor": ref.get("vendor"),
            "current_vendor": network.vendor,
            "trusted_channel": ref_channel,
            "current_channel": network.channel,
            "is_locally_administered": is_local_mac,
            "evidence_factors": evidence_factors,
            "message": msg
        }

    def scan_for_evil_twins(self, networks: List[Network]) -> List[Dict[str, Any]]:
        """
        Scans all networks against trusted networks and returns list of rogue findings.
        """
        trusted_list = self.db.repos.get_trusted_networks()
        if not trusted_list:
            return []

        findings: List[Dict[str, Any]] = []
        for net in networks:
            res = self.evaluate_network(net, trusted_list)
            if res:
                findings.append(res)
                logger.warning("EvilTwinDetector flagged ROGUE AP: %s (Severity: %s, Score: %d)",
                               net.ssid, res["severity"], res["score"])
        return findings
