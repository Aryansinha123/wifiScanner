import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from models.network import Network
from models.anomaly import AnomalyFinding
from storage.database import DatabaseManager

logger = logging.getLogger(__name__)


class PassiveAnomalyDetector:
    """
    Passive Anomaly Detection Engine for wireless environment monitoring.
    Evaluates scan observations against historical baselines and network states.
    Strictly defensive & explainable (WHAT, WHEN, WHICH BSSID, WHAT was different, WHY flagged).
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def detect_anomalies(
        self,
        previous_states: Dict[str, Dict[str, Any]],
        current_networks: List[Network],
        timestamp: Optional[str] = None
    ) -> List[AnomalyFinding]:
        """
        Analyzes current scan observations for passive environment anomalies.
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        anomalies: List[AnomalyFinding] = []
        current_map = {n.bssid: n for n in current_networks}

        active_baseline = self.db.repos.get_active_baseline()
        baseline_bssids = set(item["bssid"] for item in active_baseline["items"]) if active_baseline else set()

        # Group current networks by SSID to check BSSID density per SSID
        ssid_bssid_map: Dict[str, List[str]] = {}
        for net in current_networks:
            if net.ssid and net.ssid != "<Hidden Network>":
                ssid_bssid_map.setdefault(net.ssid, []).append(net.bssid)

        # 1. Check Anomalies per BSSID
        for bssid, net in current_map.items():
            prev = previous_states.get(bssid)

            if prev:
                # 1.1 Sudden Security Downgrade
                old_sec = (prev.get("last_security") or "UNKNOWN").upper()
                new_sec = net.security.upper()
                if old_sec in ("WPA2", "WPA3") and new_sec in ("OPEN", "WEP"):
                    anomalies.append(AnomalyFinding(
                        id=None,
                        timestamp=timestamp,
                        anomaly_type="SUDDEN_SECURITY_DOWNGRADE",
                        severity="CRITICAL",
                        ssid=net.ssid,
                        bssid=bssid,
                        what=f"Security configuration downgraded from '{old_sec}' to '{new_sec}'.",
                        when_detected=timestamp,
                        evidence=f"Previous security: {old_sec} / {prev.get('last_encryption')}, Current security: {new_sec} / {net.encryption}",
                        why_flagged="A secure network transitioned to unencrypted or weak security, which poses security risk.",
                        confidence=0.95
                    ))

                # 1.2 Unusual Channel Shift (> 4 channels or band jump)
                old_ch = prev.get("last_channel")
                if old_ch is not None and net.channel is not None and abs(net.channel - old_ch) >= 4:
                    old_band = prev.get("last_band", "Unknown")
                    anomalies.append(AnomalyFinding(
                        id=None,
                        timestamp=timestamp,
                        anomaly_type="UNUSUAL_CHANNEL_SHIFT",
                        severity="MEDIUM",
                        ssid=net.ssid,
                        bssid=bssid,
                        what=f"Access point channel shifted significantly from Channel {old_ch} ({old_band}) to Channel {net.channel} ({net.band}).",
                        when_detected=timestamp,
                        evidence=f"Channel changed by {abs(net.channel - old_ch)} channels.",
                        why_flagged="Significant channel displacement observed compared to historical baseline channel.",
                        confidence=0.85
                    ))

                # 1.3 Large Signal Fluctuation (> 35% jump)
                old_sig = prev.get("last_signal")
                if old_sig is not None and abs(net.signal_percent - old_sig) >= 35:
                    anomalies.append(AnomalyFinding(
                        id=None,
                        timestamp=timestamp,
                        anomaly_type="LARGE_SIGNAL_DEVIATION",
                        severity="INFO",
                        ssid=net.ssid,
                        bssid=bssid,
                        what=f"Signal strength changed abruptly from {old_sig}% to {net.signal_percent}%.",
                        when_detected=timestamp,
                        evidence=f"Signal delta: {abs(net.signal_percent - old_sig)} percentage points.",
                        why_flagged="Abrupt signal level shift observed in passive observations.",
                        confidence=0.75
                    ))

            # 1.4 New Network Appearing in Stable Environment with Active Baseline
            elif active_baseline and bssid not in baseline_bssids:
                anomalies.append(AnomalyFinding(
                    id=None,
                    timestamp=timestamp,
                    anomaly_type="NEW_NETWORK_IN_STABLE_ENV",
                    severity="MEDIUM",
                    ssid=net.ssid,
                    bssid=bssid,
                    what=f"New previously unseen BSSID detected while active baseline '{active_baseline['name']}' is established.",
                    when_detected=timestamp,
                    evidence=f"BSSID {bssid} ({net.ssid}) was not recorded in baseline snapshot.",
                    why_flagged="New wireless device appeared in a baseline-profiled environment.",
                    confidence=0.88
                ))

        # 2. Check SSID BSSID Density Anomaly (> 4 BSSIDs for a single SSID)
        for ssid, bssids in ssid_bssid_map.items():
            if len(bssids) >= 5:
                anomalies.append(AnomalyFinding(
                    id=None,
                    timestamp=timestamp,
                    anomaly_type="UNUSUAL_BSSID_COUNT_FOR_SSID",
                    severity="MEDIUM",
                    ssid=ssid,
                    bssid=bssids[0],
                    what=f"High BSSID density observed for SSID '{ssid}' ({len(bssids)} BSSIDs detected).",
                    when_detected=timestamp,
                    evidence=f"Observed BSSIDs: {', '.join(bssids[:4])}...",
                    why_flagged="Multiple access points broadcasting identical SSID in immediate passive range.",
                    confidence=0.80
                ))

        # 3. Check Evil Twin / Rogue AP Anomalies against Trusted Networks
        try:
            from security.evil_twin_detector import EvilTwinDetector
            et_detector = EvilTwinDetector(self.db)
            evil_twins = et_detector.scan_for_evil_twins(current_networks)
            for et in evil_twins:
                anomalies.append(AnomalyFinding(
                    id=None,
                    timestamp=timestamp,
                    anomaly_type="EVIL_TWIN_DETECTED",
                    severity=et["severity"],
                    ssid=et["ssid"],
                    bssid=et["bssid"],
                    what=et["message"],
                    when_detected=timestamp,
                    evidence=str(et.get("evidence_factors", [])),
                    why_flagged="Access point broadcast matching trusted network SSID with unknown BSSID and/or downgraded security.",
                    confidence=0.98
                ))
        except Exception as err:
            logger.warning("Error running evil twin detection in anomaly detector: %s", err)

        # Persist detected anomalies to repository
        for anomaly in anomalies:
            self.db.repos.save_anomaly(anomaly)

        if anomalies:
            logger.info("PassiveAnomalyDetector flagged %d anomaly/anomalies.", len(anomalies))

        return anomalies
