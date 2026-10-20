import logging
from typing import List, Dict, Any
from models.network import Network
from storage.database import DatabaseManager
from monitoring.change_detector import detect_changes
from monitoring.event_manager import EventManager
from monitoring.baseline_manager import BaselineManager
from monitoring.alert_manager import AlertManager
from monitoring.connection_integrity import ConnectionIntegrityMonitor
from security.evil_twin_detector import EvilTwinDetector

logger = logging.getLogger(__name__)


class MonitoringPipeline:
    """
    Coordinates scan processing, state updates, change detection,
    baseline deviation checks, evil twin detection, connection integrity monitoring,
    and real-time alert dispatching.
    """

    def __init__(self, db_manager: DatabaseManager, event_mgr: EventManager):
        self.db = db_manager
        self.event_mgr = event_mgr
        self.baseline_mgr = BaselineManager(self.db)
        self.alert_mgr = AlertManager(self.db)
        self.evil_twin_detector = EvilTwinDetector(self.db)
        self.conn_monitor = ConnectionIntegrityMonitor(self.db, self.alert_mgr)

    def process_scan_results(
        self,
        networks: List[Network],
        duration: float,
        timestamp: str
    ) -> List[Dict[str, Any]]:
        """
        Executes complete passive monitoring pipeline for a scan pass.
        Returns list of all generated events.
        """
        all_events: List[Dict[str, Any]] = []

        # 1. Save scan & get previous state snapshot
        scan_id, prev_states = self.db.save_scan(networks, duration)

        # 2. Detect standard state & security changes
        change_events = detect_changes(prev_states, networks, timestamp)
        all_events.extend(change_events)

        # 3. Detect baseline deviations if active baseline exists
        baseline_events = self.baseline_mgr.check_baseline_deviations(networks)
        all_events.extend(baseline_events)

        # 4. Feature 1: Rogue AP & Evil Twin Detection
        try:
            evil_twins = self.evil_twin_detector.scan_for_evil_twins(networks)
            for et in evil_twins:
                all_events.append({
                    "event_type": "EVIL_TWIN_DETECTED",
                    "severity": et["severity"],
                    "ssid": et["ssid"],
                    "bssid": et["bssid"],
                    "description": et["message"],
                    "old_value": f"Trusted AP ({et.get('trusted_bssid')})",
                    "new_value": f"Rogue AP ({et['bssid']}) Score {et['score']}",
                    "timestamp": timestamp
                })
                # Dispatch Real-Time Alert
                self.alert_mgr.dispatch_alert(
                    alert_type="EVIL_TWIN_DETECTED",
                    severity=et["severity"],
                    bssid=et["bssid"],
                    ssid=et["ssid"],
                    message=et["message"],
                    evidence=str(et.get("evidence_factors"))
                )
        except Exception as err:
            logger.error("Error running evil twin detection: %s", err)

        # 5. Feature 2: Dispatch Alerts for Critical Change Events (e.g. Sudden Security Downgrade)
        for ev in change_events:
            if ev.get("severity") in ("CRITICAL", "HIGH"):
                self.alert_mgr.dispatch_alert(
                    alert_type=ev["event_type"],
                    severity=ev["severity"],
                    bssid=ev.get("bssid", ""),
                    ssid=ev.get("ssid", ""),
                    message=ev.get("description", "")
                )

        # 6. Feature 5: Run Connection Integrity Evaluation
        try:
            self.conn_monitor.run_integrity_check()
        except Exception as err:
            logger.warning("Error running connection integrity check: %s", err)

        # 7. Record all events to database
        if all_events:
            self.event_mgr.record_events(all_events)
            logger.info("MonitoringPipeline generated and recorded %d security events.", len(all_events))

        return all_events
