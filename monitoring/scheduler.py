import logging
from typing import List, Dict, Any
from models.network import Network
from storage.database import DatabaseManager
from monitoring.change_detector import detect_changes
from monitoring.event_manager import EventManager
from monitoring.baseline_manager import BaselineManager

logger = logging.getLogger(__name__)


class MonitoringPipeline:
    """
    Coordinates scan processing, state updates, change detection,
    baseline deviation checks, and event persistence.
    """

    def __init__(self, db_manager: DatabaseManager, event_mgr: EventManager):
        self.db = db_manager
        self.event_mgr = event_mgr
        self.baseline_mgr = BaselineManager(self.db)

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

        # 4. Record all events to database
        if all_events:
            self.event_mgr.record_events(all_events)
            logger.info("MonitoringPipeline generated and recorded %d security events.", len(all_events))

        return all_events
