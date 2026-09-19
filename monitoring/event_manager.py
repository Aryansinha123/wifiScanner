import logging
from typing import List, Dict, Any, Optional
from storage.database import DatabaseManager

logger = logging.getLogger(__name__)


class EventManager:
    """
    Manages security monitoring events, database persistence, and queries.
    """

    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager

    def record_events(self, events: List[Dict[str, Any]]) -> int:
        """
        Persists a list of detected event dictionaries to the database.
        """
        count = 0
        for ev in events:
            res = self.db.create_event(
                event_type=ev["event_type"],
                severity=ev["severity"],
                ssid=ev.get("ssid", ""),
                bssid=ev.get("bssid", ""),
                description=ev.get("description", ""),
                old_value=ev.get("old_value", ""),
                new_value=ev.get("new_value", ""),
                timestamp=ev.get("timestamp")
            )
            if res != -1:
                count += 1
        logger.info("Recorded %d new security event(s).", count)
        return count

    def get_events(
        self,
        severity: str = "ALL",
        event_type: str = "ALL",
        search: str = "",
        limit: int = 200
    ) -> List[Dict[str, Any]]:
        """
        Retrieves event records from the database.
        """
        return self.db.get_events(
            severity=severity,
            event_type=event_type,
            search=search,
            limit=limit
        )

    def mark_event_acknowledged(self, event_id: int):
        """
        Marks an event as acknowledged.
        """
        self.db.mark_event_acknowledged(event_id)

    def clear_history(self) -> bool:
        """
        Clears all scan history and events from database.
        """
        return self.db.clear_history()

    def get_event_counts(self) -> Dict[str, int]:
        """
        Returns metric counters for events and monitoring status.
        """
        return self.db.get_monitoring_stats()
