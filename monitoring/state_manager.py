import logging
from typing import Dict, Any, List
from models.network import Network

logger = logging.getLogger(__name__)


class NetworkStateManager:
    """
    Manages three-state network lifecycle tracking across scan iterations:
      - ACTIVE (present in recent scan, is_active=1, missed=0)
      - TEMPORARILY_MISSING (absent 1..(threshold-1) scans, is_active=1)
      - NOT_DETECTED (absent >= threshold scans, is_active=0)
    """

    def __init__(self, missing_threshold: int = 3):
        self.missing_threshold = missing_threshold

    def evaluate_state_transitions(
        self,
        previous_states: Dict[str, Dict[str, Any]],
        current_networks: List[Network]
    ) -> Dict[str, str]:
        """
        Calculates new lifecycle states for all known BSSIDs.
        Returns a mapping of BSSID -> state_label ("ACTIVE", "TEMPORARILY_MISSING", "NOT_DETECTED").
        """
        current_bssids = set(n.bssid for n in current_networks)
        all_bssids = set(previous_states.keys()).union(current_bssids)

        new_states: Dict[str, str] = {}

        for bssid in all_bssids:
            if bssid in current_bssids:
                new_states[bssid] = "ACTIVE"
            else:
                prev_info = previous_states.get(bssid, {})
                was_active = bool(prev_info.get("is_active", 1))
                missed = prev_info.get("consecutive_missed_scans", 0) + 1

                if not was_active or missed >= self.missing_threshold:
                    new_states[bssid] = "NOT_DETECTED"
                else:
                    new_states[bssid] = "TEMPORARILY_MISSING"

        return new_states
