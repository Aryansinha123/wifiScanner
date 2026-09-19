import math
import logging
from typing import List, Dict, Any, Optional
from utils.parser import signal_to_dbm

logger = logging.getLogger(__name__)


class SignalAnalyzer:
    """
    Computes signal statistics, RSSI estimation, and significant signal fluctuation metrics.
    """

    @staticmethod
    def calculate_signal_stats(signals: List[int]) -> Dict[str, Any]:
        """
        Calculates min, max, avg, std_dev, and estimated RSSI from a list of signal percentages.
        """
        if not signals:
            return {
                "count": 0,
                "current": 0,
                "min": 0,
                "max": 0,
                "avg": 0.0,
                "std_dev": 0.0,
                "range": 0,
                "estimated_rssi_dbm": -100
            }

        valid_signals = [max(0, min(100, s)) for s in signals]
        current = valid_signals[-1]
        min_sig = min(valid_signals)
        max_sig = max(valid_signals)
        avg_sig = sum(valid_signals) / len(valid_signals)

        variance = sum((s - avg_sig) ** 2 for s in valid_signals) / len(valid_signals)
        std_dev = math.sqrt(variance)
        rssi = signal_to_dbm(current)

        return {
            "count": len(valid_signals),
            "current": current,
            "min": min_sig,
            "max": max_sig,
            "avg": round(avg_sig, 1),
            "std_dev": round(std_dev, 2),
            "range": max_sig - min_sig,
            "estimated_rssi_dbm": rssi
        }

    @staticmethod
    def is_significant_signal_change(
        old_signal: Optional[int],
        new_signal: int,
        threshold: int = 25
    ) -> bool:
        """
        Returns True if signal change exceeds threshold percentage points.
        """
        if old_signal is None:
            return False
        return abs(new_signal - old_signal) >= threshold
