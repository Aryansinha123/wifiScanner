import time
import threading
import logging
from datetime import datetime
from typing import Callable, Optional, Dict, Any, List
from models.network import Network
from scanner.scanner_manager import ScannerManager
from utils.parser import parse_networks

logger = logging.getLogger(__name__)


class ScanScheduler:
    """
    Thread-safe background scan scheduler for Wi-Fi discovery & security monitoring.
    """

    def __init__(self, scanner_mgr: ScannerManager = None):
        self.scanner_mgr = scanner_mgr or ScannerManager()
        self.interval_sec: int = 30  # Default 30s
        self.is_active: bool = False
        self.is_scanning: bool = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        self.last_scan_time: str = "Never"
        self.last_scan_duration: float = 0.0
        self.total_scans_completed: int = 0
        self.last_error: Optional[str] = None

        self._on_scan_success_callbacks: List[Callable[[List[Network], float], None]] = []
        self._on_scan_error_callbacks: List[Callable[[str, float], None]] = []

    def register_success_callback(self, callback: Callable[[List[Network], float], None]):
        self._on_scan_success_callbacks.append(callback)

    def register_error_callback(self, callback: Callable[[str, float], None]):
        self._on_scan_error_callbacks.append(callback)

    def set_interval(self, seconds: int):
        """
        Sets scan interval in seconds (e.g. 10, 30, 60, 300, 600, or 0 for manual).
        """
        self.interval_sec = max(0, seconds)
        logger.info("Scan interval set to %d seconds.", self.interval_sec)

    def start(self):
        """
        Starts automatic background scan monitoring loop.
        """
        if self.is_active:
            logger.debug("Scheduler is already active.")
            return

        self.is_active = True
        self._stop_event.clear()
        self._worker_thread = threading.Thread(target=self._run_loop, daemon=True)
        self._worker_thread.start()
        logger.info("ScanScheduler started (ACTIVE).")

    def pause(self):
        """
        Pauses automatic background scan monitoring.
        """
        if not self.is_active:
            return

        self.is_active = False
        self._stop_event.set()
        logger.info("ScanScheduler paused (PAUSED).")

    def trigger_manual_scan(self):
        """
        Triggers an immediate scan pass on a background thread.
        """
        if self.is_scanning:
            logger.info("Scan already in progress. Skipping manual trigger.")
            return

        thread = threading.Thread(target=self._execute_single_scan, daemon=True)
        thread.start()

    def _run_loop(self):
        while self.is_active and not self._stop_event.is_set():
            if self.interval_sec > 0:
                self._execute_single_scan()
                # Sleep in small slices to allow rapid pause/shutdown responsiveness
                elapsed = 0
                while elapsed < self.interval_sec and self.is_active and not self._stop_event.is_set():
                    time.sleep(0.5)
                    elapsed += 0.5
            else:
                time.sleep(1.0)

    def _execute_single_scan(self):
        if self.is_scanning:
            return

        self.is_scanning = True
        start_time = time.time()

        try:
            raw_output = self.scanner_mgr.scan()
            networks = parse_networks(raw_output)
            duration = time.time() - start_time

            self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.last_scan_duration = duration
            self.total_scans_completed += 1
            self.last_error = None
            self.is_scanning = False

            for cb in self._on_scan_success_callbacks:
                try:
                    cb(networks, duration)
                except Exception as cb_err:
                    logger.error("Error in scan success callback: %s", cb_err)

        except Exception as err:
            duration = time.time() - start_time
            self.last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.last_scan_duration = duration
            self.last_error = str(err)
            self.is_scanning = False

            logger.error("Scan failed: %s", err)
            for cb in self._on_scan_error_callbacks:
                try:
                    cb(str(err), duration)
                except Exception as cb_err:
                    logger.error("Error in scan error callback: %s", cb_err)

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": "ACTIVE" if self.is_active else "PAUSED",
            "is_scanning": self.is_scanning,
            "interval_sec": self.interval_sec,
            "total_scans": self.total_scans_completed,
            "last_scan_time": self.last_scan_time,
            "last_scan_duration": self.last_scan_duration,
            "last_error": self.last_error
        }
