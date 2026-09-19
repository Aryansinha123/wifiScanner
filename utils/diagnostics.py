import os
import sys
import platform
import logging
from typing import Dict, Any
from storage.database import DatabaseManager
from scanner.scanner_manager import ScannerManager

logger = logging.getLogger(__name__)


class ApplicationDiagnostics:
    """
    Performs system diagnostic health checks on Python, OS, Wi-Fi adapter, and SQLite database.
    """

    def __init__(self, db_manager: DatabaseManager, scanner_mgr: ScannerManager = None):
        self.db = db_manager
        self.scanner = scanner_mgr or ScannerManager()

    def run_diagnostics(self) -> Dict[str, Any]:

        py_ver = sys.version.split()[0]
        os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

        # Check adapter status
        adapter_status = "OK"
        adapter_info = {}
        try:
            adapter_info = self.scanner.get_interface_info()
            if adapter_info.get("state") in ("Unavailable", "Disabled"):
                adapter_status = "WARNING (Adapter Unavailable)"
        except Exception as err:
            adapter_status = f"ERROR ({err})"

        # Check DB status
        db_status = "OK"
        db_size_mb = 0.0
        try:
            if os.path.exists(self.db.db_path):
                stat = os.stat(self.db.db_path)
                db_size_mb = round(stat.st_size / (1024 * 1024), 3)
            else:
                db_status = "WARNING (Database file missing)"
        except Exception as err:
            db_status = f"ERROR ({err})"

        stats = self.db.get_monitoring_stats()

        return {
            "python_version": py_ver,
            "operating_system": os_info,
            "adapter_status": adapter_status,
            "adapter_name": adapter_info.get("name", "Unknown"),
            "database_status": db_status,
            "database_path": self.db.db_path,
            "database_size_mb": db_size_mb,
            "total_scans": stats.get("total_scans", 0),
            "tracked_bssids": stats.get("tracked_bssids", 0),
            "active_bssids": stats.get("active_bssids", 0),
            "total_events": stats.get("total_events", 0),
            "high_severity_events": stats.get("high_severity_events", 0)
        }
