import os
import shutil
import logging
from datetime import datetime
from typing import Tuple, List

logger = logging.getLogger(__name__)


class DatabaseBackupManager:
    """
    Handles automatic and manual database backups and safe restores.
    """

    def __init__(self, db_path: str = "data/wifi_scanner.db", backup_dir: str = "data/backups"):
        self.db_path = os.path.abspath(db_path)
        self.backup_dir = os.path.abspath(backup_dir)
        self._ensure_dirs()

    def _ensure_dirs(self):
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir, exist_ok=True)

    def create_backup(self, label: str = "manual") -> Tuple[bool, str]:
        """
        Creates a timestamped copy of the database file.
        Returns (success, backup_path_or_error).
        """
        if not os.path.exists(self.db_path):
            return False, f"Database file does not exist at {self.db_path}"

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"wifi_scanner_backup_{label}_{timestamp}.db"
        backup_path = os.path.join(self.backup_dir, backup_filename)

        try:
            shutil.copy2(self.db_path, backup_path)
            logger.info("Database backup created successfully at %s", backup_path)
            return True, backup_path
        except Exception as err:
            logger.error("Failed to create database backup: %s", err)
            return False, str(err)

    def list_backups(self) -> List[dict]:
        """
        Returns a list of available database backup files with size and timestamp.
        """
        if not os.path.exists(self.backup_dir):
            return []

        backups = []
        for filename in os.listdir(self.backup_dir):
            if filename.startswith("wifi_scanner_backup_") and filename.endswith(".db"):
                full_path = os.path.join(self.backup_dir, filename)
                try:
                    stat = os.stat(full_path)
                    backups.append({
                        "filename": filename,
                        "path": full_path,
                        "size_bytes": stat.st_size,
                        "created_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    })
                except Exception as err:
                    logger.warning("Error reading backup file stat for %s: %s", filename, err)

        backups.sort(key=lambda x: x["created_at"], reverse=True)
        return backups

    def restore_backup(self, backup_path: str, user_confirmed: bool = False) -> Tuple[bool, str]:
        """
        Restores a database from a backup file. Requires explicit user confirmation.
        """
        if not user_confirmed:
            return False, "Database restore cancelled: Explicit user confirmation required."

        if not os.path.exists(backup_path):
            return False, f"Backup file not found: {backup_path}"

        try:
            # Create a safety snapshot of current state before replacing
            self.create_backup(label="pre_restore_safety")
            shutil.copy2(backup_path, self.db_path)
            logger.info("Database successfully restored from %s", backup_path)
            return True, f"Database restored successfully from {os.path.basename(backup_path)}"
        except Exception as err:
            logger.error("Failed to restore database from %s: %s", backup_path, err)
            return False, f"Restore failed: {err}"
