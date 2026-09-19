import os
import sqlite3
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from models.network import Network
from storage.backup import DatabaseBackupManager
from storage.migrations import apply_migrations
from storage.repositories import RepositoryManager

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    SQLite Database Manager for Wi-Fi scan history, network tracking,
    observations, baselines, anomalies, and security monitoring events.
    """

    def __init__(self, db_path: str = "data/wifi_scanner.db"):
        self.db_path = db_path
        self._memory_conn: Optional[sqlite3.Connection] = None
        self._ensure_dir()
        self.backup_mgr = DatabaseBackupManager(db_path=self.db_path)
        self.repos = RepositoryManager(self._get_connection)
        self._init_db()

    def _ensure_dir(self):
        if self.db_path == ":memory:":
            return
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    def _get_connection(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._memory_conn.row_factory = sqlite3.Row
                self._memory_conn.execute("PRAGMA foreign_keys = ON;")
            return self._memory_conn

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn


    def _init_db(self):
        logger.info("Initializing SQLite database at %s...", self.db_path)
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # 1. Scans Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        duration REAL,
                        network_count INTEGER,
                        unique_ssid_count INTEGER,
                        open_count INTEGER,
                        secured_count INTEGER,
                        channel_count INTEGER
                    );
                """)

                # 2. Networks Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS networks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ssid TEXT,
                        bssid TEXT NOT NULL UNIQUE,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        last_signal INTEGER,
                        last_rssi INTEGER,
                        last_channel INTEGER,
                        last_band TEXT,
                        last_security TEXT,
                        last_encryption TEXT,
                        last_radio_type TEXT,
                        last_risk_level TEXT,
                        last_security_score INTEGER,
                        is_active INTEGER DEFAULT 1,
                        consecutive_missed_scans INTEGER DEFAULT 0,
                        vendor TEXT DEFAULT 'Unknown Vendor',
                        risk_score INTEGER DEFAULT 50
                    );
                """)

                # 3. Observations Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS observations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        bssid TEXT NOT NULL,
                        ssid TEXT,
                        signal_percent INTEGER,
                        estimated_rssi INTEGER,
                        channel INTEGER,
                        band TEXT,
                        security TEXT,
                        encryption TEXT,
                        radio_type TEXT,
                        security_score INTEGER,
                        risk_level TEXT,
                        timestamp TEXT NOT NULL,
                        vendor TEXT DEFAULT 'Unknown Vendor',
                        FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
                    );
                """)

                # 4. Events Table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        ssid TEXT,
                        bssid TEXT,
                        description TEXT,
                        old_value TEXT,
                        new_value TEXT,
                        acknowledged INTEGER DEFAULT 0
                    );
                """)

                # Apply Schema Migrations safely
                apply_migrations(conn, self.db_path)

                # Indexes for Performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_obs_bssid ON observations(bssid);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_obs_timestamp ON observations(timestamp);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_bssid ON events(bssid);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_networks_bssid ON networks(bssid);")

                conn.commit()
            logger.info("SQLite database initialized successfully.")
        except Exception as err:
            logger.error("Failed to initialize database: %s", err)
            raise RuntimeError(f"Database initialization failed: {err}") from err


    def save_scan(self, networks: List[Network], duration: float) -> Tuple[int, Dict[str, dict]]:
        """
        Saves a scan record, inserts observation rows, updates the tracked networks state,
        and returns a tuple of (scan_id, previous_network_states).
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        total_bssids = len(networks)
        valid_ssids = set(n.ssid for n in networks if n.ssid and n.ssid != "<Hidden Network>")
        unique_ssid_count = len(valid_ssids)
        open_count = sum(1 for n in networks if n.security.upper() == "OPEN")
        secured_count = sum(1 for n in networks if n.security.upper() in ("WPA2", "WPA3"))
        channel_count = len(set(n.channel for n in networks if n.channel is not None))

        previous_states: Dict[str, dict] = {}

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                # Get existing network states before this scan
                cursor.execute("SELECT * FROM networks;")
                for row in cursor.fetchall():
                    previous_states[row["bssid"]] = dict(row)

                # Insert Scan
                cursor.execute("""
                    INSERT INTO scans (timestamp, duration, network_count, unique_ssid_count, open_count, secured_count, channel_count)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                """, (timestamp, duration, total_bssids, unique_ssid_count, open_count, secured_count, channel_count))
                scan_id = cursor.lastrowid

                current_bssids = set()

                # Process detected networks
                for net in networks:
                    bssid = net.bssid
                    current_bssids.add(bssid)
                    score = net.security_score()
                    risk = net.risk_level()

                    # Insert observation
                    cursor.execute("""
                        INSERT INTO observations (
                            scan_id, bssid, ssid, signal_percent, estimated_rssi,
                            channel, band, security, encryption, radio_type,
                            security_score, risk_level, timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        scan_id, bssid, net.ssid, net.signal_percent, net.signal_dbm,
                        net.channel, net.band, net.security, net.encryption, net.radio_type,
                        score, risk, timestamp
                    ))

                    # Upsert network entry
                    if bssid in previous_states:
                        cursor.execute("""
                            UPDATE networks SET
                                ssid = ?,
                                last_seen = ?,
                                last_signal = ?,
                                last_rssi = ?,
                                last_channel = ?,
                                last_band = ?,
                                last_security = ?,
                                last_encryption = ?,
                                last_radio_type = ?,
                                last_risk_level = ?,
                                last_security_score = ?,
                                is_active = 1,
                                consecutive_missed_scans = 0
                            WHERE bssid = ?;
                        """, (
                            net.ssid, timestamp, net.signal_percent, net.signal_dbm,
                            net.channel, net.band, net.security, net.encryption, net.radio_type,
                            risk, score, bssid
                        ))
                    else:
                        cursor.execute("""
                            INSERT INTO networks (
                                ssid, bssid, first_seen, last_seen, last_signal, last_rssi,
                                last_channel, last_band, last_security, last_encryption,
                                last_radio_type, last_risk_level, last_security_score, is_active,
                                consecutive_missed_scans
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0);
                        """, (
                            net.ssid, bssid, timestamp, timestamp, net.signal_percent, net.signal_dbm,
                            net.channel, net.band, net.security, net.encryption,
                            net.radio_type, risk, score
                        ))

                # Update missed-scan state for absent networks (three-state model)
                # ACTIVE (is_active=1, missed=0..2) → TEMPORARILY_MISSING → NOT_DETECTED (is_active=0)
                for bssid, prev_info in previous_states.items():
                    if bssid not in current_bssids:
                        was_active = prev_info.get("is_active", 1)
                        if was_active == 0:
                            # Already confirmed NOT_DETECTED — no state change
                            continue
                        prev_missed = prev_info.get("consecutive_missed_scans", 0)
                        new_missed = prev_missed + 1
                        if new_missed >= 3:
                            # Threshold crossed → mark NOT_DETECTED
                            cursor.execute(
                                "UPDATE networks SET is_active = 0, consecutive_missed_scans = ? WHERE bssid = ?;",
                                (new_missed, bssid)
                            )
                        else:
                            # TEMPORARILY_MISSING — increment counter, stay active
                            cursor.execute(
                                "UPDATE networks SET consecutive_missed_scans = ? WHERE bssid = ?;",
                                (new_missed, bssid)
                            )

                conn.commit()

            return scan_id, previous_states

        except Exception as err:
            logger.error("Error saving scan to database: %s", err)
            raise RuntimeError(f"Database error saving scan: {err}") from err

    def create_event(
        self,
        event_type: str,
        severity: str,
        ssid: str,
        bssid: str,
        description: str,
        old_value: str = "",
        new_value: str = "",
        timestamp: Optional[str] = None
    ) -> int:
        """
        Inserts a new security monitoring event.
        """
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO events (timestamp, event_type, severity, ssid, bssid, description, old_value, new_value, acknowledged)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0);
                """, (timestamp, event_type, severity, ssid, bssid, description, old_value, new_value))
                conn.commit()
                return cursor.lastrowid
        except Exception as err:
            logger.error("Failed to create event in database: %s", err)
            return -1

    def get_events(
        self,
        severity: str = "ALL",
        event_type: str = "ALL",
        search: str = "",
        limit: int = 200
    ) -> List[Dict[str, Any]]:
        """
        Queries security events with optional filtering.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM events WHERE 1=1"
                params = []

                if severity and severity.upper() != "ALL":
                    query += " AND severity = ?"
                    params.append(severity.upper())

                if event_type and event_type.upper() != "ALL":
                    query += " AND event_type = ?"
                    params.append(event_type.upper())

                if search:
                    q = f"%{search.strip().lower()}%"
                    query += " AND (LOWER(ssid) LIKE ? OR LOWER(bssid) LIKE ? OR LOWER(event_type) LIKE ? OR LOWER(description) LIKE ?)"
                    params.extend([q, q, q, q])

                query += " ORDER BY id DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to query events: %s", err)
            return []

    def mark_event_acknowledged(self, event_id: int):
        """
        Marks an event as acknowledged.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE events SET acknowledged = 1 WHERE id = ?;", (event_id,))
                conn.commit()
        except Exception as err:
            logger.error("Failed to acknowledge event %d: %s", event_id, err)

    def get_all_tracked_networks(self) -> List[Dict[str, Any]]:
        """
        Returns list of all tracked network entries from the networks table.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM networks ORDER BY is_active DESC, last_seen DESC;")
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to fetch tracked networks: %s", err)
            return []

    def get_network_history(self, bssid: str) -> List[Dict[str, Any]]:
        """
        Returns all historical observations for a specific BSSID.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM observations WHERE bssid = ? ORDER BY id DESC LIMIT 100;
                """, (bssid,))
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to fetch network history for %s: %s", bssid, err)
            return []

    def get_monitoring_stats(self) -> Dict[str, int]:
        """
        Calculates summary statistics for the security monitor.
        """
        stats = {
            "total_scans": 0,
            "tracked_bssids": 0,
            "active_bssids": 0,
            "total_events": 0,
            "high_severity_events": 0,
            "new_networks_count": 0,
            "not_detected_count": 0,
            "security_changes_count": 0
        }

        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT COUNT(*) FROM scans;")
                stats["total_scans"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM networks;")
                stats["tracked_bssids"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM networks WHERE is_active = 1;")
                stats["active_bssids"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM events;")
                stats["total_events"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM events WHERE severity IN ('HIGH', 'CRITICAL');")
                stats["high_severity_events"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM events WHERE event_type = 'NEW_NETWORK';")
                stats["new_networks_count"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM events WHERE event_type = 'NETWORK_NOT_DETECTED';")
                stats["not_detected_count"] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM events WHERE event_type IN ('SECURITY_CHANGE', 'SECURITY_DOWNGRADE', 'SECURITY_UPGRADE');")
                stats["security_changes_count"] = cursor.fetchone()[0]

        except Exception as err:
            logger.error("Failed to retrieve monitoring stats: %s", err)

        return stats

    def clear_history(self) -> bool:
        """
        Clears scan history, observations, tracked networks, and events.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM observations;")
                cursor.execute("DELETE FROM scans;")
                cursor.execute("DELETE FROM events;")
                cursor.execute("DELETE FROM networks;")
                conn.commit()
            logger.info("Database history successfully cleared.")
            return True
        except Exception as err:
            logger.error("Failed to clear database history: %s", err)
            return False
