import sqlite3
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from models.network import Network
from models.scan import ScanSession
from models.event import SecurityEvent
from models.observation import NetworkObservation
from models.baseline import EnvironmentBaseline, BaselineItem
from models.anomaly import AnomalyFinding

logger = logging.getLogger(__name__)


class RepositoryManager:
    """
    Repository wrapper providing domain queries over the SQLite connection pool.
    """

    def __init__(self, get_connection_fn):
        self.get_conn = get_connection_fn

    # ---------------------------------------------------------
    # ANOMALIES REPOSITORY
    # ---------------------------------------------------------
    def save_anomaly(self, anomaly: AnomalyFinding) -> int:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO anomalies (
                        timestamp, anomaly_type, severity, ssid, bssid,
                        what, when_detected, evidence, why_flagged, confidence, acknowledged
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    anomaly.timestamp, anomaly.anomaly_type, anomaly.severity,
                    anomaly.ssid, anomaly.bssid, anomaly.what, anomaly.when_detected,
                    anomaly.evidence, anomaly.why_flagged, anomaly.confidence,
                    1 if anomaly.acknowledged else 0
                ))
                conn.commit()
                return cursor.lastrowid
        except Exception as err:
            logger.error("Failed to save anomaly: %s", err)
            return -1

    def get_anomalies(
        self,
        severity: str = "ALL",
        search: str = "",
        limit: int = 200
    ) -> List[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM anomalies WHERE 1=1"
                params = []

                if severity and severity.upper() != "ALL":
                    query += " AND severity = ?"
                    params.append(severity.upper())

                if search:
                    q = f"%{search.strip().lower()}%"
                    query += " AND (LOWER(ssid) LIKE ? OR LOWER(bssid) LIKE ? OR LOWER(anomaly_type) LIKE ? OR LOWER(what) LIKE ?)"
                    params.extend([q, q, q, q])

                query += " ORDER BY id DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to query anomalies: %s", err)
            return []

    def mark_anomaly_acknowledged(self, anomaly_id: int):
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE anomalies SET acknowledged = 1 WHERE id = ?;", (anomaly_id,))
                conn.commit()
        except Exception as err:
            logger.error("Failed to acknowledge anomaly %d: %s", anomaly_id, err)

    # ---------------------------------------------------------
    # BASELINES REPOSITORY
    # ---------------------------------------------------------
    def save_baseline(self, name: str, description: str, items: List[Dict[str, Any]]) -> int:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                # Deactivate current active baseline
                cursor.execute("UPDATE baselines SET is_active = 0;")

                cursor.execute("""
                    INSERT INTO baselines (name, created_at, description, item_count, is_active)
                    VALUES (?, ?, ?, ?, 1);
                """, (name, timestamp, description, len(items)))
                baseline_id = cursor.lastrowid

                for item in items:
                    cursor.execute("""
                        INSERT INTO baseline_items (
                            baseline_id, bssid, ssid, security, encryption,
                            channel, band, avg_signal, min_signal, max_signal, vendor
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (
                        baseline_id, item.get("bssid"), item.get("ssid"),
                        item.get("security"), item.get("encryption"),
                        item.get("channel"), item.get("band"),
                        item.get("avg_signal", 0.0), item.get("min_signal", 0),
                        item.get("max_signal", 0), item.get("vendor", "Unknown Vendor")
                    ))

                conn.commit()
                return baseline_id
        except Exception as err:
            logger.error("Failed to save baseline: %s", err)
            return -1

    def get_active_baseline(self) -> Optional[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM baselines WHERE is_active = 1 ORDER BY id DESC LIMIT 1;")
                row = cursor.fetchone()
                if not row:
                    return None

                baseline = dict(row)
                cursor.execute("SELECT * FROM baseline_items WHERE baseline_id = ?;", (baseline["id"],))
                baseline["items"] = [dict(r) for r in cursor.fetchall()]
                return baseline
        except Exception as err:
            logger.error("Failed to fetch active baseline: %s", err)
            return None

    def get_all_baselines(self) -> List[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM baselines ORDER BY id DESC;")
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to list baselines: %s", err)
            return []

    def set_active_baseline(self, baseline_id: int):
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE baselines SET is_active = 0;")
                cursor.execute("UPDATE baselines SET is_active = 1 WHERE id = ?;", (baseline_id,))
                conn.commit()
        except Exception as err:
            logger.error("Failed to set active baseline: %s", err)

    def delete_baseline(self, baseline_id: int):
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM baseline_items WHERE baseline_id = ?;", (baseline_id,))
                cursor.execute("DELETE FROM baselines WHERE id = ?;", (baseline_id,))
                conn.commit()
        except Exception as err:
            logger.error("Failed to delete baseline %d: %s", baseline_id, err)

    # ---------------------------------------------------------
    # CHANNEL STATS & HISTORICAL TRENDS REPOSITORY
    # ---------------------------------------------------------
    def save_channel_stats(self, scan_id: int, stats: List[Dict[str, Any]]):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                for st in stats:
                    cursor.execute("""
                        INSERT INTO channel_stats (
                            scan_id, channel, band, network_count, unique_ssid_count, avg_signal, timestamp
                        ) VALUES (?, ?, ?, ?, ?, ?, ?);
                    """, (
                        scan_id, st.get("channel"), st.get("band"),
                        st.get("network_count", 0), st.get("unique_ssid_count", 0),
                        st.get("avg_signal", 0.0), timestamp
                    ))
                conn.commit()
        except Exception as err:
            logger.error("Failed to save channel stats: %s", err)

    def get_channel_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT channel, band, AVG(network_count) as avg_networks, MAX(network_count) as max_networks, AVG(avg_signal) as avg_signal
                    FROM channel_stats
                    GROUP BY channel, band
                    ORDER BY channel ASC;
                """)
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to query channel history: %s", err)
            return []
