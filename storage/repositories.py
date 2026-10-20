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

    # ---------------------------------------------------------
    # TRUSTED NETWORKS REPOSITORY (Feature 1: Evil Twin Detection)
    # ---------------------------------------------------------
    def add_trusted_network(
        self,
        ssid: str,
        bssid: str,
        vendor: str = "Unknown Vendor",
        security: str = "WPA2",
        channel: Optional[int] = None,
        notes: str = ""
    ) -> int:
        bssid_clean = bssid.strip().upper()
        added_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO trusted_networks (ssid, bssid, vendor, security, channel, added_at, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid = excluded.ssid,
                        vendor = excluded.vendor,
                        security = excluded.security,
                        channel = excluded.channel,
                        added_at = excluded.added_at,
                        notes = excluded.notes;
                """, (ssid.strip(), bssid_clean, vendor, security, channel, added_at, notes))
                conn.commit()
                return cursor.lastrowid
        except Exception as err:
            logger.error("Failed to add trusted network: %s", err)
            return -1

    def remove_trusted_network(self, bssid: str) -> bool:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM trusted_networks WHERE bssid = ?;", (bssid.strip().upper(),))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as err:
            logger.error("Failed to remove trusted network %s: %s", bssid, err)
            return False

    def get_trusted_networks(self) -> List[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM trusted_networks ORDER BY ssid ASC, added_at DESC;")
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to list trusted networks: %s", err)
            return []

    def get_trusted_network_by_bssid(self, bssid: str) -> Optional[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM trusted_networks WHERE bssid = ?;", (bssid.strip().upper(),))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as err:
            logger.error("Failed to query trusted network by bssid %s: %s", bssid, err)
            return None

    def get_trusted_networks_by_ssid(self, ssid: str) -> List[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM trusted_networks WHERE LOWER(ssid) = LOWER(?);", (ssid.strip(),))
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to query trusted networks by ssid %s: %s", ssid, err)
            return []

    def is_bssid_trusted(self, bssid: str) -> bool:
        return self.get_trusted_network_by_bssid(bssid) is not None

    # ---------------------------------------------------------
    # REAL-TIME ALERTS REPOSITORY (Feature 2: Real-Time Alerts)
    # ---------------------------------------------------------
    def save_alert(
        self,
        alert_type: str,
        severity: str,
        bssid: str,
        ssid: str,
        message: str,
        evidence: str = "",
        status: str = "NEW",
        last_sent_at: Optional[str] = None
    ) -> int:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sent_at = last_sent_at or now_str
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO alerts (
                        alert_type, severity, bssid, ssid, message, evidence,
                        status, created_at, last_sent_at, acknowledged
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0);
                """, (alert_type, severity, bssid, ssid, message, evidence, status, now_str, sent_at))
                conn.commit()
                return cursor.lastrowid
        except Exception as err:
            logger.error("Failed to save alert: %s", err)
            return -1

    def get_alerts(
        self,
        severity: str = "ALL",
        status: str = "ALL",
        limit: int = 200
    ) -> List[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                query = "SELECT * FROM alerts WHERE 1=1"
                params = []

                if severity and severity.upper() != "ALL":
                    query += " AND severity = ?"
                    params.append(severity.upper())

                if status and status.upper() != "ALL":
                    query += " AND status = ?"
                    params.append(status.upper())

                query += " ORDER BY id DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to query alerts: %s", err)
            return []

    def mark_alert_acknowledged(self, alert_id: int) -> bool:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE alerts SET acknowledged = 1, status = 'ACKNOWLEDGED' WHERE id = ?;
                """, (alert_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as err:
            logger.error("Failed to acknowledge alert %d: %s", alert_id, err)
            return False

    def get_latest_alert_for(self, alert_type: str, bssid: str) -> Optional[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM alerts
                    WHERE alert_type = ? AND bssid = ?
                    ORDER BY id DESC LIMIT 1;
                """, (alert_type, bssid))
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as err:
            logger.error("Failed to fetch latest alert for %s/%s: %s", alert_type, bssid, err)
            return None

    def get_unacknowledged_alert_count(self) -> int:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0;")
                row = cursor.fetchone()
                return row[0] if row else 0
        except Exception as err:
            logger.error("Failed to count unacknowledged alerts: %s", err)
            return 0

    # ---------------------------------------------------------
    # CONNECTION INTEGRITY LOGS REPOSITORY (Feature 5)
    # ---------------------------------------------------------
    def log_connection_integrity(
        self,
        timestamp: str,
        ssid: str,
        gateway_ip: str,
        gateway_mac: str,
        arp_status: str,
        dns_status: str,
        overall_health: str,
        details: str = ""
    ) -> int:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO connection_integrity_logs (
                        timestamp, ssid, gateway_ip, gateway_mac,
                        arp_status, dns_status, overall_health, details
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """, (timestamp, ssid, gateway_ip, gateway_mac, arp_status, dns_status, overall_health, details))
                conn.commit()
                return cursor.lastrowid
        except Exception as err:
            logger.error("Failed to log connection integrity check: %s", err)
            return -1

    def get_latest_connection_integrity(self) -> Optional[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM connection_integrity_logs ORDER BY id DESC LIMIT 1;")
                row = cursor.fetchone()
                return dict(row) if row else None
        except Exception as err:
            logger.error("Failed to get latest connection integrity log: %s", err)
            return None

    def get_connection_integrity_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        try:
            with self.get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM connection_integrity_logs ORDER BY id DESC LIMIT ?;", (limit,))
                return [dict(r) for r in cursor.fetchall()]
        except Exception as err:
            logger.error("Failed to fetch connection integrity history: %s", err)
            return []
