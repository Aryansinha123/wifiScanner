import sqlite3
import logging
from storage.backup import DatabaseBackupManager

logger = logging.getLogger(__name__)


def apply_migrations(conn: sqlite3.Connection, db_path: str = "data/wifi_scanner.db"):
    """
    Safely inspects database schema and applies incremental schema migrations.
    Never drops existing tables or deletes scan history.
    """
    logger.info("Checking database schema migrations...")
    cursor = conn.cursor()

    # Create migration history table if not present
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version INTEGER UNIQUE NOT NULL,
            applied_at TEXT NOT NULL
        );
    """)

    # Check networks columns
    cursor.execute("PRAGMA table_info(networks);")
    networks_cols = [row[1] for row in cursor.fetchall()]

    if "consecutive_missed_scans" not in networks_cols:
        logger.info("Migration: Adding consecutive_missed_scans column to networks table.")
        cursor.execute("ALTER TABLE networks ADD COLUMN consecutive_missed_scans INTEGER DEFAULT 0;")

    if "vendor" not in networks_cols:
        logger.info("Migration: Adding vendor column to networks table.")
        cursor.execute("ALTER TABLE networks ADD COLUMN vendor TEXT DEFAULT 'Unknown Vendor';")

    if "risk_score" not in networks_cols:
        logger.info("Migration: Adding risk_score column to networks table.")
        cursor.execute("ALTER TABLE networks ADD COLUMN risk_score INTEGER DEFAULT 50;")

    # Check observations columns
    cursor.execute("PRAGMA table_info(observations);")
    obs_cols = [row[1] for row in cursor.fetchall()]

    if "vendor" not in obs_cols:
        logger.info("Migration: Adding vendor column to observations table.")
        cursor.execute("ALTER TABLE observations ADD COLUMN vendor TEXT DEFAULT 'Unknown Vendor';")

    # 5. Baselines Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            description TEXT,
            item_count INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1
        );
    """)

    # 6. Baseline Items Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS baseline_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            baseline_id INTEGER NOT NULL,
            bssid TEXT NOT NULL,
            ssid TEXT,
            security TEXT,
            encryption TEXT,
            channel INTEGER,
            band TEXT,
            avg_signal REAL,
            min_signal INTEGER,
            max_signal INTEGER,
            vendor TEXT,
            FOREIGN KEY(baseline_id) REFERENCES baselines(id) ON DELETE CASCADE
        );
    """)

    # 7. Anomalies Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            anomaly_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            ssid TEXT,
            bssid TEXT,
            what TEXT NOT NULL,
            when_detected TEXT NOT NULL,
            evidence TEXT NOT NULL,
            why_flagged TEXT NOT NULL,
            confidence REAL DEFAULT 0.8,
            acknowledged INTEGER DEFAULT 0
        );
    """)

    # 8. Channel Stats Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS channel_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            channel INTEGER NOT NULL,
            band TEXT NOT NULL,
            network_count INTEGER DEFAULT 0,
            unique_ssid_count INTEGER DEFAULT 0,
            avg_signal REAL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
    """)

    # Create Additional Performance Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp ON anomalies(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_anomalies_bssid ON anomalies(bssid);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_baseline_items_bssid ON baseline_items(bssid);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_channel_stats_ch ON channel_stats(channel);")

    # 9. Trusted Networks Table (Feature 1: Evil Twin / Rogue AP Detection)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trusted_networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid TEXT NOT NULL,
            bssid TEXT NOT NULL UNIQUE,
            vendor TEXT DEFAULT 'Unknown Vendor',
            security TEXT DEFAULT 'WPA2',
            channel INTEGER,
            added_at TEXT NOT NULL,
            notes TEXT DEFAULT ''
        );
    """)

    # 10. Real-Time Alerts Table (Feature 2: Deduplication, Cooldown, Severity, Acknowledgment)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            bssid TEXT,
            ssid TEXT,
            message TEXT NOT NULL,
            evidence TEXT DEFAULT '',
            status TEXT DEFAULT 'NEW',
            created_at TEXT NOT NULL,
            last_sent_at TEXT,
            acknowledged INTEGER DEFAULT 0
        );
    """)

    # 11. Connection Integrity Logs Table (Feature 5: Connection Integrity Monitor)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS connection_integrity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ssid TEXT,
            gateway_ip TEXT,
            gateway_mac TEXT,
            arp_status TEXT,
            dns_status TEXT,
            overall_health TEXT,
            details TEXT
        );
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_trusted_ssid ON trusted_networks(ssid);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_trusted_bssid ON trusted_networks(bssid);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_bssid ON alerts(bssid);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_logs_time ON connection_integrity_logs(timestamp);")

    conn.commit()
    logger.info("Database schema migrations verified successfully.")
