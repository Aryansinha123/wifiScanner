# Database Schema Documentation

## Database Engine: SQLite 3

File Location: `data/wifi_scanner.db`

---

## Tables Overview

### 1. `scans`
Stores session metadata for completed Wi-Fi scan passes.
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `timestamp` (TEXT NOT NULL)
- `duration` (REAL)
- `network_count` (INTEGER)
- `unique_ssid_count` (INTEGER)
- `open_count` (INTEGER)
- `secured_count` (INTEGER)
- `channel_count` (INTEGER)

### 2. `networks`
Tracks distinct wireless access points (BSSID lifecycle).
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `ssid` (TEXT)
- `bssid` (TEXT NOT NULL UNIQUE)
- `first_seen` (TEXT NOT NULL)
- `last_seen` (TEXT NOT NULL)
- `last_signal` (INTEGER)
- `last_rssi` (INTEGER)
- `last_channel` (INTEGER)
- `last_band` (TEXT)
- `last_security` (TEXT)
- `last_encryption` (TEXT)
- `last_radio_type` (TEXT)
- `last_risk_level` (TEXT)
- `last_security_score` (INTEGER)
- `is_active` (INTEGER DEFAULT 1)
- `consecutive_missed_scans` (INTEGER DEFAULT 0)
- `vendor` (TEXT DEFAULT 'Unknown Vendor')
- `risk_score` (INTEGER DEFAULT 50)

### 3. `observations`
Time-series log of every detected BSSID per scan pass.
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `scan_id` (INTEGER NOT NULL, FK -> scans.id)
- `bssid` (TEXT NOT NULL)
- `ssid` (TEXT)
- `signal_percent` (INTEGER)
- `estimated_rssi` (INTEGER)
- `channel` (INTEGER)
- `band` (TEXT)
- `security` (TEXT)
- `encryption` (TEXT)
- `radio_type` (TEXT)
- `security_score` (INTEGER)
- `risk_level` (TEXT)
- `timestamp` (TEXT NOT NULL)
- `vendor` (TEXT)

### 4. `events`
Security monitoring event log.
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `timestamp` (TEXT NOT NULL)
- `event_type` (TEXT NOT NULL)
- `severity` (TEXT NOT NULL)
- `ssid` (TEXT)
- `bssid` (TEXT)
- `description` (TEXT)
- `old_value` (TEXT)
- `new_value` (TEXT)
- `acknowledged` (INTEGER DEFAULT 0)

### 5. `baselines` & `baseline_items`
Saved wireless environment baseline snapshots and baseline BSSID items.

### 6. `anomalies`
Log of detected passive environment anomalies (WHAT, WHEN, WHICH BSSID, evidence, explanation).

---

## Schema Migration Safety
Migrations are handled incrementally in `storage/migrations.py`. Existing databases are altered (`ALTER TABLE`) without deleting scan history. Automated database backups are created before migration passes.
