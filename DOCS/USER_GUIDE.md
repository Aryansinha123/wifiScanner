# Wi-Fi Security Platform - User Guide

## User Manual & Operating Instructions

---

## 1. Quick Start

To launch the application GUI:
```bash
python main.py
```

---

## 2. Main Navigation & Workflow

The application interface is navigated using the sidebar panel:

- **Dashboard**: High-level overview of active networks, security protocol distribution, baseline status, and recent security alerts.
- **Live Scanner**: Perform manual Wi-Fi scans or toggle Auto-Refresh (30s). View network lists with signal strength, estimated RSSI, channel, frequency band, encryption, MAC vendor, and risk level.
- **Security Monitor**: Standalone or integrated real-time monitoring window tracking state transitions and security changes.
- **Events**: Historical event log and timeline viewer with search, filtering by severity/type, and event acknowledgment.
- **Analytics**: Channel density breakdown for 2.4 GHz and 5 GHz bands, signal statistics (min/max/avg/std dev), and channel recommendations.
- **Baseline**: Snapshot normal wireless environment baselines and monitor for baseline deviations.
- **Reports**: Generate styled HTML executive security reports, CSV dataset exports, and JSON archives.
- **Database**: Monitor database metrics, create timestamped backups, and safely restore database snapshots.
- **Settings**: Configure scan intervals, missing scan thresholds, signal thresholds, and toggle Offline Simulation Mode.
- **Diagnostics**: Run system diagnostic health checks on Python, OS, WLAN adapter, and SQLite database.

---

## 3. Establishing an Environment Baseline

1. Perform 2-3 Wi-Fi scans in your normal operating environment.
2. Navigate to the **Baseline** section in the sidebar.
3. Click **Create New Baseline** and enter a baseline name.
4. The system snapshots all active access points. Subsequent scan passes automatically evaluate deviations against this active baseline.

---

## 4. Offline Simulation Mode

For development, testing, or demonstrations without relying on physical Wi-Fi changes:
1. Open **Settings**.
2. Check **Enable Offline Simulation Mode**.
3. Scan passes will generate synthetic scenarios (stable environment, new network, security downgrade, channel shift, baseline deviation).
