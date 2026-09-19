# Wi-Fi Security Intelligence & Monitoring Platform

A defensive, feature-rich Wi-Fi security monitoring and wireless-environment intelligence platform built in Python 3.11+, SQLite 3, and Tkinter/ttk.

![Defensive Scope](https://img.shields.io/badge/Scope-100%25%20Passive%20%26%20Defensive-blue)
![Python Version](https://img.shields.io/badge/Python-3.11%2B-green)
![Database](https://img.shields.io/badge/Storage-SQLite3-sqlite)
![License](https://img.shields.io/badge/License-MIT-brightgreen)

---

## Key Features

- **Passive Wi-Fi Discovery**: Scans 2.4 GHz and 5 GHz wireless networks using Windows WLAN APIs (`netsh wlan show networks mode=bssid`).
- **Multi-Factor Heuristic Risk Engine**: Calculates explainable 0–100 risk scores and risk levels (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) based on protocol, cipher strength, security changes, and behavioral anomalies.
- **Three-State Network Lifecycle Tracking**: Tracks BSSID states (`ACTIVE`, `TEMPORARILY_MISSING`, `NOT_DETECTED`) with threshold debouncing (default: 3 scans).
- **Environment Baseline System**: Snapshot expected wireless environments and receive `BASELINE_DEVIATION` alerts when unseen networks or configuration shifts occur.
- **Passive Anomaly Detection Engine**: Detects 8 observation anomaly patterns (security downgrades, channel shifts, signal fluctuations, baseline deviations) with explainable evidence.
- **Offline MAC OUI Vendor Lookup**: Resolves network hardware vendors locally using an embedded IEEE OUI database.
- **Channel & Signal Intelligence**: Evaluates channel density, 2.4 GHz vs 5 GHz distribution, RSSI estimations, and signal statistics.
- **Executive Security Reports**: Generates styled HTML executive reports, CSV data exports, and JSON archives.
- **Database Management & Migrations**: Automated SQLite schema migrations, timestamped database backups, and safe restore controls.
- **Offline Simulation & Demo Mode**: Test security monitoring scenarios (new networks, security downgrades, channel hops) without physical Wi-Fi changes.
- **Modern Sidebar GUI**: Intuitive navigation connecting Dashboard, Live Scanner, Security Monitor, History, Events, Analytics, Baseline, Reports, Database, Settings, and Diagnostics.

---

## Security Scope & Philosophy

This is a **DEFENSIVE and PASSIVE** monitoring application.

### The application MAY:
- Discover nearby Wi-Fi networks using normal OS WLAN scanning.
- Analyze wireless configurations and signal behavior.
- Maintain historical records and detect anomalies.
- Generate security assessments and reports.

### The application MUST NOT:
- Perform deauthentication or packet injection.
- Capture WPA handshakes or crack passwords.
- Attempt unauthorized authentication or automatic connections.
- Intercept traffic or perform offensive operations.

---

## Installation & Setup

1. **Prerequisites**: Windows 10/11, Python 3.11+
2. **Clone / Navigate**:
   ```bash
   cd WifiScanner
   ```
3. **Run Application**:
   ```bash
   python main.py
   ```
4. **Run Test Suite**:
   ```bash
   python -m unittest discover tests
   ```

---

## Architecture Overview

```
wifi-security-platform/
├── main.py
├── config.json
├── data/
│   ├── wifi_scanner.db
│   ├── backups/
│   └── reports/
├── models/
│   ├── network.py, scan.py, event.py, observation.py, baseline.py, anomaly.py
├── scanner/
│   ├── windows_scanner.py, scanner_manager.py, adapter_manager.py, scan_scheduler.py
├── parser/
│   ├── netsh_parser.py, normalizer.py, validators.py
├── storage/
│   ├── database.py, repositories.py, migrations.py, backup.py
├── security/
│   ├── analyzer.py, risk_engine.py, security_rules.py, configuration_analyzer.py
├── monitoring/
│   ├── change_detector.py, state_manager.py, event_manager.py, baseline_manager.py, scheduler.py
├── analytics/
│   ├── channel_analyzer.py, signal_analyzer.py, anomaly_detector.py
├── intelligence/
│   ├── bssid_analyzer.py, ssid_analyzer.py, vendor_analyzer.py, environment_profiler.py, pattern_detector.py
├── reports/
│   ├── report_generator.py, csv_report.py, html_report.py
├── gui/
│   ├── main_window.py, dashboard.py, baseline_window.py, analytics_window.py, events_window.py...
├── docs/
│   ├── ARCHITECTURE.md, DATABASE.md, SECURITY_MODEL.md, USER_GUIDE.md, PROJECT_REPORT.md
└── tests/
    ├── test_parser.py, test_security.py, test_database.py, test_risk.py, test_anomaly.py, test_analytics.py
```

---

## Documentation

Detailed documentation is available in the `docs/` directory:
- [Architecture Reference](docs/ARCHITECTURE.md)
- [Database Schema Reference](docs/DATABASE.md)
- [Defensive Security Model](docs/SECURITY_MODEL.md)
- [User Manual Guide](docs/USER_GUIDE.md)
- [Academic Project Report](docs/PROJECT_REPORT.md)

---

## License

MIT License. Designed for defensive cybersecurity research, network administration, and educational wireless environment intelligence.
