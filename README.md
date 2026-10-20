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

## Top 5 Features, Explained

### 1. Evil Twin / Rogue AP Detection

- **What it is**: An attacker creates a fake Wi-Fi network with the same name as a real one (e.g. `VIT-Campus` or `HomeWiFi`) so people connect to it and get spied on.
- **How it works**: For every SSID you trust, you store its known BSSIDs, vendor, security type, and channel in the `trusted_networks` table. On each scan, the tool compares what it sees against that record.
- **Example Scenario**:
  - *Trusted*: `HomeWiFi`, BSSID `00:19:E0:11:22:33`, WPA2, channel 6
  - *Seen now*: `HomeWiFi`, BSSID `DE:AD:BE:EF:00:01`, Open, channel 11
  - *Result*: **CRITICAL alert**, `“Potential Evil Twin: Same SSID 'HomeWiFi', unknown BSSID DE:AD:BE:EF:00:01, security downgraded WPA2 -> Open”`
- **Explainable Evidence Scoring**:

| Evidence | Points | Description |
| :--- | :--- | :--- |
| Same SSID, BSSID not in trusted list | **+40** | Unknown access point impersonating a trusted network name |
| Security weaker than trusted version | **+30** | Security downgraded (e.g. WPA2 $\rightarrow$ Open) |
| Different vendor (OUI) | **+15** | Hardware MAC OUI vendor mismatch against trusted AP |
| Different channel | **+5** | AP transmitting on an unexpected channel |
| Locally administered (fake-looking) MAC | **+10** | IEEE 802 randomized or spoofed MAC address detected |

- **What was added**: A `trusted_networks` table (`id`, `ssid`, `bssid`, `vendor`, `security`, `channel`, `added_at`, `notes`) and a button on the Baseline page, **⭐ Mark Selected as Trusted**, as well as in the Network Details modal.

---

### 2. Real-Time Alerts

- **What it is**: The tool tells you when something bad happens instead of waiting for you to open it.
- **Channels**:
  - **Windows toast notification**: Works 100% offline via native PowerShell WinRT API.
  - **Telegram bot or email**: Notifies you remotely when you're away from your computer.
- **What makes it good, not annoying**:
  - **Deduplication**: The same alert for the same BSSID isn't sent twice.
  - **Cooldown**: One alert per event type per BSSID per 30 minutes (configurable in Settings).
  - **Severity threshold**: Choose between `CRITICAL Only`, `HIGH & CRITICAL`, `MEDIUM`, or `ALL`.
  - **Acknowledge button**: Marks an alert as seen in the Events & Alerts tab and permanently stops repeats.
- **What was added**: An `alerts` table (`id`, `alert_type`, `severity`, `bssid`, `ssid`, `message`, `status`, `created_at`, `last_sent_at`, `acknowledged`), an Alert Manager engine, and a **Settings** page for the threshold, cooldown, and notification channels.

---

### 3. Weak-Configuration Checks

- **What it is**: The tool flags networks that are insecure by design, even if nothing suspicious is happening.
- **What netsh can detect**:
  - **Open networks** (no password) (+85 points, CRITICAL)
  - **WEP encryption** (broken or outdated) (+75 points, HIGH)
  - **Legacy WPA** instead of WPA2/WPA3 (+35 points, MEDIUM)
  - **TKIP cipher** (deprecated) (+20 points, MEDIUM)
  - **Hidden SSIDs** (+15 points, LOW)
  - **Default router names** like `TP-Link_4F2A`, `JioFiber-xxxx`, `D-Link_xxxx`, `NETGEARxx`, `Tenda_xxxx`, etc., which often come with predictable passwords (+15 points, LOW)
- **Important limitation**: WPS and PMF (802.11w) are not exposed by the Windows `netsh` API. Detecting them requires parsing raw beacon frames (Scapy plus a monitor-mode adapter). These are treated as advanced monitor-mode modules and are not promised in the core netsh scanner.
- **What was added**: A `weak_config_rules` list in the risk engine and configuration analyzer, each rule returning a score and a human-readable reason, such as `“TKIP cipher is deprecated (+20)”`.

---

### 4. Channel Recommendation Engine

- **What it is**: It tells the user which channel to switch their router to for optimal performance and minimal interference.
- **How it works**:
  - On **2.4 GHz**, channels overlap, so only 1, 6, and 11 are truly separate. For each of those, the tool counts the networks on it (co-channel) and its overlapping neighbors (adjacent channels), weighted by signal strength:
    $$\text{Congestion Score} = \sum \text{Signal}_{\text{co-channel}} + 0.7 \times \sum \text{Signal}_{\text{adjacent}}$$
  - On **5 GHz**, it counts networks per channel and prefers the emptier, lowest-congestion channel.
  - The lowest congestion score wins.
- **Example output**: `“Channel 6 has 9 networks (very crowded). Channel 11 has 2. Recommended: Channel 11.”`
- **What was added**: A dedicated card on the **Analytics** page with a bar chart of congestion per channel and a highlighted recommendation badge for both 2.4 GHz and 5 GHz bands.

---

### 5. Connection Integrity Monitor

- **What it is**: It protects the network you’re actually connected to, not just the ambient ones around you.
- **Checks**:
  - **ARP spoofing**: Records the default gateway’s MAC address (`arp -a`). If it suddenly changes on the same SSID, an alert is triggered: someone may be intercepting your traffic via a Man-In-The-Middle (MITM) attack.
  - **DNS hijacking**: Resolves a few known canary domains (`google.com`, `cloudflare.com`, `wikipedia.org`) using your system DNS and compares the answers against trusted DNS-over-HTTPS (DoH) servers (Cloudflare `1.1.1.1` and Google DoH). If the answers differ or point to loopback/private RFC1918 IPs, your DNS is tampered with.
  - **Gateway change**: Alerts if the default gateway IP or MAC changes on the same SSID.
- **What was added**: A **“Connection Health”** panel on the **Dashboard** showing Gateway MAC (`Stable` / `Changed`), DNS (`Consistent` / `Mismatch`), and Status (`Safe` / `Warning` / `Critical`), along with an on-demand **Check Connection Health** button.

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
│   ├── evil_twin_detector.py, weak_config_rules.py, analyzer.py, risk_engine.py, security_rules.py, configuration_analyzer.py
├── monitoring/
│   ├── alert_manager.py, connection_integrity.py, change_detector.py, state_manager.py, event_manager.py, baseline_manager.py, scheduler.py
├── analytics/
│   ├── channel_analyzer.py, signal_analyzer.py, anomaly_detector.py
├── intelligence/
│   ├── bssid_analyzer.py, ssid_analyzer.py, vendor_analyzer.py, environment_profiler.py, pattern_detector.py
├── reports/
│   ├── report_generator.py, csv_report.py, html_report.py
├── gui/
│   ├── main_window.py, dashboard.py, baseline_window.py, analytics_window.py, events_window.py, settings_window.py, network_details.py...
├── docs/
│   ├── ARCHITECTURE.md, DATABASE.md, SECURITY_MODEL.md, USER_GUIDE.md, PROJECT_REPORT.md
└── tests/
    ├── test_evil_twin.py, test_alerts.py, test_weak_config.py, test_channel_recommendation.py, test_connection_integrity.py, test_parser.py, test_analyzer.py, test_database.py, test_risk.py, test_anomaly.py, test_analytics.py
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
