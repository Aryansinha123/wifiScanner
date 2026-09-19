# System Architecture Specification

## Wi-Fi Security Intelligence & Monitoring Platform

```
                    GUI (Tkinter / ttk Multi-Window Navigation)
                                       │
                              Application Controller
                                       │
       ┌───────────────────────────────┼───────────────────────────────┐
       │                               │                               │
 Scanning Engine              Monitoring Pipeline              Analytics Engine
(Windows netsh/Adapters)     (State & Baseline Mgr)        (Signal, Channel, Trends)
       │                               │                               │
       └───────────────────────────────┼───────────────────────────────┘
                                       │
                             Security Engine (Risk & Anomaly)
                                       │
       ┌───────────────────────────────┼───────────────────────────────┐
       │                               │                               │
Heuristic Risk Engine           Passive Anomaly Engine          Suspicious Pattern Detector
(Explainable Score 0-100)      (8 Anomaly Indicators)            (Correlated Indicators)
       │                               │                               │
       └───────────────────────────────┼───────────────────────────────┘
                                       │
                            Storage & Data Layer
                                       │
                      SQLite Engine (Migrations & Repositories)
                                       │
                          Historical Data & Reporting
```

## Architectural Layers

1. **Acquisition & Scanning Layer** (`scanner/`, `parser/`):
   - Executes non-invasive OS commands (`netsh wlan show interfaces`, `netsh wlan show networks mode=bssid`).
   - Parses raw stdout with resilient regex patterns handling localized whitespace and hidden SSIDs.
   - Converts signal percentages to estimated RSSI (dBm).

2. **Monitoring & Baseline Layer** (`monitoring/`):
   - Tracks network state transitions across scan passes (`ACTIVE`, `TEMPORARILY_MISSING`, `NOT_DETECTED`).
   - Debounces disappearances using a configurable missing scan threshold (default: 3 scans).
   - Manages environment baselines and evaluates baseline deviation events.

3. **Analytics & Intelligence Layer** (`analytics/`, `intelligence/`):
   - Computes channel density for 2.4 GHz and 5 GHz frequency bands.
   - Performs signal statistics (min, max, avg, standard deviation).
   - Resolves MAC OUI vendors using an embedded IEEE OUI dictionary.
   - Builds detailed BSSID and multi-BSSID SSID profiles.

4. **Security & Anomaly Layer** (`security/`):
   - Evaluates multi-factor heuristic risk scores (0-100) with explainable breakdowns.
   - Detects 8 passive anomaly types (security downgrades, channel jumps, signal anomalies, baseline deviations).
   - Correlates multi-indicator security patterns.

5. **Storage Layer** (`storage/`):
   - Manages SQLite persistence, schema migrations (`storage/migrations.py`), timestamped backups (`storage/backup.py`), and repositories (`storage/repositories.py`).

6. **User Interface & Reporting Layer** (`gui/`, `reports/`):
   - Modular desktop GUI with sidebar navigation.
   - Standalone executive HTML report generator, CSV, and JSON data exports.
