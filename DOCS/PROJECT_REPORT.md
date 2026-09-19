# Project Technical Report

# Wi-Fi Security Intelligence & Wireless-Environment Intelligence Platform

---

## Abstract

This report documents the architectural design, implementation methodology, and security algorithms of the **Wi-Fi Security Intelligence & Monitoring Platform**. Built upon Python 3.11+, SQLite 3, and Tkinter/ttk, the application provides passive wireless network discovery, multi-factor heuristic risk scoring, three-state network lifecycle tracking, passive anomaly detection, environment baseline deviation monitoring, and executive security reporting.

---

## 1. Problem Statement & Objectives

Wireless local area networks (WLANs) are exposed to passive environment shifts, security configuration changes, and unauthorized network appearances. The objective of this project is to develop an enterprise-grade, 100% passive, local-first defensive wireless intelligence platform that monitors wireless environments without engaging in active probing, packet injection, or offensive operations.

---

## 2. System Architecture & Methodology

The system is structured in six modular tiers:
1. **Acquisition**: OS WLAN command wrapper (`netsh wlan show networks mode=bssid`).
2. **Parsing & Normalization**: Regular expression parser converting raw text to normalized dataclasses (`Network`).
3. **Storage & Persistence**: SQLite database with schema migrations, repositories, and automated timestamped backups.
4. **Monitoring & Lifecycle**: Three-state network tracking (`ACTIVE`, `TEMPORARILY_MISSING`, `NOT_DETECTED`) with threshold debouncing.
5. **Security & Anomaly Engines**: Deterministic multi-factor risk scoring (0-100) and passive anomaly detection across 8 observation indicators.
6. **Presentation & Reporting**: Sidebar-navigated Tkinter GUI, HTML executive reports, and CSV/JSON exports.

---

## 3. Mathematical & Algorithmic Models

### 3.1 Signal to Estimated RSSI Formula
$$\text{Estimated RSSI (dBm)} = -100 + (\text{Signal Percentage} \times 0.5)$$

### 3.2 Heuristic Risk Score Model
$$R = S_{\text{protocol}} + C_{\text{cipher}} + \sum M_{\text{behavioral}}$$
Where $R$ is clamped to $[0, 100]$.

---

## 4. Results & Verification

- **Unit Testing**: 100% test pass rate across 35 unit test cases covering parser, risk engine, anomaly detector, channel analyzer, signal metrics, and database migrations.
- **Performance**: Sub-second scan processing and GUI responsiveness with 100+ BSSIDs and 10,000+ historical observations.
- **Privacy**: Local-first architecture; zero external network transmissions or credential collection.

---

## 5. Conclusion & Scope Limitations

The platform achieves comprehensive defensive Wi-Fi monitoring. All observations remain passive metrics, explicitly adhering to defensive cybersecurity guidelines.
