# Defensive Security Model & Risk Engine Specification

## Passive Monitoring Philosophy

This application is strictly **100% defensive and passive**.
It operates exclusively using standard OS WLAN discovery commands (`netsh wlan show networks mode=bssid`).
It does NOT perform packet injection, deauthentication, handshake capturing, password cracking, or active network probing.

---

## Multi-Factor Heuristic Risk Model

Risk scores (0–100) are computed deterministically from observable configuration attributes and behavioral changes:

```
Final Risk Score = Base Protocol Score + Cipher Modifiers + Behavioral Modifiers
```

### 1. Base Security Protocol Score
- WPA3: +0 points
- WPA2: +10 points
- WPA1: +35 points
- WEP: +75 points
- OPEN: +85 points
- UNKNOWN: +40 points

### 2. Cipher Modifiers
- Unencrypted (NONE): +15 points
- Deprecated TKIP: +20 points
- Deprecated WEP cipher: +15 points

### 3. Behavioral & Observational Modifiers
- Security Downgrade observed: +30 points
- Baseline Deviation detected: +20 points
- BSSID/SSID Anomaly: +15 points
- Unexpected Channel Shift: +10 points
- Large Signal Fluctuation: +10 points

### Risk Level Classifications
- `0 - 20`: LOW
- `21 - 45`: MEDIUM
- `46 - 70`: HIGH
- `71 - 100`: CRITICAL

---

## Passive Anomaly Detection Engine

Detects 8 key environment anomaly patterns:
1. `SUDDEN_SECURITY_DOWNGRADE`
2. `UNUSUAL_CHANNEL_SHIFT`
3. `UNUSUAL_SSID_BSSID_RELATIONSHIP`
4. `RAPID_STATE_TRANSITIONS`
5. `UNEXPECTED_SECURITY_PROTOCOL`
6. `LARGE_SIGNAL_DEVIATION`
7. `UNUSUAL_BSSID_COUNT_FOR_SSID`
8. `NEW_NETWORK_IN_STABLE_ENV`

Every anomaly finding includes:
- **WHAT** was observed
- **WHEN** detected
- **WHICH** BSSID/SSID
- **EVIDENCE** observed
- **WHY** flagged

---

## Explicit Security Limitations & Disclaimer

1. Passive observation cannot determine whether an access point is malicious with certainty.
2. An unfamiliar SSID or BSSID is not proof of attack activity.
3. A security configuration change does not prove router compromise.
4. Signal fluctuations reflect environmental changes and distance, not proof of rogue device movement.
5. All risk scores and anomaly findings represent passive visibility metrics intended for defensive monitoring and administration.
