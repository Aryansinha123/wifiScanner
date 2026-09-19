import logging
from typing import List, Dict, Any, Optional
from models.network import Network

logger = logging.getLogger(__name__)

SECURITY_RANKS = {
    "WPA3": 4,
    "WPA2": 3,
    "WPA": 2,
    "WEP": 1,
    "OPEN": 0,
    "UNKNOWN": 0
}

# A BSSID must be absent from this many consecutive scans
# before a NETWORK_NOT_DETECTED event is generated.
NETWORK_MISSING_THRESHOLD = 3


def detect_changes(
    previous_states: Dict[str, Dict[str, Any]],
    current_networks: List[Network],
    timestamp: str
) -> List[Dict[str, Any]]:
    """
    Compares previous network states with current scan networks
    and returns a list of detected event dictionaries.

    Uses a three-state model with debounce:
        ACTIVE → TEMPORARILY_MISSING → NOT_DETECTED

    A BSSID must be absent from NETWORK_MISSING_THRESHOLD consecutive
    scans before a NETWORK_NOT_DETECTED event is emitted.
    NETWORK_REAPPEARED is only emitted when transitioning from confirmed
    NOT_DETECTED (is_active=0) back to present.
    """
    events: List[Dict[str, Any]] = []

    current_map: Dict[str, Network] = {n.bssid: n for n in current_networks}
    current_bssids = set(current_map.keys())
    previous_bssids = set(previous_states.keys())

    # 1. Detect New Networks & State Changes for Present BSSIDs
    for bssid, net in current_map.items():
        if bssid not in previous_bssids:
            # NEW NETWORK — never seen before
            events.append({
                "event_type": "NEW_NETWORK",
                "severity": "INFO",
                "ssid": net.ssid,
                "bssid": bssid,
                "description": "New wireless access point detected.",
                "old_value": "N/A",
                "new_value": f"Security: {net.security}, Channel: {net.channel}",
                "timestamp": timestamp
            })
        else:
            prev = previous_states[bssid]
            was_active = bool(prev.get("is_active", 1))

            # REAPPEARED NETWORK — only from confirmed NOT_DETECTED (is_active=0)
            if not was_active:
                events.append({
                    "event_type": "NETWORK_REAPPEARED",
                    "severity": "INFO",
                    "ssid": net.ssid,
                    "bssid": bssid,
                    "description": "Wireless access point reappeared in scan.",
                    "old_value": "Not Detected",
                    "new_value": f"Signal: {net.signal_percent}%",
                    "timestamp": timestamp
                })
            # Note: TEMPORARILY_MISSING (is_active=1, missed>0) returning
            # does NOT generate a NETWORK_REAPPEARED event — silent reset.

            # SSID CHANGE
            old_ssid = prev.get("ssid") or "<Hidden Network>"
            if old_ssid != net.ssid:
                events.append({
                    "event_type": "SSID_CHANGE",
                    "severity": "MEDIUM",
                    "ssid": net.ssid,
                    "bssid": bssid,
                    "description": "SSID change observed for BSSID.",
                    "old_value": old_ssid,
                    "new_value": net.ssid,
                    "timestamp": timestamp
                })

            # SECURITY CHANGES & DOWNGRADE / UPGRADE
            old_sec = (prev.get("last_security") or "UNKNOWN").upper()
            new_sec = net.security.upper()
            old_enc = prev.get("last_encryption") or "Unknown"
            new_enc = net.encryption

            if old_sec != new_sec or old_enc.upper() != new_enc.upper():
                old_val_str = f"{old_sec} / {old_enc}"
                new_val_str = f"{new_sec} / {new_enc}"

                old_rank = SECURITY_RANKS.get(old_sec, 0)
                new_rank = SECURITY_RANKS.get(new_sec, 0)

                if new_rank < old_rank:
                    events.append({
                        "event_type": "SECURITY_DOWNGRADE",
                        "severity": "HIGH",
                        "ssid": net.ssid,
                        "bssid": bssid,
                        "description": "Wireless security configuration downgrade observed.",
                        "old_value": old_val_str,
                        "new_value": new_val_str,
                        "timestamp": timestamp
                    })
                elif new_rank > old_rank:
                    events.append({
                        "event_type": "SECURITY_UPGRADE",
                        "severity": "INFO",
                        "ssid": net.ssid,
                        "bssid": bssid,
                        "description": "Wireless security configuration improved.",
                        "old_value": old_val_str,
                        "new_value": new_val_str,
                        "timestamp": timestamp
                    })
                else:
                    events.append({
                        "event_type": "SECURITY_CHANGE",
                        "severity": "MEDIUM",
                        "ssid": net.ssid,
                        "bssid": bssid,
                        "description": "Wireless security configuration changed.",
                        "old_value": old_val_str,
                        "new_value": new_val_str,
                        "timestamp": timestamp
                    })

            # CHANNEL CHANGE
            old_ch = prev.get("last_channel")
            if old_ch is not None and net.channel is not None and old_ch != net.channel:
                events.append({
                    "event_type": "CHANNEL_CHANGE",
                    "severity": "INFO",
                    "ssid": net.ssid,
                    "bssid": bssid,
                    "description": "Channel change detected.",
                    "old_value": str(old_ch),
                    "new_value": str(net.channel),
                    "timestamp": timestamp
                })

            # SIGNAL CHANGE (>= 20 percentage points)
            old_sig = prev.get("last_signal")
            if old_sig is not None and abs(net.signal_percent - old_sig) >= 20:
                events.append({
                    "event_type": "SIGNAL_CHANGE",
                    "severity": "INFO",
                    "ssid": net.ssid,
                    "bssid": bssid,
                    "description": "Significant signal change detected.",
                    "old_value": f"{old_sig}%",
                    "new_value": f"{net.signal_percent}%",
                    "timestamp": timestamp
                })

    # 2. Detect Confirmed Disappearances (threshold-based)
    for bssid, prev in previous_states.items():
        if bssid not in current_bssids:
            was_active = bool(prev.get("is_active", 1))
            if not was_active:
                # Already confirmed NOT_DETECTED — no duplicate event
                continue

            # Check if this scan crosses the missed-scan threshold
            prev_missed = prev.get("consecutive_missed_scans", 0)
            new_missed = prev_missed + 1

            if new_missed >= NETWORK_MISSING_THRESHOLD:
                # Threshold crossed — generate NETWORK_NOT_DETECTED exactly once
                events.append({
                    "event_type": "NETWORK_NOT_DETECTED",
                    "severity": "INFO",
                    "ssid": prev.get("ssid") or "<Hidden Network>",
                    "bssid": bssid,
                    "description": f"Network was not detected for {new_missed} consecutive scans.",
                    "old_value": "Active",
                    "new_value": "Not Detected",
                    "timestamp": timestamp
                })
            # else: TEMPORARILY_MISSING — no event yet

    return events
