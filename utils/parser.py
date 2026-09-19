import re
from typing import Optional, List, Dict, Any
from models.network import Network


def signal_to_dbm(signal_percent: int) -> int:
    """
    Provides an estimated RSSI value (dBm) from Windows signal percentage.
    Formula: Estimated RSSI = -100 + (signal_percent * 0.5)
    """
    clamped = max(0, min(100, signal_percent))
    return int(-100 + (clamped * 0.5))


def get_frequency(channel: Optional[int], band_str: str = "") -> str:
    """
    Converts Wi-Fi channel or band string into a frequency band label.
    Supports 2.4 GHz, 5 GHz, and Unknown.
    """
    if "2.4" in band_str:
        return "2.4 GHz"
    if "5" in band_str:
        return "5 GHz"

    if channel is None:
        return "Unknown"

    if 1 <= channel <= 14:
        return "2.4 GHz"
    if 32 <= channel <= 177:
        return "5 GHz"

    return "Unknown"


def normalize_security(authentication: str, encryption: str) -> str:
    """
    Normalizes Windows authentication string into a standardized security label.
    """
    auth = authentication.upper()
    enc = encryption.upper()

    if "WPA3" in auth:
        return "WPA3"
    if "WPA2" in auth:
        return "WPA2"
    if "WPA" in auth:
        return "WPA"
    if "WEP" in auth:
        return "WEP"
    if "OPEN" in auth or enc == "NONE":
        return "OPEN"
    return "UNKNOWN"


def parse_networks(raw_data: str) -> List[Network]:
    """
    Parses raw text output from 'netsh wlan show networks mode=bssid'
    and returns a list of Network dataclass objects (one per BSSID).
    """
    networks: List[Network] = []

    current_ssid: Optional[str] = None
    current_authentication: str = "Unknown"
    current_encryption: str = "Unknown"

    current_bssid: Optional[str] = None
    current_signal: int = 0
    current_channel: Optional[int] = None
    current_radio: str = "Unknown"
    current_band: str = ""

    def save_current_network():
        nonlocal current_bssid, current_signal, current_channel, current_radio, current_band

        if current_ssid is None or current_bssid is None:
            return

        sec_label = normalize_security(current_authentication, current_encryption)
        band_label = get_frequency(current_channel, current_band)
        estimated_rssi = signal_to_dbm(current_signal)

        network = Network(
            ssid=current_ssid,
            bssid=current_bssid,
            signal_percent=current_signal,
            signal_dbm=estimated_rssi,
            channel=current_channel,
            band=band_label,
            security=sec_label,
            encryption=current_encryption if current_encryption else "Unknown",
            radio_type=current_radio if current_radio else "Unknown"
        )
        networks.append(network)

        current_bssid = None
        current_signal = 0
        current_channel = None
        current_radio = "Unknown"
        current_band = ""

    lines = raw_data.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # SSID header (e.g. "SSID 1 : HomeWiFi" or "SSID 2 : ")
        ssid_match = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", stripped, re.IGNORECASE)
        if ssid_match:
            save_current_network()
            raw_ssid = ssid_match.group(1).strip()
            current_ssid = raw_ssid if raw_ssid else "<Hidden Network>"
            current_authentication = "Unknown"
            current_encryption = "Unknown"
            continue

        # Authentication
        auth_match = re.match(r"^Authentication\s*:\s*(.*)$", stripped, re.IGNORECASE)
        if auth_match:
            current_authentication = auth_match.group(1).strip() or "Unknown"
            continue

        # Encryption / Cipher
        enc_match = re.match(r"^(?:Encryption|Cipher)\s*:\s*(.*)$", stripped, re.IGNORECASE)
        if enc_match:
            current_encryption = enc_match.group(1).strip() or "Unknown"
            continue

        # BSSID header (e.g. "BSSID 1 : AA:BB:CC:DD:EE:FF")
        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*([0-9A-Fa-f:-]+)$", stripped, re.IGNORECASE)
        if bssid_match:
            save_current_network()
            current_bssid = bssid_match.group(1).upper()
            continue

        # Signal percentage
        signal_match = re.match(r"^Signal\s*:\s*(\d+)%?$", stripped, re.IGNORECASE)
        if signal_match:
            current_signal = int(signal_match.group(1))
            continue

        # Radio type
        radio_match = re.match(r"^Radio type\s*:\s*(.*)$", stripped, re.IGNORECASE)
        if radio_match:
            current_radio = radio_match.group(1).strip() or "Unknown"
            continue

        # Band
        band_match = re.match(r"^Band\s*:\s*(.*)$", stripped, re.IGNORECASE)
        if band_match:
            current_band = band_match.group(1).strip()
            continue

        # Channel
        channel_match = re.match(r"^Channel\s*:\s*(\d+)$", stripped, re.IGNORECASE)
        if channel_match:
            current_channel = int(channel_match.group(1))
            continue

    save_current_network()
    return networks


def parse_interface(raw_data: str) -> Dict[str, Any]:
    """
    Parses raw text output from 'netsh wlan show interfaces'
    and returns a dictionary containing adapter information.
    """
    info = {
        "name": "Unknown",
        "description": "Unknown",
        "state": "Unknown",
        "ssid": "Not Connected",
        "bssid": "N/A",
        "channel": None,
        "signal_percent": None,
        "radio_type": "Unknown",
        "band": "Unknown"
    }

    lines = raw_data.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped or ":" not in stripped:
            continue

        parts = stripped.split(":", 1)
        key = parts[0].strip().lower()
        val = parts[1].strip()

        if key in ("name", "interface name"):
            info["name"] = val
        elif key == "description":
            info["description"] = val
        elif key == "state":
            info["state"] = val
        elif key == "ssid":
            info["ssid"] = val if val else "Not Connected"
        elif key in ("ap bssid", "bssid"):
            info["bssid"] = val.upper() if val else "N/A"
        elif key == "channel":
            if val.isdigit():
                info["channel"] = int(val)
        elif key == "signal":
            val_clean = val.replace("%", "").strip()
            if val_clean.isdigit():
                info["signal_percent"] = int(val_clean)
        elif key == "radio type":
            info["radio_type"] = val
        elif key == "band":
            info["band"] = val

    if info["channel"] is not None and info["band"] == "Unknown":
        info["band"] = get_frequency(info["channel"])

    return info