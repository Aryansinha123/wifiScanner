import re

from models.network import Network


def signal_to_dbm(signal_percent: int) -> int:
    """
    Provides a rough estimated RSSI value from
    Windows signal percentage.

    This is an estimate, not a direct measurement.
    """

    signal_percent = max(0, min(100, signal_percent))

    return int(-100 + (signal_percent * 0.5))


def get_frequency(channel):
    """
    Converts a Wi-Fi channel into a frequency band.
    """

    if channel is None:
        return "Unknown"

    # 2.4 GHz
    if 1 <= channel <= 14:
        return "2.4 GHz"

    # 5 GHz
    if 32 <= channel <= 177:
        return "5 GHz"

    # 6 GHz
    if 1 <= channel <= 233:
        return "6 GHz"

    return "Unknown"


def normalize_security(authentication: str, encryption: str) -> str:
    """
    Converts Windows authentication information
    into a simple security label.
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


def parse_networks(raw_data: str) -> list[Network]:
    """
    Parses output from:

    netsh wlan show networks mode=bssid

    and returns a list of Network objects.
    """

    networks = []

    current_ssid = None
    current_authentication = ""
    current_encryption = ""

    current_bssid = None
    current_signal = 0
    current_channel = None
    current_radio = ""

    def save_current_network():
        nonlocal current_bssid
        nonlocal current_signal
        nonlocal current_channel
        nonlocal current_radio

        if current_ssid is None or current_bssid is None:
            return

        security = normalize_security(
            current_authentication,
            current_encryption
        )

        frequency = get_frequency(current_channel)

        signal_dbm = signal_to_dbm(
            current_signal
        )

        network = Network(
            ssid=current_ssid,
            bssid=current_bssid,
            signal_percent=current_signal,
            signal_dbm=signal_dbm,
            channel=current_channel,
            frequency=frequency,
            security=security,
            encryption=current_encryption,
            radio_type=current_radio
        )

        networks.append(network)

        current_bssid = None
        current_signal = 0
        current_channel = None
        current_radio = ""

    lines = raw_data.splitlines()

    for line in lines:

        stripped = line.strip()

        # New SSID
        ssid_match = re.match(
            r"^SSID\s+\d+\s*:\s*(.*)$",
            stripped,
            re.IGNORECASE
        )

        if ssid_match:

            save_current_network()

            current_ssid = ssid_match.group(1).strip()

            current_authentication = ""
            current_encryption = ""

            continue

        # Authentication
        auth_match = re.match(
            r"^Authentication\s*:\s*(.*)$",
            stripped,
            re.IGNORECASE
        )

        if auth_match:

            current_authentication = (
                auth_match.group(1).strip()
            )

            continue

        # Encryption
        encryption_match = re.match(
            r"^Encryption\s*:\s*(.*)$",
            stripped,
            re.IGNORECASE
        )

        if encryption_match:

            current_encryption = (
                encryption_match.group(1).strip()
            )

            continue

        # New BSSID
        bssid_match = re.match(
            r"^BSSID\s+\d+\s*:\s*([0-9A-Fa-f:-]+)$",
            stripped,
            re.IGNORECASE
        )

        if bssid_match:

            save_current_network()

            current_bssid = (
                bssid_match.group(1).upper()
            )

            continue

        # Signal
        signal_match = re.match(
            r"^Signal\s*:\s*(\d+)%$",
            stripped,
            re.IGNORECASE
        )

        if signal_match:

            current_signal = int(
                signal_match.group(1)
            )

            continue

        # Radio type
        radio_match = re.match(
            r"^Radio type\s*:\s*(.*)$",
            stripped,
            re.IGNORECASE
        )

        if radio_match:

            current_radio = (
                radio_match.group(1).strip()
            )

            continue

        # Channel
        channel_match = re.match(
            r"^Channel\s*:\s*(\d+)$",
            stripped,
            re.IGNORECASE
        )

        if channel_match:

            current_channel = int(
                channel_match.group(1)
            )

            continue

    # Save final network
    save_current_network()

    return networks