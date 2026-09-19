import re
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

# Embedded Local IEEE OUI Database for offline passive MAC lookup
# Format: 6-char hex prefix -> Vendor Name
LOCAL_OUI_DATABASE: Dict[str, str] = {
    "00000C": "Cisco Systems",
    "000142": "Cisco Systems",
    "00037F": "Atheros Communications",
    "00040E": "AVM GmbH",
    "00055D": "D-Link Corporation",
    "000740": "Cisco Systems",
    "00095B": "Netgear",
    "000B86": "Aruba Networks",
    "000C29": "VMware, Inc.",
    "000E08": "Cisco Systems",
    "000F66": "Cisco Systems",
    "001018": "Broadcom Corporation",
    "00112F": "Asustek Computer",
    "001217": "Cisco Systems",
    "001310": "Cisco Systems",
    "0013E8": "Intel Corporate",
    "001422": "Dell Inc.",
    "00146C": "Netgear",
    "0014BF": "Linksys",
    "00156D": "Ubiquiti Networks",
    "001601": "Cisco Systems",
    "0016B6": "Cisco Systems",
    "001735": "Linksys",
    "001788": "Philips Lighting",
    "001801": "Samsung Electronics",
    "00184D": "Netgear",
    "0018E7": "Cameo Communications",
    "0019A8": "Belkin International",
    "0019E0": "TP-Link Technologies",
    "001A11": "Google LLC",
    "001A2B": "Ayecom Technology",
    "001B11": "D-Link Corporation",
    "001B2F": "Netgear",
    "001B63": "Apple, Inc.",
    "001C10": "Cisco Systems",
    "001D7E": "Cisco Systems",
    "001E2A": "Netgear",
    "001E8C": "ASUSTeK Computer",
    "001F33": "Netgear",
    "001F9F": "Actiontec Electronics",
    "002129": "Cisco Systems",
    "00216A": "Intel Corporate",
    "00226B": "Cisco Systems",
    "002369": "Cisco Systems",
    "0024A5": "Buffalo Inc.",
    "0024B2": "Aruba Networks",
    "00259C": "Cisco Systems",
    "002644": "Lenovo",
    "00265A": "D-Link Corporation",
    "002686": "Cisco Systems",
    "002719": "TP-Link Technologies",
    "005056": "VMware, Inc.",
    "00CDFE": "Apple, Inc.",
    "00E04C": "Realtek Semiconductor",
    "0418D6": "Ubiquiti Networks",
    "0418B6": "TP-Link Technologies",
    "04D6AA": "Huawei Technologies",
    "080027": "Oracle VirtualBox",
    "08028E": "Cisco Systems",
    "0C8B7D": "Huawei Technologies",
    "0CB6D2": "Espressif Inc.",
    "100C6B": "Apple, Inc.",
    "10DA43": "Netgear",
    "142D27": "Apple, Inc.",
    "14CC20": "TP-Link Technologies",
    "180373": "TP-Link Technologies",
    "18A6F7": "TP-Link Technologies",
    "18E829": "Ubiquiti Networks",
    "1C151F": "Amazon Technologies",
    "1C7EE5": "D-Link Corporation",
    "1C965A": "Google LLC",
    "1CB72C": "Apple, Inc.",
    "203706": "Cisco Systems",
    "20AA4B": "Cisco Systems",
    "240588": "Espressif Inc.",
    "240AC4": "Espressif Inc.",
    "24A43C": "Ubiquiti Networks",
    "2816A8": "TP-Link Technologies",
    "282092": "Apple, Inc.",
    "286C07": "Xiaomi Communications",
    "2C3068": "Apple, Inc.",
    "2CF4C5": "Raspberry Pi Trading",
    "300ED5": "Apple, Inc.",
    "302303": "Belkin International",
    "3085A9": "ASUSTeK Computer",
    "3090AB": "Apple, Inc.",
    "342E86": "TP-Link Technologies",
    "3460F9": "TP-Link Technologies",
    "3810D5": "Apple, Inc.",
    "382C4A": "ASUSTeK Computer",
    "386077": "Google LLC",
    "3C7C3F": "Apple, Inc.",
    "3C846A": "TP-Link Technologies",
    "40169F": "TP-Link Technologies",
    "40313C": "Apple, Inc.",
    "44D9E7": "Ubiquiti Networks",
    "488D36": "Amazon Technologies",
    "4C5E0C": "Routerboard / MikroTik",
    "50642B": "TP-Link Technologies",
    "50C7BF": "TP-Link Technologies",
    "525400": "QEMU / KVM Virtual",
    "54B80A": "Ubiquiti Networks",
    "54E6FC": "TP-Link Technologies",
    "588B23": "Apple, Inc.",
    "5C5140": "Intel Corporate",
    "601466": "TP-Link Technologies",
    "6032B1": "TP-Link Technologies",
    "60A44C": "ASUSTeK Computer",
    "60E327": "TP-Link Technologies",
    "6466B3": "TP-Link Technologies",
    "647002": "TP-Link Technologies",
    "64D154": "Routerboard / MikroTik",
    "68FF7B": "Ubiquiti Networks",
    "704F57": "Ubiquiti Networks",
    "708105": "Ubiquiti Networks",
    "7483C2": "TP-Link Technologies",
    "74AC5C": "Ubiquiti Networks",
    "788A20": "Ubiquiti Networks",
    "788C54": "Netgear",
    "7C10C9": "Ubiquiti Networks",
    "7C8BCA": "Ubiquiti Networks",
    "802AA8": "Ubiquiti Networks",
    "8416F9": "TP-Link Technologies",
    "84D81B": "Apple, Inc.",
    "88D7F6": "TP-Link Technologies",
    "8C3BAD": "TP-Link Technologies",
    "8CDCD4": "TP-Link Technologies",
    "90A2DA": "Arduino SA",
    "90F652": "TP-Link Technologies",
    "94103E": "Belkin International",
    "944452": "Belkin International",
    "98DED0": "Raspberry Pi Trading",
    "A00460": "Netgear",
    "A42BB0": "Apple, Inc.",
    "A47B2C": "Google LLC",
    "B4FB24": "Espressif Inc.",
    "B827EB": "Raspberry Pi Foundation",
    "C025E9": "TP-Link Technologies",
    "C05627": "Belkin International",
    "C46E1F": "TP-Link Technologies",
    "C83A35": "Tenda Technology",
    "CC40D0": "Google LLC",
    "D807B6": "TP-Link Technologies",
    "D84732": "Apple, Inc.",
    "DC396F": "Apple, Inc.",
    "DC9FDB": "Espressif Inc.",
    "E063DA": "Atheros Communications",
    "E4956E": "Ubiquiti Networks",
    "E848B8": "TP-Link Technologies",
    "F09FC2": "Ubiquiti Networks",
    "F4F5E8": "TP-Link Technologies",
    "FCECDA": "Ubiquiti Networks",
}


def lookup_vendor(bssid: str) -> str:
    """
    Parses BSSID MAC address and returns matching vendor name from local OUI database.
    Does NOT require external API calls.
    """
    if not bssid:
        return "Unknown Vendor"

    clean_mac = re.sub(r"[^0-9A-Fa-f]", "", bssid).upper()
    if len(clean_mac) < 6:
        return "Unknown Vendor"

    oui_prefix = clean_mac[:6]
    vendor = LOCAL_OUI_DATABASE.get(oui_prefix)
    if vendor:
        return vendor

    # Check for locally administered / randomized MAC addresses (bit 1 of 1st byte)
    try:
        first_byte = int(clean_mac[:2], 16)
        if first_byte & 0x02:
            return "Randomized / Private MAC"
    except ValueError:
        pass

    return "Unknown Vendor"
