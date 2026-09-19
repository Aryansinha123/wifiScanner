import unittest
from utils.parser import parse_networks, parse_interface, signal_to_dbm, get_frequency, normalize_security
from models.network import Network


SAMPLE_NETSH_OUTPUT = """
Interface name : Wi-Fi 
There are 5 networks currently visible. 

SSID 1 : HomeWiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP 
    BSSID 1                 : AA:BB:CC:DD:EE:FF
         Signal             : 85%  
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 : 
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP 
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 90%  
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 149

SSID 3 : PublicFree
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None 
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 50%  
         Radio type         : 802.11ac
         Channel            : 36
    BSSID 2                 : 00:11:22:33:44:56
         Signal             : 30%  
         Radio type         : 802.11n
         Channel            : 11

SSID 4 : LegacyNet
    Network type            : Infrastructure
    Authentication          : WEP
    Encryption              : WEP
    BSSID 1                 : 99:88:77:66:55:44
         Signal             : 40%
         Radio type         : 802.11g
         Channel            : 1
"""

SAMPLE_INTERFACE_OUTPUT = """
There is 1 interface on the system: 

    Name                   : Wi-Fi
    Description            : Realtek RTL8822CE 802.11ac PCIe Adapter
    GUID                   : 0948300b-d970-4fa1-83ec-ebc321a3aff0
    Physical address       : a8:41:f4:c3:65:f7
    Interface type         : Primary
    State                  : connected
    SSID                   : HomeWiFi 
    AP BSSID               : AA:BB:CC:DD:EE:FF
    Band                   : 2.4 GHz
    Channel                : 6
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Signal                 : 100% 
"""


class TestParser(unittest.TestCase):

    def test_signal_to_dbm(self):
        self.assertEqual(signal_to_dbm(100), -50)
        self.assertEqual(signal_to_dbm(85), -57)
        self.assertEqual(signal_to_dbm(0), -100)
        self.assertEqual(signal_to_dbm(120), -50)  # Clamped to 100
        self.assertEqual(signal_to_dbm(-10), -100) # Clamped to 0

    def test_get_frequency(self):
        self.assertEqual(get_frequency(6, "2.4 GHz"), "2.4 GHz")
        self.assertEqual(get_frequency(36, "5 GHz"), "5 GHz")
        self.assertEqual(get_frequency(6), "2.4 GHz")
        self.assertEqual(get_frequency(149), "5 GHz")
        self.assertEqual(get_frequency(None), "Unknown")

    def test_normalize_security(self):
        self.assertEqual(normalize_security("WPA3-Personal", "CCMP"), "WPA3")
        self.assertEqual(normalize_security("WPA2-Personal", "CCMP"), "WPA2")
        self.assertEqual(normalize_security("WPA-Personal", "TKIP"), "WPA")
        self.assertEqual(normalize_security("WEP", "WEP"), "WEP")
        self.assertEqual(normalize_security("Open", "None"), "OPEN")
        self.assertEqual(normalize_security("SomethingElse", "CCMP"), "UNKNOWN")

    def test_parse_networks(self):
        networks = parse_networks(SAMPLE_NETSH_OUTPUT)
        
        # 5 total BSSIDs parsed
        self.assertEqual(len(networks), 5)

        # Network 1: HomeWiFi (WPA2)
        n1 = networks[0]
        self.assertEqual(n1.ssid, "HomeWiFi")
        self.assertEqual(n1.bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(n1.signal_percent, 85)
        self.assertEqual(n1.signal_dbm, -57)
        self.assertEqual(n1.channel, 6)
        self.assertEqual(n1.band, "2.4 GHz")
        self.assertEqual(n1.frequency, "2.4 GHz")
        self.assertEqual(n1.security, "WPA2")
        self.assertEqual(n1.risk_level(), "LOW")

        # Network 2: Hidden network (WPA3)
        n2 = networks[1]
        self.assertEqual(n2.ssid, "<Hidden Network>")
        self.assertEqual(n2.bssid, "11:22:33:44:55:66")
        self.assertEqual(n2.security, "WPA3")
        self.assertEqual(n2.risk_level(), "LOW")

        # Network 3 & 4: PublicFree multiple BSSIDs (OPEN)
        n3 = networks[2]
        self.assertEqual(n3.ssid, "PublicFree")
        self.assertEqual(n3.bssid, "00:11:22:33:44:55")
        self.assertEqual(n3.security, "OPEN")
        self.assertEqual(n3.risk_level(), "CRITICAL")
        self.assertEqual(n3.channel, 36)
        self.assertEqual(n3.band, "5 GHz")

        # Network 5: WEP network
        n5 = networks[4]
        self.assertEqual(n5.ssid, "LegacyNet")
        self.assertEqual(n5.security, "WEP")
        self.assertEqual(n5.risk_level(), "HIGH")

    def test_parse_interface(self):
        info = parse_interface(SAMPLE_INTERFACE_OUTPUT)
        self.assertEqual(info["name"], "Wi-Fi")
        self.assertEqual(info["state"], "connected")
        self.assertEqual(info["ssid"], "HomeWiFi")
        self.assertEqual(info["bssid"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(info["channel"], 6)
        self.assertEqual(info["signal_percent"], 100)
        self.assertEqual(info["band"], "2.4 GHz")


if __name__ == "__main__":
    unittest.main()
