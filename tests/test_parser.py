import unittest
from utils.parser import parse_networks, signal_to_dbm, get_frequency, normalize_security
from models.network import Network


SAMPLE_NETSH_OUTPUT = """
Interface name : Wi-Fi 
There are 4 networks currently visible. 

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
        
        # 4 total BSSIDs parsed
        self.assertEqual(len(networks), 4)

        # Network 1: HomeWiFi (WPA2)
        n1 = networks[0]
        self.assertEqual(n1.ssid, "HomeWiFi")
        self.assertEqual(n1.bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(n1.signal_percent, 85)
        self.assertEqual(n1.signal_dbm, -57)
        self.assertEqual(n1.channel, 6)
        self.assertEqual(n1.frequency, "2.4 GHz")
        self.assertEqual(n1.security, "WPA2")
        self.assertEqual(n1.risk_level(), "LOW")

        # Network 2: Hidden network (WPA3)
        n2 = networks[1]
        self.assertEqual(n2.ssid, "<Hidden Network>")
        self.assertEqual(n2.bssid, "11:22:33:44:55:66")
        self.assertEqual(n2.security, "WPA3")
        self.assertEqual(n2.risk_level(), "LOW")

        # Network 3 & 4: PublicFree multiple BSSIDs
        n3 = networks[2]
        self.assertEqual(n3.ssid, "PublicFree")
        self.assertEqual(n3.bssid, "00:11:22:33:44:55")
        self.assertEqual(n3.security, "OPEN")
        self.assertEqual(n3.risk_level(), "CRITICAL")
        self.assertEqual(n3.channel, 36)
        self.assertEqual(n3.frequency, "5 GHz")

        n4 = networks[3]
        self.assertEqual(n4.ssid, "PublicFree")
        self.assertEqual(n4.bssid, "00:11:22:33:44:56")
        self.assertEqual(n4.security, "OPEN")
        self.assertEqual(n4.channel, 11)
        self.assertEqual(n4.frequency, "2.4 GHz")


if __name__ == "__main__":
    unittest.main()
