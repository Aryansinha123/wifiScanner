import os
import tempfile
import unittest
from storage.database import DatabaseManager
from models.network import Network
from security.evil_twin_detector import EvilTwinDetector


class TestEvilTwinDetector(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_evil_twin.db")
        self.db = DatabaseManager(self.db_path)
        self.detector = EvilTwinDetector(self.db)

    def tearDown(self):
        del self.db
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_locally_administered_mac_detection(self):
        # Locally administered bit: 2nd hex digit is 2, 6, A, or E
        # DE:AD:BE:EF:00:01 -> byte 0 is 0xDE -> (0xDE & 0x02) != 0 -> True
        self.assertTrue(EvilTwinDetector.is_locally_administered_mac("DE:AD:BE:EF:00:01"))
        self.assertTrue(EvilTwinDetector.is_locally_administered_mac("02:00:00:00:00:00"))
        self.assertTrue(EvilTwinDetector.is_locally_administered_mac("a6:11:22:33:44:55"))
        # Globally unique (OUI assigned)
        self.assertFalse(EvilTwinDetector.is_locally_administered_mac("00:19:E0:11:22:33"))
        self.assertFalse(EvilTwinDetector.is_locally_administered_mac("14:CC:20:11:22:33"))
        self.assertFalse(EvilTwinDetector.is_locally_administered_mac("00:00:0C:12:34:56"))  # Cisco

    def test_security_downgrade_hierarchy(self):
        self.assertTrue(EvilTwinDetector.is_security_weaker("OPEN", "WPA2"))
        self.assertTrue(EvilTwinDetector.is_security_weaker("WEP", "WPA2"))
        self.assertTrue(EvilTwinDetector.is_security_weaker("WPA", "WPA3"))
        self.assertTrue(EvilTwinDetector.is_security_weaker("WPA2", "WPA3"))
        self.assertFalse(EvilTwinDetector.is_security_weaker("WPA2", "WPA2"))
        self.assertFalse(EvilTwinDetector.is_security_weaker("WPA3", "WPA2"))

    def test_exact_user_prompt_scenario(self):
        """
        User prompt scenario:
        Trusted: HomeWiFi, BSSID 00:19:E0:11:22:33, WPA2, channel 6, vendor TP-Link
        Seen now: HomeWiFi, BSSID DE:AD:BE:EF:00:01, Open, channel 11
        Result: CRITICAL alert, "Same SSID, unknown BSSID, security downgraded WPA2 -> Open"
        """
        # Save trusted network
        self.db.repos.add_trusted_network(
            ssid="HomeWiFi",
            bssid="00:19:E0:11:22:33",
            vendor="TP-Link Technologies",
            security="WPA2",
            channel=6
        )

        rogue_net = Network(
            ssid="HomeWiFi",
            bssid="DE:AD:BE:EF:00:01",
            signal_percent=85,
            signal_dbm=-55,
            channel=11,
            band="2.4 GHz",
            security="OPEN",
            encryption="NONE",
            radio_type="802.11n",
            vendor="Unknown Vendor"
        )

        res = self.detector.evaluate_network(rogue_net)
        self.assertIsNotNone(res)
        self.assertTrue(res["is_rogue"])
        self.assertEqual(res["severity"], "CRITICAL")

        # Check evidence breakdown:
        # Same SSID, unknown BSSID (+40)
        # Security weaker WPA2 -> OPEN (+30)
        # Different channel 11 vs 6 (+5)
        # Locally administered MAC DE:AD... (+10)
        # Total expected: at least 85
        self.assertGreaterEqual(res["score"], 85)
        self.assertIn("security downgraded", res["message"].lower())
        self.assertIn("DE:AD:BE:EF:00:01", res["message"])

    def test_legitimate_ap_no_false_positive(self):
        self.db.repos.add_trusted_network(
            ssid="HomeWiFi",
            bssid="00:19:E0:11:22:33",
            vendor="TP-Link Technologies",
            security="WPA2",
            channel=6
        )

        legit_net = Network(
            ssid="HomeWiFi",
            bssid="00:19:E0:11:22:33",
            signal_percent=90,
            signal_dbm=-50,
            channel=6,
            band="2.4 GHz",
            security="WPA2",
            encryption="CCMP",
            radio_type="802.11n",
            vendor="TP-Link Technologies"
        )

        res = self.detector.evaluate_network(legit_net)
        self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
