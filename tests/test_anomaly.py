import unittest
from models.network import Network
from storage.database import DatabaseManager
from analytics.anomaly_detector import PassiveAnomalyDetector


class TestAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.db = DatabaseManager(":memory:")
        self.detector = PassiveAnomalyDetector(self.db)

    def test_detect_sudden_security_downgrade(self):
        prev_states = {
            "00:11:22:33:44:55": {
                "bssid": "00:11:22:33:44:55",
                "ssid": "TestAP",
                "last_security": "WPA2",
                "last_encryption": "CCMP",
                "last_channel": 6,
                "last_signal": 80,
                "is_active": 1
            }
        }

        current_nets = [
            Network(
                ssid="TestAP",
                bssid="00:11:22:33:44:55",
                signal_percent=80,
                signal_dbm=-60,
                channel=6,
                band="2.4 GHz",
                security="OPEN",
                encryption="NONE",
                radio_type="802.11n"
            )
        ]

        anomalies = self.detector.detect_anomalies(prev_states, current_nets)
        self.assertTrue(any(a.anomaly_type == "SUDDEN_SECURITY_DOWNGRADE" for a in anomalies))

    def test_detect_unusual_channel_shift(self):
        prev_states = {
            "00:11:22:33:44:55": {
                "bssid": "00:11:22:33:44:55",
                "ssid": "TestAP",
                "last_security": "WPA2",
                "last_encryption": "CCMP",
                "last_channel": 1,
                "last_signal": 80,
                "is_active": 1
            }
        }

        current_nets = [
            Network(
                ssid="TestAP",
                bssid="00:11:22:33:44:55",
                signal_percent=80,
                signal_dbm=-60,
                channel=11,
                band="2.4 GHz",
                security="WPA2",
                encryption="CCMP",
                radio_type="802.11n"
            )
        ]

        anomalies = self.detector.detect_anomalies(prev_states, current_nets)
        self.assertTrue(any(a.anomaly_type == "UNUSUAL_CHANNEL_SHIFT" for a in anomalies))


if __name__ == "__main__":
    unittest.main()
