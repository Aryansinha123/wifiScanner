import unittest
from models.network import Network
from security.risk_engine import MultiFactorRiskEngine


class TestRiskEngine(unittest.TestCase):

    def test_wpa3_risk_score(self):
        net = Network(
            ssid="SecureWPA3",
            bssid="AA:BB:CC:DD:EE:01",
            signal_percent=90,
            signal_dbm=-55,
            channel=36,
            band="5 GHz",
            security="WPA3",
            encryption="CCMP",
            radio_type="802.11ax"
        )
        res = MultiFactorRiskEngine.calculate_risk(net)
        self.assertEqual(res["level"], "LOW")
        self.assertLessEqual(res["score"], 20)

    def test_open_network_risk_score(self):
        net = Network(
            ssid="FreeWifi",
            bssid="AA:BB:CC:DD:EE:02",
            signal_percent=70,
            signal_dbm=-65,
            channel=6,
            band="2.4 GHz",
            security="OPEN",
            encryption="NONE",
            radio_type="802.11n"
        )
        res = MultiFactorRiskEngine.calculate_risk(net)
        self.assertEqual(res["level"], "CRITICAL")
        self.assertGreaterEqual(res["score"], 71)

    def test_security_downgrade_modifier(self):
        net = Network(
            ssid="Corporate",
            bssid="AA:BB:CC:DD:EE:03",
            signal_percent=80,
            signal_dbm=-60,
            channel=1,
            band="2.4 GHz",
            security="OPEN",
            encryption="NONE",
            radio_type="802.11n"
        )
        res = MultiFactorRiskEngine.calculate_risk(net, has_security_downgrade=True)
        self.assertEqual(res["score"], 100)
        self.assertEqual(res["level"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()
