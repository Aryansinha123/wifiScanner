import unittest
from models.network import Network
from security.weak_config_rules import (
    evaluate_weak_configurations,
    is_default_router_name,
    WEAK_CONFIG_RULES
)
from security.risk_engine import MultiFactorRiskEngine
from security.configuration_analyzer import ConfigurationAnalyzer


class TestWeakConfigurationChecks(unittest.TestCase):

    def test_open_network_rule(self):
        net = Network(
            ssid="PublicAirport",
            bssid="00:11:22:33:44:01",
            signal_percent=80,
            signal_dbm=-60,
            channel=6,
            band="2.4 GHz",
            security="OPEN",
            encryption="NONE",
            radio_type="802.11n"
        )
        findings = evaluate_weak_configurations(net)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("RULE_OPEN_NETWORK", rule_ids)
        open_rule = next(f for f in findings if f["rule_id"] == "RULE_OPEN_NETWORK")
        self.assertEqual(open_rule["points"], 85)
        self.assertEqual(open_rule["severity"], "CRITICAL")
        self.assertIn("+85", open_rule["reason"])

    def test_wep_rule(self):
        net = Network(
            ssid="OldCafe",
            bssid="00:11:22:33:44:02",
            signal_percent=70,
            signal_dbm=-65,
            channel=1,
            band="2.4 GHz",
            security="WEP",
            encryption="WEP",
            radio_type="802.11g"
        )
        findings = evaluate_weak_configurations(net)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("RULE_WEP_ENCRYPTION", rule_ids)
        wep_rule = next(f for f in findings if f["rule_id"] == "RULE_WEP_ENCRYPTION")
        self.assertEqual(wep_rule["points"], 75)
        self.assertEqual(wep_rule["severity"], "HIGH")

    def test_tkip_cipher_rule(self):
        net = Network(
            ssid="LegacyOffice",
            bssid="00:11:22:33:44:03",
            signal_percent=85,
            signal_dbm=-55,
            channel=11,
            band="2.4 GHz",
            security="WPA2",
            encryption="TKIP",
            radio_type="802.11n"
        )
        findings = evaluate_weak_configurations(net)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("RULE_TKIP_CIPHER", rule_ids)
        tkip_rule = next(f for f in findings if f["rule_id"] == "RULE_TKIP_CIPHER")
        self.assertEqual(tkip_rule["points"], 20)
        self.assertIn("TKIP cipher is deprecated (+20)", tkip_rule["reason"])

    def test_hidden_ssid_rule(self):
        net = Network(
            ssid="<Hidden Network>",
            bssid="00:11:22:33:44:04",
            signal_percent=60,
            signal_dbm=-70,
            channel=36,
            band="5 GHz",
            security="WPA2",
            encryption="CCMP",
            radio_type="802.11ac"
        )
        findings = evaluate_weak_configurations(net)
        rule_ids = [f["rule_id"] for f in findings]
        self.assertIn("RULE_HIDDEN_SSID", rule_ids)
        hidden_rule = next(f for f in findings if f["rule_id"] == "RULE_HIDDEN_SSID")
        self.assertEqual(hidden_rule["points"], 15)

    def test_default_router_ssid_patterns(self):
        default_names = [
            "TP-Link_4F2A",
            "TP-LINK_A1B2C3",
            "JioFiber-5G2A",
            "D-Link_8820",
            "NETGEAR45",
            "Tenda_B320",
            "ASUS_78A2",
            "Airtel_9821"
        ]
        for name in default_names:
            self.assertTrue(is_default_router_name(name), f"Expected '{name}' to match default router pattern")

        custom_names = [
            "MyAwesomeHomeWifi",
            "Corporate_Secure_Network",
            "CoffeeShop-Guest",
            "VIT-Campus"
        ]
        for name in custom_names:
            self.assertFalse(is_default_router_name(name), f"Expected '{name}' not to match default router pattern")

    def test_configuration_analyzer_integration(self):
        net = Network(
            ssid="TP-Link_4F2A",
            bssid="00:11:22:33:44:05",
            signal_percent=90,
            signal_dbm=-50,
            channel=6,
            band="2.4 GHz",
            security="WPA2",
            encryption="TKIP",
            radio_type="802.11n"
        )
        analysis = ConfigurationAnalyzer.analyze_network_configuration(net)
        self.assertIn("weak_config_findings", analysis)
        weak_rules = [w["rule_id"] for w in analysis["weak_config_findings"]]
        self.assertIn("RULE_DEFAULT_ROUTER_SSID", weak_rules)
        self.assertIn("RULE_TKIP_CIPHER", weak_rules)


if __name__ == "__main__":
    unittest.main()
