import os
import tempfile
import unittest
from storage.database import DatabaseManager
from utils.config import ConfigManager
from monitoring.alert_manager import AlertManager


class TestAlertManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_alerts.db")
        self.config_path = os.path.join(self.temp_dir.name, "test_config.json")
        self.db = DatabaseManager(self.db_path)
        self.config_mgr = ConfigManager(self.config_path)

        # Disable external network notifications for test environment
        self.config_mgr.set("alert_toast_enabled", False)
        self.config_mgr.set("alert_telegram_enabled", False)
        self.config_mgr.set("alert_email_enabled", False)
        self.config_mgr.set("alert_severity_threshold", "HIGH")
        self.config_mgr.set("alert_cooldown_minutes", 30)

        self.alert_mgr = AlertManager(self.db, self.config_mgr)

    def tearDown(self):
        del self.db
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_alert_severity_threshold_filtering(self):
        # Threshold is HIGH
        # INFO should be suppressed
        res_info = self.alert_mgr.dispatch_alert(
            alert_type="NEW_NETWORK",
            severity="INFO",
            bssid="11:22:33:44:55:66",
            ssid="GuestNet",
            message="New network observed"
        )
        self.assertFalse(res_info)

        # MEDIUM should be suppressed
        res_med = self.alert_mgr.dispatch_alert(
            alert_type="UNUSUAL_CHANNEL_SHIFT",
            severity="MEDIUM",
            bssid="11:22:33:44:55:66",
            ssid="GuestNet",
            message="Channel shifted"
        )
        self.assertFalse(res_med)

        # HIGH should be dispatched
        res_high = self.alert_mgr.dispatch_alert(
            alert_type="WEAK_ENCRYPTION",
            severity="HIGH",
            bssid="11:22:33:44:55:66",
            ssid="GuestNet",
            message="Weak configuration"
        )
        self.assertTrue(res_high)

        # CRITICAL should be dispatched
        res_crit = self.alert_mgr.dispatch_alert(
            alert_type="EVIL_TWIN_DETECTED",
            severity="CRITICAL",
            bssid="99:88:77:66:55:44",
            ssid="Corporate",
            message="Evil twin detected"
        )
        self.assertTrue(res_crit)

    def test_alert_cooldown_and_deduplication(self):
        # First alert should succeed
        res1 = self.alert_mgr.dispatch_alert(
            alert_type="SECURITY_DOWNGRADE",
            severity="CRITICAL",
            bssid="AA:BB:CC:DD:EE:01",
            ssid="WorkWiFi",
            message="Downgraded to Open"
        )
        self.assertTrue(res1)

        # Immediate repeat for same alert_type and bssid should be blocked by cooldown
        res2 = self.alert_mgr.dispatch_alert(
            alert_type="SECURITY_DOWNGRADE",
            severity="CRITICAL",
            bssid="AA:BB:CC:DD:EE:01",
            ssid="WorkWiFi",
            message="Downgraded to Open (Repeat)"
        )
        self.assertFalse(res2)

        # Different BSSID should be allowed
        res3 = self.alert_mgr.dispatch_alert(
            alert_type="SECURITY_DOWNGRADE",
            severity="CRITICAL",
            bssid="AA:BB:CC:DD:EE:02",
            ssid="WorkWiFi",
            message="Downgraded to Open on different AP"
        )
        self.assertTrue(res3)

    def test_acknowledgment_stops_repeats(self):
        self.alert_mgr.dispatch_alert(
            alert_type="EVIL_TWIN_DETECTED",
            severity="CRITICAL",
            bssid="AA:BB:CC:DD:EE:03",
            ssid="HomeNet",
            message="Evil twin"
        )

        alerts = self.db.repos.get_alerts()
        self.assertEqual(len(alerts), 1)
        alert_id = alerts[0]["id"]
        self.assertEqual(alerts[0]["acknowledged"], 0)

        # Mark acknowledged
        self.alert_mgr.db.repos.mark_alert_acknowledged(alert_id)

        # Verify acknowledged
        updated = self.db.repos.get_alerts()[0]
        self.assertEqual(updated["acknowledged"], 1)
        self.assertEqual(updated["status"], "ACKNOWLEDGED")

        # Future attempts should be suppressed because it is acknowledged
        res_repeat = self.alert_mgr.dispatch_alert(
            alert_type="EVIL_TWIN_DETECTED",
            severity="CRITICAL",
            bssid="AA:BB:CC:DD:EE:03",
            ssid="HomeNet",
            message="Evil twin repeat"
        )
        self.assertFalse(res_repeat)


if __name__ == "__main__":
    unittest.main()
