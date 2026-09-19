import os
import tempfile
import unittest
from storage.database import DatabaseManager
from models.network import Network


class TestDatabaseManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_wifi.db")
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        del self.db
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_db_initialization(self):
        self.assertTrue(os.path.exists(self.db_path))
        stats = self.db.get_monitoring_stats()
        self.assertEqual(stats["total_scans"], 0)
        self.assertEqual(stats["tracked_bssids"], 0)

    def test_save_scan_and_history(self):
        net1 = Network(
            ssid="HomeWiFi",
            bssid="AA:BB:CC:DD:EE:FF",
            signal_percent=85,
            signal_dbm=-57,
            channel=6,
            band="2.4 GHz",
            security="WPA2",
            encryption="CCMP",
            radio_type="802.11n"
        )

        scan_id, prev_states = self.db.save_scan([net1], duration=1.23)
        self.assertEqual(scan_id, 1)
        self.assertEqual(len(prev_states), 0)

        stats = self.db.get_monitoring_stats()
        self.assertEqual(stats["total_scans"], 1)
        self.assertEqual(stats["tracked_bssids"], 1)
        self.assertEqual(stats["active_bssids"], 1)

        history = self.db.get_network_history("AA:BB:CC:DD:EE:FF")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["ssid"], "HomeWiFi")
        self.assertEqual(history[0]["security"], "WPA2")

    def test_create_and_acknowledge_event(self):
        event_id = self.db.create_event(
            event_type="NEW_NETWORK",
            severity="INFO",
            ssid="GuestWiFi",
            bssid="11:22:33:44:55:66",
            description="New AP detected"
        )
        self.assertGreater(event_id, 0)

        events = self.db.get_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["acknowledged"], 0)

        self.db.mark_event_acknowledged(event_id)
        events_after = self.db.get_events()
        self.assertEqual(events_after[0]["acknowledged"], 1)

    def test_clear_history(self):
        net1 = Network(
            ssid="HomeWiFi",
            bssid="AA:BB:CC:DD:EE:FF",
            signal_percent=85,
            signal_dbm=-57,
            channel=6,
            band="2.4 GHz",
            security="WPA2",
            encryption="CCMP",
            radio_type="802.11n"
        )
        self.db.save_scan([net1], duration=1.0)
        self.db.create_event("NEW_NETWORK", "INFO", "HomeWiFi", "AA:BB:CC:DD:EE:FF", "New network")

        self.db.clear_history()
        stats = self.db.get_monitoring_stats()
        self.assertEqual(stats["total_scans"], 0)
        self.assertEqual(stats["tracked_bssids"], 0)
        self.assertEqual(stats["total_events"], 0)


if __name__ == "__main__":
    unittest.main()
