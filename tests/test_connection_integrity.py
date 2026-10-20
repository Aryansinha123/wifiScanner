import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from storage.database import DatabaseManager
from monitoring.alert_manager import AlertManager
from monitoring.connection_integrity import ConnectionIntegrityMonitor


class TestConnectionIntegrityMonitor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_conn_int.db")
        self.db = DatabaseManager(self.db_path)
        self.alert_mgr = AlertManager(self.db)
        self.monitor = ConnectionIntegrityMonitor(self.db, self.alert_mgr)

    def tearDown(self):
        del self.db
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    @patch("monitoring.connection_integrity.ConnectionIntegrityMonitor.get_connected_wifi_details")
    @patch("monitoring.connection_integrity.ConnectionIntegrityMonitor.get_default_gateway_ip")
    @patch("monitoring.connection_integrity.ConnectionIntegrityMonitor.get_gateway_mac")
    @patch("monitoring.connection_integrity.ConnectionIntegrityMonitor.check_dns_integrity")
    def test_arp_spoofing_detection(self, mock_dns, mock_mac, mock_ip, mock_wifi):
        mock_wifi.return_value = {
            "connected": True,
            "interface": "Wi-Fi",
            "state": "connected",
            "ssid": "SecureCorp",
            "bssid": "00:11:22:33:44:55",
            "radio_type": "802.11ax",
            "signal": "95%"
        }
        mock_ip.return_value = "192.168.1.1"
        mock_dns.return_value = ("CONSISTENT", "System DNS matches DoH", {})

        # Pass 1: Initial observation of gateway MAC AA:BB:CC:00:11:22
        mock_mac.return_value = "AA:BB:CC:00:11:22"
        res1 = self.monitor.run_integrity_check()
        self.assertEqual(res1["overall_health"], "SAFE")
        self.assertEqual(res1["arp_status"], "STABLE")

        # Pass 2: Attacker suddenly poisons ARP table with rogue MAC DE:AD:BE:EF:99:99 on the same gateway IP and SSID!
        mock_mac.return_value = "DE:AD:BE:EF:99:99"
        res2 = self.monitor.run_integrity_check()
        self.assertEqual(res2["overall_health"], "CRITICAL")
        self.assertEqual(res2["arp_status"], "SPOOF_DETECTED")
        self.assertIn("ARP Spoofing", res2["details"])

        # Verify alert was saved in database
        alerts = self.db.repos.get_alerts()
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["alert_type"], "ARP_SPOOFING_DETECTED")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")

    @patch("monitoring.connection_integrity.socket.gethostbyname")
    def test_dns_hijacking_private_ip_detection(self, mock_socket):
        # Attacker configures rogue DNS resolving google.com to 192.168.1.250 (internal phish portal)
        mock_socket.return_value = "192.168.1.250"

        # Mock DoH response with public Google IPs
        with patch("urllib.request.urlopen") as mock_url:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read.return_value = b'{"Answer": [{"type": 1, "data": "142.250.190.46"}]}'
            mock_url.return_value.__enter__.return_value = mock_resp

            status, summary, details = ConnectionIntegrityMonitor.check_dns_integrity(["google.com"])
            self.assertEqual(status, "MISMATCH")
            self.assertIn("RFC1918", details["google.com"]["reason"])

    @patch("monitoring.connection_integrity.socket.gethostbyname")
    def test_dns_healthy_resolution(self, mock_socket):
        mock_socket.return_value = "142.250.190.46"

        with patch("urllib.request.urlopen") as mock_url:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.read.return_value = b'{"Answer": [{"type": 1, "data": "142.250.190.46"}]}'
            mock_url.return_value.__enter__.return_value = mock_resp

            status, summary, details = ConnectionIntegrityMonitor.check_dns_integrity(["google.com"])
            self.assertEqual(status, "CONSISTENT")


if __name__ == "__main__":
    unittest.main()
