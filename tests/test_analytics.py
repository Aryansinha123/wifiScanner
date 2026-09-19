import unittest
from models.network import Network
from analytics.channel_analyzer import ChannelAnalyzer
from analytics.signal_analyzer import SignalAnalyzer


class TestAnalytics(unittest.TestCase):

    def test_channel_analyzer_grouping(self):
        nets = [
            Network("Net1", "00:11:22:33:44:01", 80, -60, 1, "2.4 GHz", "WPA2", "CCMP", "802.11n"),
            Network("Net2", "00:11:22:33:44:02", 70, -65, 1, "2.4 GHz", "WPA2", "CCMP", "802.11n"),
            Network("Net3", "00:11:22:33:44:03", 90, -55, 36, "5 GHz", "WPA3", "CCMP", "802.11ac")
        ]

        res = ChannelAnalyzer.analyze_channels(nets)
        self.assertEqual(res["count_24ghz"], 2)
        self.assertEqual(res["count_5ghz"], 1)

    def test_signal_analyzer_stats(self):
        signals = [40, 60, 80]
        stats = SignalAnalyzer.calculate_signal_stats(signals)
        self.assertEqual(stats["min"], 40)
        self.assertEqual(stats["max"], 80)
        self.assertEqual(stats["avg"], 60.0)
        self.assertEqual(stats["current"], 80)


if __name__ == "__main__":
    unittest.main()
