import unittest
from models.network import Network
from analytics.channel_analyzer import ChannelAnalyzer


class TestChannelRecommendationEngine(unittest.TestCase):

    def test_user_prompt_scenario_channel_11_recommended(self):
        """
        User scenario:
        Channel 6 has 9 networks (very crowded).
        Channel 11 has 2 networks.
        Channel 1 has 5 networks.
        Recommended: Channel 11
        """
        networks = []

        # 9 networks on channel 6
        for i in range(9):
            networks.append(Network(
                ssid=f"Net_Ch6_{i}",
                bssid=f"00:11:22:66:00:{i:02x}",
                signal_percent=80,
                signal_dbm=-60,
                channel=6,
                band="2.4 GHz",
                security="WPA2",
                encryption="CCMP",
                radio_type="802.11n"
            ))

        # 5 networks on channel 1
        for i in range(5):
            networks.append(Network(
                ssid=f"Net_Ch1_{i}",
                bssid=f"00:11:22:11:00:{i:02x}",
                signal_percent=70,
                signal_dbm=-65,
                channel=1,
                band="2.4 GHz",
                security="WPA2",
                encryption="CCMP",
                radio_type="802.11n"
            ))

        # 2 networks on channel 11
        for i in range(2):
            networks.append(Network(
                ssid=f"Net_Ch11_{i}",
                bssid=f"00:11:22:AA:00:{i:02x}",
                signal_percent=40,
                signal_dbm=-75,
                channel=11,
                band="2.4 GHz",
                security="WPA2",
                encryption="CCMP",
                radio_type="802.11n"
            ))

        recs = ChannelAnalyzer.get_channel_recommendations(networks)
        rec_24 = recs["band_24ghz"]["recommended_channel"]
        scores = recs["band_24ghz"]["scores"]

        self.assertEqual(rec_24, 11)
        self.assertEqual(scores[6]["crowd_label"], "Very Crowded")
        self.assertEqual(scores[6]["co_channel_count"], 9)
        self.assertEqual(scores[11]["co_channel_count"], 2)

        # Verification of explanation string
        explanation = recs["band_24ghz"]["explanation"]
        self.assertIn("Recommended: Channel 11", explanation)
        self.assertIn("Channel 6 has 9 direct network(s)", explanation)

    def test_adjacent_channel_interference_weighting(self):
        """
        Verify that networks on adjacent channels (e.g., channel 2, 3) contribute
        interference to center channel 1.
        """
        networks = [
            Network(
                ssid="Net_Ch2",
                bssid="00:11:22:33:02:01",
                signal_percent=100,
                signal_dbm=-40,
                channel=2,
                band="2.4 GHz",
                security="WPA2",
                encryption="CCMP",
                radio_type="802.11n"
            )
        ]
        recs = ChannelAnalyzer.get_channel_recommendations(networks)
        scores = recs["band_24ghz"]["scores"]

        # Channel 1 should register 1 adjacent network with weighted congestion (0.7 * 100 = 70.0)
        self.assertEqual(scores[1]["adjacent_count"], 1)
        self.assertEqual(scores[1]["co_channel_count"], 0)
        self.assertEqual(scores[1]["congestion_score"], 70.0)

        # Channel 11 should have 0 congestion
        self.assertEqual(scores[11]["congestion_score"], 0.0)

    def test_5ghz_channel_recommendation(self):
        networks = [
            Network(
                ssid="Office_5G_1",
                bssid="00:11:22:55:01:01",
                signal_percent=90,
                signal_dbm=-50,
                channel=36,
                band="5 GHz",
                security="WPA3",
                encryption="CCMP",
                radio_type="802.11ax"
            ),
            Network(
                ssid="Office_5G_2",
                bssid="00:11:22:55:01:02",
                signal_percent=85,
                signal_dbm=-55,
                channel=36,
                band="5 GHz",
                security="WPA2",
                encryption="CCMP",
                radio_type="802.11ac"
            )
        ]
        recs = ChannelAnalyzer.get_channel_recommendations(networks)
        rec_5 = recs["band_5ghz"]["recommended_channel"]
        # Channel 36 has 2 networks, so an empty channel like 40 or 44 should be recommended
        self.assertNotEqual(rec_5, 36)
        self.assertEqual(recs["band_5ghz"]["scores"][rec_5]["count"], 0)


if __name__ == "__main__":
    unittest.main()
