import unittest
from monitoring.change_detector import detect_changes, NETWORK_MISSING_THRESHOLD
from models.network import Network


def make_prev(bssid, ssid="HomeWiFi", security="WPA2", encryption="CCMP",
              channel=6, signal=85, is_active=1, missed=0):
    """Helper to build a previous_states entry."""
    return {
        "ssid": ssid,
        "bssid": bssid,
        "last_security": security,
        "last_encryption": encryption,
        "last_channel": channel,
        "last_signal": signal,
        "is_active": is_active,
        "consecutive_missed_scans": missed
    }


BSSID_A = "AA:BB:CC:DD:EE:FF"
BSSID_B = "11:22:33:44:55:66"
TS = "2026-08-28 23:50:00"


class TestChangeDetectorDebounce(unittest.TestCase):
    """
    Tests for the Phase 2.1 monitoring stability / debounce layer.
    Covers all 11 scenarios specified in the requirements.
    """

    # ------------------------------------------------------------------
    # TEST 1: Existing BSSID appears in every scan → no events
    # ------------------------------------------------------------------
    def test_01_bssid_present_every_scan(self):
        prev = {BSSID_A: make_prev(BSSID_A)}
        current = [
            Network("HomeWiFi", BSSID_A, 85, -57, 6, "2.4 GHz", "WPA2", "CCMP", "802.11n")
        ]
        events = detect_changes(prev, current, TS)
        self.assertEqual(len(events), 0)

    # ------------------------------------------------------------------
    # TEST 2: BSSID disappears for ONE scan → no NETWORK_NOT_DETECTED
    # ------------------------------------------------------------------
    def test_02_missing_one_scan(self):
        prev = {BSSID_A: make_prev(BSSID_A, missed=0)}
        current = []  # absent
        events = detect_changes(prev, current, TS)
        not_detected = [e for e in events if e["event_type"] == "NETWORK_NOT_DETECTED"]
        self.assertEqual(len(not_detected), 0)

    # ------------------------------------------------------------------
    # TEST 3: BSSID disappears for TWO scans → no NETWORK_NOT_DETECTED
    # ------------------------------------------------------------------
    def test_03_missing_two_scans(self):
        prev = {BSSID_A: make_prev(BSSID_A, missed=1)}
        current = []
        events = detect_changes(prev, current, TS)
        not_detected = [e for e in events if e["event_type"] == "NETWORK_NOT_DETECTED"]
        self.assertEqual(len(not_detected), 0)

    # ------------------------------------------------------------------
    # TEST 4: BSSID disappears for THREE consecutive scans → exactly 1 NETWORK_NOT_DETECTED
    # ------------------------------------------------------------------
    def test_04_missing_three_scans(self):
        # missed=2 means two prior misses; this scan is the third miss
        prev = {BSSID_A: make_prev(BSSID_A, missed=2)}
        current = []
        events = detect_changes(prev, current, TS)
        not_detected = [e for e in events if e["event_type"] == "NETWORK_NOT_DETECTED"]
        self.assertEqual(len(not_detected), 1)
        self.assertEqual(not_detected[0]["severity"], "INFO")
        self.assertEqual(not_detected[0]["bssid"], BSSID_A)

    # ------------------------------------------------------------------
    # TEST 5: BSSID remains absent for TEN scans → still exactly 1 NETWORK_NOT_DETECTED
    #         (after threshold crossing, is_active=0, so no more events)
    # ------------------------------------------------------------------
    def test_05_missing_ten_scans_no_duplicates(self):
        # After the threshold was crossed, is_active=0
        prev = {BSSID_A: make_prev(BSSID_A, is_active=0, missed=9)}
        current = []
        events = detect_changes(prev, current, TS)
        not_detected = [e for e in events if e["event_type"] == "NETWORK_NOT_DETECTED"]
        self.assertEqual(len(not_detected), 0)

    # ------------------------------------------------------------------
    # TEST 6: After confirmed NOT_DETECTED, BSSID reappears → exactly 1 NETWORK_REAPPEARED
    # ------------------------------------------------------------------
    def test_06_reappearance_from_not_detected(self):
        prev = {BSSID_A: make_prev(BSSID_A, is_active=0, missed=5)}
        current = [
            Network("HomeWiFi", BSSID_A, 80, -60, 6, "2.4 GHz", "WPA2", "CCMP", "802.11n")
        ]
        events = detect_changes(prev, current, TS)
        reappeared = [e for e in events if e["event_type"] == "NETWORK_REAPPEARED"]
        self.assertEqual(len(reappeared), 1)

    # ------------------------------------------------------------------
    # TEST 7: BSSID remains present after reappearing → no additional REAPPEARED events
    # ------------------------------------------------------------------
    def test_07_no_duplicate_reappeared(self):
        # After reappearing, state is active with missed=0
        prev = {BSSID_A: make_prev(BSSID_A, is_active=1, missed=0)}
        current = [
            Network("HomeWiFi", BSSID_A, 80, -60, 6, "2.4 GHz", "WPA2", "CCMP", "802.11n")
        ]
        events = detect_changes(prev, current, TS)
        reappeared = [e for e in events if e["event_type"] == "NETWORK_REAPPEARED"]
        self.assertEqual(len(reappeared), 0)

    # ------------------------------------------------------------------
    # TEST 8: Completely new BSSID appears → exactly 1 NEW_NETWORK
    # ------------------------------------------------------------------
    def test_08_new_bssid(self):
        prev = {}  # empty — no prior knowledge
        current = [
            Network("OfficeWiFi", BSSID_B, 90, -55, 36, "5 GHz", "WPA3", "CCMP", "802.11ax")
        ]
        events = detect_changes(prev, current, TS)
        new_net = [e for e in events if e["event_type"] == "NEW_NETWORK"]
        self.assertEqual(len(new_net), 1)
        self.assertEqual(new_net[0]["bssid"], BSSID_B)

    # ------------------------------------------------------------------
    # TEST 9: Known BSSID appears again → no NEW_NETWORK
    # ------------------------------------------------------------------
    def test_09_known_bssid_no_new_event(self):
        prev = {BSSID_B: make_prev(BSSID_B, ssid="OfficeWiFi", security="WPA3")}
        current = [
            Network("OfficeWiFi", BSSID_B, 90, -55, 36, "5 GHz", "WPA3", "CCMP", "802.11ax")
        ]
        events = detect_changes(prev, current, TS)
        new_net = [e for e in events if e["event_type"] == "NEW_NETWORK"]
        self.assertEqual(len(new_net), 0)

    # ------------------------------------------------------------------
    # TEST 10: WPA2 remains WPA2 → no SECURITY_CHANGE
    # ------------------------------------------------------------------
    def test_10_security_unchanged(self):
        prev = {BSSID_A: make_prev(BSSID_A, security="WPA2", encryption="CCMP")}
        current = [
            Network("HomeWiFi", BSSID_A, 85, -57, 6, "2.4 GHz", "WPA2", "CCMP", "802.11n")
        ]
        events = detect_changes(prev, current, TS)
        sec_events = [e for e in events if "SECURITY" in e["event_type"]]
        self.assertEqual(len(sec_events), 0)

    # ------------------------------------------------------------------
    # TEST 11: WPA2 → OPEN → SECURITY_DOWNGRADE (HIGH)
    # ------------------------------------------------------------------
    def test_11_security_downgrade(self):
        prev = {BSSID_A: make_prev(BSSID_A, security="WPA2", encryption="CCMP")}
        current = [
            Network("HomeWiFi", BSSID_A, 85, -57, 6, "2.4 GHz", "OPEN", "None", "802.11n")
        ]
        events = detect_changes(prev, current, TS)
        downgrades = [e for e in events if e["event_type"] == "SECURITY_DOWNGRADE"]
        self.assertEqual(len(downgrades), 1)
        self.assertEqual(downgrades[0]["severity"], "HIGH")

    # ------------------------------------------------------------------
    # ADDITIONAL: Temporarily missing network returns silently (no REAPPEARED)
    # ------------------------------------------------------------------
    def test_temporarily_missing_returns_silently(self):
        # missed=1, is_active=1 → still TEMPORARILY_MISSING, not confirmed NOT_DETECTED
        prev = {BSSID_A: make_prev(BSSID_A, is_active=1, missed=1)}
        current = [
            Network("HomeWiFi", BSSID_A, 85, -57, 6, "2.4 GHz", "WPA2", "CCMP", "802.11n")
        ]
        events = detect_changes(prev, current, TS)
        reappeared = [e for e in events if e["event_type"] == "NETWORK_REAPPEARED"]
        self.assertEqual(len(reappeared), 0)

    # ------------------------------------------------------------------
    # ADDITIONAL: Verify threshold constant is 3
    # ------------------------------------------------------------------
    def test_threshold_is_three(self):
        self.assertEqual(NETWORK_MISSING_THRESHOLD, 3)


if __name__ == "__main__":
    unittest.main()
