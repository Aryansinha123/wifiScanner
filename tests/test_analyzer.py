import unittest
from security.analyzer import analyze_security


class TestAnalyzer(unittest.TestCase):

    def test_wpa3_analysis(self):
        result = analyze_security("WPA3")
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["level"], "LOW")

    def test_wpa2_analysis(self):
        result = analyze_security("WPA2")
        self.assertEqual(result["score"], 85)
        self.assertEqual(result["level"], "LOW")

    def test_wpa_analysis(self):
        result = analyze_security("WPA")
        self.assertEqual(result["score"], 60)
        self.assertEqual(result["level"], "MEDIUM")

    def test_wep_analysis(self):
        result = analyze_security("WEP")
        self.assertEqual(result["score"], 20)
        self.assertEqual(result["level"], "HIGH")

    def test_open_analysis(self):
        result = analyze_security("OPEN")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "CRITICAL")

    def test_unknown_analysis(self):
        result = analyze_security("UNKNOWN")
        self.assertEqual(result["score"], 50)
        self.assertEqual(result["level"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
