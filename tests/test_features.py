import unittest

from backend.features import build_risk_summary_html, is_priority_alert, translate_prediction_label


class FeatureHelpersTests(unittest.TestCase):
    def test_build_risk_summary_html_uses_stored_risk_label(self):
        html = build_risk_summary_html("High")

        self.assertIn("Cao", html)
        self.assertIn("risk-high", html)

    def test_dos_alerts_become_priority_only_when_risk_is_high(self):
        self.assertFalse(is_priority_alert(translate_prediction_label("DoS"), "Low"))
        self.assertFalse(is_priority_alert(translate_prediction_label("DoS"), "Medium"))
        self.assertTrue(is_priority_alert(translate_prediction_label("DoS"), "High"))


if __name__ == "__main__":
    unittest.main()
