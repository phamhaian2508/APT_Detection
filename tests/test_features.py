import unittest

from backend.features import (
    build_risk_summary_html,
    clamp_attack_risk,
    is_priority_alert,
    risk_rank,
    translate_prediction_label,
    translate_risk_label,
)


class FeatureHelpersTests(unittest.TestCase):
    def test_build_risk_summary_html_uses_stored_risk_label(self):
        html = build_risk_summary_html("High")

        self.assertIn("Cao", html)
        self.assertIn("risk-high", html)

    def test_dos_alerts_become_priority_only_when_risk_is_high(self):
        self.assertFalse(is_priority_alert(translate_prediction_label("DoS"), "Low"))
        self.assertFalse(is_priority_alert(translate_prediction_label("DoS"), "Medium"))
        self.assertTrue(is_priority_alert(translate_prediction_label("DoS"), "High"))

    def test_ddos_alerts_become_priority_only_when_risk_is_high(self):
        self.assertFalse(is_priority_alert(translate_prediction_label("DDoS"), "Medium"))
        self.assertTrue(is_priority_alert(translate_prediction_label("DDoS"), "High"))

    def test_ddos_risk_is_clamped_to_medium_when_it_would_otherwise_be_low(self):
        clamped = clamp_attack_risk(translate_prediction_label("DDoS"), "Low")

        self.assertEqual(risk_rank(clamped), risk_rank("Medium"))
        self.assertEqual(clamped, translate_risk_label("Medium"))

    def test_ddos_risk_is_clamped_to_high_when_it_would_otherwise_be_very_high(self):
        clamped = clamp_attack_risk(translate_prediction_label("DDoS"), "Very High")

        self.assertEqual(risk_rank(clamped), risk_rank("High"))
        self.assertEqual(clamped, translate_risk_label("High"))


if __name__ == "__main__":
    unittest.main()
