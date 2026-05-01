import unittest

from backend.features import (
    build_alert_record,
    build_risk_summary_html,
    clamp_attack_probability,
    clamp_attack_risk,
    is_priority_alert,
    ordered_record,
    risk_rank,
    translate_prediction_label,
    translate_risk_label,
)


class FeatureHelpersTests(unittest.TestCase):
    def test_build_risk_summary_html_uses_stored_risk_label(self):
        html = build_risk_summary_html("High")

        self.assertIn("Cao", html)
        self.assertIn("risk-high", html)

    def test_dos_alerts_never_become_priority(self):
        self.assertFalse(is_priority_alert(translate_prediction_label("DoS"), "Low"))
        self.assertFalse(is_priority_alert(translate_prediction_label("DoS"), "Medium"))
        self.assertFalse(is_priority_alert(translate_prediction_label("DoS"), "High"))

    def test_ddos_alerts_become_priority_only_when_risk_is_high(self):
        self.assertFalse(is_priority_alert(translate_prediction_label("DDoS"), "Medium"))
        self.assertTrue(is_priority_alert(translate_prediction_label("DDoS"), "High"))

    def test_dns_abuse_alerts_become_priority_only_when_risk_is_high(self):
        self.assertFalse(is_priority_alert(translate_prediction_label("DNS-Abuse"), "Medium"))
        self.assertTrue(is_priority_alert(translate_prediction_label("DNS-Abuse"), "High"))

    def test_ddos_risk_is_clamped_to_medium_when_it_would_otherwise_be_low(self):
        clamped = clamp_attack_risk(translate_prediction_label("DDoS"), "Low")

        self.assertEqual(risk_rank(clamped), risk_rank("Medium"))
        self.assertEqual(clamped, translate_risk_label("Medium"))

    def test_ddos_risk_is_clamped_to_high_when_it_would_otherwise_be_very_high(self):
        clamped = clamp_attack_risk(translate_prediction_label("DDoS"), "Very High")

        self.assertEqual(risk_rank(clamped), risk_rank("High"))
        self.assertEqual(clamped, translate_risk_label("High"))

    def test_dos_risk_is_clamped_to_medium_when_it_would_otherwise_be_high(self):
        clamped = clamp_attack_risk(translate_prediction_label("DoS"), "High")

        self.assertEqual(risk_rank(clamped), risk_rank("Medium"))
        self.assertEqual(clamped, translate_risk_label("Medium"))

    def test_dos_probability_is_capped_below_ninety_nine_percent(self):
        clamped = clamp_attack_probability(translate_prediction_label("DoS"), 0.9999)

        self.assertLess(clamped, 0.99)
        self.assertEqual(clamped, 0.962)

    def test_dns_abuse_probability_is_capped_below_ninety_nine_percent(self):
        clamped = clamp_attack_probability(translate_prediction_label("DNS-Abuse"), 0.9999)

        self.assertLess(clamped, 0.99)
        self.assertEqual(clamped, 0.978)

    def test_alert_records_initialize_service_hints_and_keep_them_in_ordered_output(self):
        record = build_alert_record([0.0] * 48, translate_prediction_label("Benign"), 0.12, translate_risk_label("Low"))
        self.assertEqual(record["ServiceHints"], [])

        record["FlowID"] = 1
        record["ServiceHints"] = [translate_prediction_label("RDP-Patator")]
        ordered = ordered_record(record)

        self.assertEqual(ordered["ServiceHints"], [translate_prediction_label("RDP-Patator")])


if __name__ == "__main__":
    unittest.main()
