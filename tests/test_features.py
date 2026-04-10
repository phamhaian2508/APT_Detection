import unittest

from backend.features import build_risk_summary_html


class FeatureHelpersTests(unittest.TestCase):
    def test_build_risk_summary_html_uses_stored_risk_label(self):
        html = build_risk_summary_html("High")

        self.assertIn("Cao", html)
        self.assertIn("risk-high", html)


if __name__ == "__main__":
    unittest.main()
