import unittest

from backend.inference import InferenceService
from backend.features import translate_prediction_label, translate_risk_label


class InferenceServiceTests(unittest.TestCase):
    def test_unconfirmed_model_dos_prediction_is_downgraded(self):
        record = {
            "Classification": translate_prediction_label("DoS"),
            "Probability": 0.91,
            "Risk": translate_risk_label("Medium"),
        }

        InferenceService._suppress_unconfirmed_flood_prediction(
            record,
            model_prediction=translate_prediction_label("DoS"),
            flood_heuristic_match=None,
        )

        self.assertEqual(record["Classification"], translate_prediction_label("Benign"))
        self.assertEqual(record["Risk"], translate_risk_label("Low"))
        self.assertLessEqual(record["Probability"], 0.49)

    def test_confirmed_model_dos_prediction_is_preserved(self):
        record = {
            "Classification": translate_prediction_label("DoS"),
            "Probability": 0.91,
            "Risk": translate_risk_label("Medium"),
        }

        InferenceService._suppress_unconfirmed_flood_prediction(
            record,
            model_prediction=translate_prediction_label("DoS"),
            flood_heuristic_match=object(),
        )

        self.assertEqual(record["Classification"], translate_prediction_label("DoS"))
        self.assertEqual(record["Risk"], translate_risk_label("Medium"))
        self.assertEqual(record["Probability"], 0.91)


if __name__ == "__main__":
    unittest.main()
