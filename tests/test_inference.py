import unittest
from types import SimpleNamespace

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

    def test_build_stream_payload_normalizes_historical_dos_risk_probability_and_priority(self):
        service = InferenceService.__new__(InferenceService)
        service.geo_resolver = SimpleNamespace(decorate_ip=lambda address: address)
        record = {
            "FlowID": 7,
            "Src": "192.168.186.134",
            "SrcPort": 54321,
            "Dest": "192.168.186.2",
            "DestPort": 80,
            "Protocol": "TCP",
            "FlowStartTime": "2026-05-01 09:00:00",
            "FlowLastSeen": "2026-05-01 09:00:02",
            "PName": "python.exe",
            "PID": 1234,
            "Classification": translate_prediction_label("DoS"),
            "Probability": 0.9999,
            "Risk": translate_risk_label("High"),
            "ServiceHints": [],
        }

        payload = service.build_stream_payload(record)

        self.assertEqual(payload["prediction"], translate_prediction_label("DoS"))
        self.assertEqual(payload["risk"], translate_risk_label("Medium"))
        self.assertEqual(payload["probability"], 0.962)
        self.assertFalse(payload["isPriority"])


if __name__ == "__main__":
    unittest.main()
