import csv
import io
import tempfile
import unittest
from pathlib import Path

from backend.features import MODEL_FEATURE_FIELDS, translate_prediction_label, translate_risk_label
from backend.storage import AlertRepository


def build_record(seed):
    record = {}
    for index, field in enumerate(MODEL_FEATURE_FIELDS):
        record[field] = float(seed + index)

    record.update(
        {
            "Src": f"10.0.0.{seed}",
            "SrcPort": 1000 + seed,
            "Dest": f"8.8.8.{seed}",
            "DestPort": 2000 + seed,
            "Protocol": "TCP",
            "FlowStartTime": f"2026-04-07 00:00:0{seed}",
            "FlowLastSeen": f"2026-04-07 00:00:1{seed}",
            "PName": f"proc-{seed}.exe",
            "PID": 3000 + seed,
            "TargetIsLocal": False,
            "Classification": translate_prediction_label("Benign"),
            "Probability": 0.9,
            "Risk": translate_risk_label("Minimal"),
            "ServiceHints": [],
        }
    )
    return record


class StorageTests(unittest.TestCase):
    def test_iter_alerts_csv_streams_header_and_rows(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            repo = AlertRepository(
                db_path=str(tmp_path / "alerts.db"),
                output_csv_path=str(tmp_path / "output_logs.csv"),
                input_csv_path=str(tmp_path / "input_logs.csv"),
            )

            first = repo.save_alert(build_record(1))
            second = repo.save_alert(build_record(2))

            chunks = list(repo.iter_alerts_csv({}))
            csv_payload = "".join(chunks)
            rows = list(csv.DictReader(io.StringIO(csv_payload)))

            self.assertEqual(len(rows), 2)
            self.assertEqual([row["FlowID"] for row in rows], [str(second["FlowID"]), str(first["FlowID"])])
            self.assertEqual(rows[0]["Classification"], translate_prediction_label("Benign"))
            self.assertEqual(rows[0]["Risk"], translate_risk_label("Minimal"))

    def test_reset_runtime_data_clears_alerts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            repo = AlertRepository(
                db_path=str(tmp_path / "alerts.db"),
                output_csv_path=str(tmp_path / "output_logs.csv"),
                input_csv_path=str(tmp_path / "input_logs.csv"),
            )

            repo.save_alert(build_record(1))
            repo.save_alert(build_record(2))
            repo.reset_runtime_data()
            rows, total = repo.query_alerts({}, limit=20, offset=0)

            self.assertEqual(total, 0)
            self.assertEqual(rows, [])

    def test_reset_runtime_data_removes_disabled_compatibility_logs(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            output_path = tmp_path / "output_logs.csv"
            input_path = tmp_path / "input_logs.csv"
            output_path.write_text("legacy", encoding="utf-8")
            input_path.write_text("legacy", encoding="utf-8")
            repo = AlertRepository(
                db_path=str(tmp_path / "alerts.db"),
                output_csv_path=str(output_path),
                input_csv_path=str(input_path),
                write_compatibility_logs=False,
            )

            repo.reset_runtime_data()

            self.assertFalse(output_path.exists())
            self.assertFalse(input_path.exists())

    def test_query_search_matches_service_hints_in_record_json(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            repo = AlertRepository(
                db_path=str(tmp_path / "alerts.db"),
                output_csv_path=str(tmp_path / "output_logs.csv"),
                input_csv_path=str(tmp_path / "input_logs.csv"),
            )

            record = build_record(1)
            record["ServiceHints"] = [translate_prediction_label("RDP-Patator")]
            repo.save_alert(record)

            rows, total = repo.query_alerts({"q": "RDP"}, limit=20, offset=0)

            self.assertEqual(total, 1)
            self.assertEqual(rows[0]["ServiceHints"], [translate_prediction_label("RDP-Patator")])

    def test_prediction_filter_matches_service_hints(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            repo = AlertRepository(
                db_path=str(tmp_path / "alerts.db"),
                output_csv_path=str(tmp_path / "output_logs.csv"),
                input_csv_path=str(tmp_path / "input_logs.csv"),
            )

            record = build_record(1)
            record["Classification"] = translate_prediction_label("DoS")
            record["ServiceHints"] = [translate_prediction_label("RDP-Patator")]
            repo.save_alert(record)

            rows, total = repo.query_alerts({"prediction": "RDP-Patator"}, limit=20, offset=0)

            self.assertEqual(total, 1)
            self.assertEqual(rows[0]["Classification"], translate_prediction_label("DoS"))
            self.assertEqual(rows[0]["ServiceHints"], [translate_prediction_label("RDP-Patator")])


if __name__ == "__main__":
    unittest.main()
