import csv
import io
import tempfile
import unittest
from pathlib import Path

from backend.features import FLOW_METADATA_FIELDS, MODEL_FEATURE_FIELDS
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
            "Classification": "Lưu lượng hợp lệ",
            "Probability": 0.9,
            "Risk": "Rất thấp",
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
            self.assertEqual(rows[0]["Classification"], "Lưu lượng hợp lệ")
            self.assertEqual(rows[0]["Risk"], "Rất thấp")


if __name__ == "__main__":
    unittest.main()
