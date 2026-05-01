from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Tuple

from backend.features import (
    FLOW_METADATA_FIELDS,
    MODEL_FEATURE_FIELDS,
    ordered_record,
    prediction_filter_values,
    risk_filter_values,
)


class AlertRepository:
    def __init__(
        self,
        db_path: str = "data/alerts.db",
        output_csv_path: str = "output_logs.csv",
        input_csv_path: str = "input_logs.csv",
        write_compatibility_logs: bool = False,
    ) -> None:
        self.db_path = Path(db_path)
        self.output_csv_path = Path(output_csv_path)
        self.input_csv_path = Path(input_csv_path)
        self.write_compatibility_logs = write_compatibility_logs
        self._write_lock = Lock()
        self._next_flow_id = 1
        self._alerts: List[Dict[str, Any]] = []

    def reset_runtime_data(self, clear_csv_logs: bool = True) -> None:
        with self._write_lock:
            self._alerts.clear()
            self._next_flow_id = 1

        if clear_csv_logs:
            if self.write_compatibility_logs:
                self.output_csv_path.write_text("", encoding="utf-8-sig")
                self.input_csv_path.write_text("", encoding="utf-8-sig")
            else:
                for path in (self.output_csv_path, self.input_csv_path):
                    if path.exists():
                        path.unlink()

    def save_alert(self, record: Dict[str, Any]) -> Dict[str, Any]:
        base_record = ordered_record(dict(record))
        with self._write_lock:
            flow_id = self._next_flow_id
            self._next_flow_id += 1
            base_record["FlowID"] = flow_id
            stored_record = ordered_record(base_record)
            self._alerts.append(stored_record)

        self._append_compatibility_logs(stored_record)
        return dict(stored_record)

    def get_alert(self, flow_id: int) -> Dict[str, Any] | None:
        with self._write_lock:
            for record in self._alerts:
                if int(record.get("FlowID") or -1) == flow_id:
                    return dict(record)
        return None

    def query_alerts(self, filters: Dict[str, Any], limit: int = 200, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        with self._write_lock:
            filtered_rows = [dict(record) for record in self._alerts if self._matches_filters(record, filters)]

        filtered_rows.sort(key=lambda record: int(record.get("FlowID") or 0), reverse=True)
        total = len(filtered_rows)
        rows = filtered_rows[offset : offset + limit]
        return rows, total

    def top_sources(self, filters: Dict[str, Any] | None = None, limit: int = 10) -> List[Dict[str, Any]]:
        counts: Dict[str, int] = {}
        active_filters = filters or {}
        with self._write_lock:
            for record in self._alerts:
                if not self._matches_filters(record, active_filters):
                    continue
                source_ip = str(record.get("Src") or "").strip()
                if not source_ip:
                    continue
                counts[source_ip] = counts.get(source_ip, 0) + 1

        ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        return [{"SourceIP": source_ip, "count": count} for source_ip, count in ranked[:limit]]

    def load_source_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        with self._write_lock:
            for record in self._alerts:
                source_ip = str(record.get("Src") or "").strip()
                if not source_ip:
                    continue
                counts[source_ip] = counts.get(source_ip, 0) + 1
        return counts

    def export_alerts_csv(self, filters: Dict[str, Any]) -> str:
        rows, _ = self.query_alerts(filters, limit=100000, offset=0)
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=["FlowID"] + MODEL_FEATURE_FIELDS + FLOW_METADATA_FIELDS + ["Classification", "Probability", "Risk", "ServiceHints"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        return output.getvalue()

    def iter_alerts_csv(self, filters: Dict[str, Any], batch_size: int = 1000):
        fieldnames = ["FlowID"] + MODEL_FEATURE_FIELDS + FLOW_METADATA_FIELDS + ["Classification", "Probability", "Risk", "ServiceHints"]
        header_buffer = io.StringIO()
        writer = csv.DictWriter(header_buffer, fieldnames=fieldnames)
        writer.writeheader()
        yield header_buffer.getvalue()

        rows, _ = self.query_alerts(filters, limit=100000, offset=0)
        offset = 0
        while offset < len(rows):
            chunk_rows = rows[offset : offset + batch_size]
            chunk_buffer = io.StringIO()
            chunk_writer = csv.DictWriter(chunk_buffer, fieldnames=fieldnames)
            for row in chunk_rows:
                chunk_writer.writerow(row)
            yield chunk_buffer.getvalue()
            offset += batch_size

    def _matches_filters(self, record: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        query = str(filters.get("q") or "").strip().lower()
        if query:
            searchable_values = [
                str(record.get("Src") or ""),
                str(record.get("Dest") or ""),
                str(record.get("Protocol") or ""),
                str(record.get("PName") or ""),
                str(record.get("Classification") or ""),
                str(record.get("Risk") or ""),
                str(record.get("SrcPort") or ""),
                str(record.get("DestPort") or ""),
                str(record.get("PID") or ""),
                json.dumps(ordered_record(record), ensure_ascii=False),
            ]
            if not any(query in value.lower() for value in searchable_values):
                return False

        risk_value = str(filters.get("risk") or "").strip()
        if risk_value:
            if str(record.get("Risk") or "") not in set(risk_filter_values(risk_value)):
                return False

        prediction_value = str(filters.get("prediction") or "").strip()
        if prediction_value:
            prediction_values = set(prediction_filter_values(prediction_value))
            classification = str(record.get("Classification") or "")
            service_hints = [str(hint) for hint in list(record.get("ServiceHints") or []) if hint]
            if classification not in prediction_values and not any(hint in prediction_values for hint in service_hints):
                return False

        protocol_value = str(filters.get("protocol") or "").strip().upper()
        if protocol_value and str(record.get("Protocol") or "").strip().upper() != protocol_value:
            return False

        return True

    def _append_compatibility_logs(self, record: Dict[str, Any]) -> None:
        if not self.write_compatibility_logs:
            return

        model_values = [record[field] for field in MODEL_FEATURE_FIELDS]
        flow_info = [record[field] for field in FLOW_METADATA_FIELDS]
        prediction_row = [record["Classification"], record["Probability"], record["Risk"]]

        with self.output_csv_path.open("a", newline="", encoding="utf-8-sig") as output_file:
            writer = csv.writer(output_file)
            writer.writerow([f"Flow #{record['FlowID']}"])
            writer.writerow(["Flow info:"] + flow_info)
            writer.writerow(["Flow features:"] + model_values)
            writer.writerow(["Prediction:"] + prediction_row)
            writer.writerow(["-" * 98])

        with self.input_csv_path.open("a", newline="", encoding="utf-8-sig") as input_file:
            writer = csv.writer(input_file)
            writer.writerow([f"Flow #{record['FlowID']}"])
            writer.writerow(["Flow info:"] + model_values)
            writer.writerow(["-" * 98])
