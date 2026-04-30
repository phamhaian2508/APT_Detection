from __future__ import annotations

import csv
import io
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterator, List, Tuple

from backend.features import (
    FLOW_METADATA_FIELDS,
    MODEL_FEATURE_FIELDS,
    ordered_record,
    prediction_filter_values,
    risk_filter_values,
    risk_rank,
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
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_csv_path = Path(output_csv_path)
        self.input_csv_path = Path(input_csv_path)
        self.write_compatibility_logs = write_compatibility_logs
        self._write_lock = Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.execute("PRAGMA journal_mode=WAL;")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    flow_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    classification TEXT NOT NULL,
                    probability REAL NOT NULL,
                    risk TEXT NOT NULL,
                    risk_rank INTEGER NOT NULL,
                    src TEXT,
                    src_port INTEGER,
                    dest TEXT,
                    dest_port INTEGER,
                    protocol TEXT,
                    flow_start_time TEXT,
                    flow_last_seen TEXT,
                    pname TEXT,
                    pid TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    record_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_risk_rank ON alerts (risk_rank DESC)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_classification ON alerts (classification)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_protocol ON alerts (protocol)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts (src)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dest ON alerts (dest)")
            connection.commit()

    def reset_runtime_data(self, clear_csv_logs: bool = True) -> None:
        with self._write_lock:
            with self._connection() as connection:
                connection.execute("DELETE FROM alerts")
                connection.execute("DELETE FROM sqlite_sequence WHERE name = 'alerts'")
                connection.commit()

        if clear_csv_logs:
            if self.write_compatibility_logs:
                self.output_csv_path.write_text("", encoding="utf-8-sig")
                self.input_csv_path.write_text("", encoding="utf-8-sig")
            else:
                for path in (self.output_csv_path, self.input_csv_path):
                    if path.exists():
                        path.unlink()

    def save_alert(self, record: Dict[str, Any]) -> Dict[str, Any]:
        base_record = dict(record)
        with self._write_lock:
            with self._connection() as connection:
                cursor = connection.execute(
                    """
                    INSERT INTO alerts (
                        classification,
                        probability,
                        risk,
                        risk_rank,
                        src,
                        src_port,
                        dest,
                        dest_port,
                        protocol,
                        flow_start_time,
                        flow_last_seen,
                        pname,
                        pid,
                        record_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        base_record["Classification"],
                        float(base_record["Probability"]),
                        base_record["Risk"],
                        risk_rank(base_record["Risk"]),
                        base_record["Src"],
                        base_record["SrcPort"],
                        base_record["Dest"],
                        base_record["DestPort"],
                        base_record["Protocol"],
                        base_record["FlowStartTime"],
                        base_record["FlowLastSeen"],
                        base_record["PName"],
                        str(base_record["PID"]) if base_record["PID"] is not None else None,
                        "{}",
                    ),
                )
                flow_id = int(cursor.lastrowid)
                base_record["FlowID"] = flow_id
                payload = json.dumps(ordered_record(base_record), ensure_ascii=False)
                connection.execute("UPDATE alerts SET record_json = ? WHERE flow_id = ?", (payload, flow_id))
                connection.commit()

            self._append_compatibility_logs(base_record)
        return base_record

    def get_alert(self, flow_id: int) -> Dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT record_json FROM alerts WHERE flow_id = ?", (flow_id,)).fetchone()
        if row is None:
            return None
        return json.loads(row["record_json"])

    def query_alerts(self, filters: Dict[str, Any], limit: int = 200, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        where_clause, params = self._build_where_clause(filters)
        with self._connection() as connection:
            rows = connection.execute(
                f"""
                SELECT record_json
                FROM alerts
                {where_clause}
                ORDER BY flow_id DESC
                LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            ).fetchall()
            total = connection.execute(
                f"SELECT COUNT(*) AS total FROM alerts {where_clause}",
                params,
            ).fetchone()["total"]
        return [json.loads(row["record_json"]) for row in rows], int(total)

    def top_sources(self, filters: Dict[str, Any] | None = None, limit: int = 10) -> List[Dict[str, Any]]:
        where_clause, params = self._build_where_clause(filters or {})
        with self._connection() as connection:
            rows = connection.execute(
                f"""
                SELECT src AS SourceIP, COUNT(*) AS count
                FROM alerts
                {where_clause}
                GROUP BY src
                ORDER BY count DESC, src ASC
                LIMIT ?
                """,
                params + [limit],
            ).fetchall()
        return [{"SourceIP": row["SourceIP"], "count": row["count"]} for row in rows if row["SourceIP"]]

    def load_source_counts(self) -> Dict[str, int]:
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT src, COUNT(*) AS count
                FROM alerts
                WHERE src IS NOT NULL AND src != ''
                GROUP BY src
                """
            ).fetchall()
        return {row["src"]: int(row["count"]) for row in rows}

    def export_alerts_csv(self, filters: Dict[str, Any]) -> str:
        rows, _ = self.query_alerts(filters, limit=100000, offset=0)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["FlowID"] + MODEL_FEATURE_FIELDS + FLOW_METADATA_FIELDS + ["Classification", "Probability", "Risk", "ServiceHints"])
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        return output.getvalue()

    def iter_alerts_csv(self, filters: Dict[str, Any], batch_size: int = 1000) -> Iterator[str]:
        fieldnames = ["FlowID"] + MODEL_FEATURE_FIELDS + FLOW_METADATA_FIELDS + ["Classification", "Probability", "Risk", "ServiceHints"]
        header_buffer = io.StringIO()
        writer = csv.DictWriter(header_buffer, fieldnames=fieldnames)
        writer.writeheader()
        yield header_buffer.getvalue()

        where_clause, params = self._build_where_clause(filters)
        offset = 0
        while True:
            with self._connection() as connection:
                rows = connection.execute(
                    f"""
                    SELECT record_json
                    FROM alerts
                    {where_clause}
                    ORDER BY flow_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    params + [batch_size, offset],
                ).fetchall()

            if not rows:
                break

            chunk_buffer = io.StringIO()
            chunk_writer = csv.DictWriter(chunk_buffer, fieldnames=fieldnames)
            for row in rows:
                chunk_writer.writerow(json.loads(row["record_json"]))
            yield chunk_buffer.getvalue()
            offset += batch_size

    def _build_where_clause(self, filters: Dict[str, Any]) -> Tuple[str, List[Any]]:
        conditions: List[str] = []
        params: List[Any] = []

        query = (filters.get("q") or "").strip()
        if query:
            like_value = f"%{query}%"
            search_conditions = [
                "src LIKE ?",
                "dest LIKE ?",
                "protocol LIKE ?",
                "pname LIKE ?",
                "classification LIKE ?",
                "risk LIKE ?",
                "record_json LIKE ?",
                "CAST(src_port AS TEXT) LIKE ?",
                "CAST(dest_port AS TEXT) LIKE ?",
                "CAST(pid AS TEXT) LIKE ?",
            ]
            conditions.append("(" + " OR ".join(search_conditions) + ")")
            params.extend([like_value] * len(search_conditions))

        risk_value = (filters.get("risk") or "").strip()
        if risk_value:
            risk_values = risk_filter_values(risk_value)
            conditions.append("risk IN (" + ", ".join(["?"] * len(risk_values)) + ")")
            params.extend(risk_values)

        prediction_value = (filters.get("prediction") or "").strip()
        if prediction_value:
            prediction_values = prediction_filter_values(prediction_value)
            prediction_conditions = ["classification IN (" + ", ".join(["?"] * len(prediction_values)) + ")"]
            prediction_params: List[Any] = list(prediction_values)

            hint_conditions = ["record_json LIKE ?" for _ in prediction_values]
            prediction_conditions.append("(" + " OR ".join(hint_conditions) + ")")
            prediction_params.extend([f"%{value}%" for value in prediction_values])

            conditions.append("(" + " OR ".join(prediction_conditions) + ")")
            params.extend(prediction_params)

        protocol_value = (filters.get("protocol") or "").strip()
        if protocol_value:
            conditions.append("protocol = ?")
            params.append(protocol_value)

        if not conditions:
            return "", params
        return "WHERE " + " AND ".join(conditions), params

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
