from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock
import logging
import time
from typing import Any, Dict

from flask import Flask, Response, abort, jsonify, render_template, request, send_from_directory
from flask_socketio import SocketIO

from backend.config import AppConfig
from backend.capture import CaptureService
from backend.features import build_alert_record, demo_prediction_filter_labels, translate_prediction_label, translate_risk_label
from backend.inference import InferenceService
from backend.logging_utils import setup_logging
from backend.storage import AlertRepository


class AppRuntime:
    def __init__(self, socketio: SocketIO, repository: AlertRepository, inference: InferenceService, config: AppConfig, logger: logging.Logger) -> None:
        self.socketio = socketio
        self.repository = repository
        self.inference = inference
        self.config = config
        self.logger = logger
        self.capture = CaptureService(
            self.handle_terminated_flow,
            on_flow_updated=self.handle_live_flow_update,
            flow_timeout=config.flow_timeout,
            sniff_timeout=config.sniff_timeout,
            process_refresh_interval=config.process_refresh_interval,
            logger=logger.getChild("capture"),
        )
        self.thread_stop_event = Event()
        self.capture_thread = None
        self.worker_thread = None
        self.thread_lock = Lock()
        self.metrics_lock = Lock()
        self.flow_queue: Queue[list] = Queue(maxsize=config.queue_size)
        self.dropped_flows = 0
        self.worker_errors = 0
        self.processed_flows = 0
        self.started_at = time.time()
        self.source_counts = Counter(self.repository.load_source_counts())

    def handle_terminated_flow(self, features: list) -> None:
        try:
            self.flow_queue.put_nowait(list(features))
        except Full:
            with self.metrics_lock:
                self.dropped_flows += 1
                dropped_count = self.dropped_flows
            if dropped_count % 100 == 1:
                self.logger.warning("Flow queue full, dropped %s terminated flows.", dropped_count)
            return

    def handle_live_flow_update(self, snapshot: dict[str, Any]) -> None:
        flow_key = str(snapshot.get("flowKey") or "")
        payload = self.build_live_payload(flow_key)
        if payload is None:
            payload = dict(snapshot)
            if payload.get("probability") in ("", None):
                payload["probability"] = 0.0
        else:
            payload["packetsSeen"] = snapshot.get("packetsSeen")
        self.socketio.emit(
            "newresult",
            {
                "result": payload,
                "ips": self.top_sources_snapshot(limit=10),
            },
            namespace="/test",
        )

    def build_live_record(self, flow_key: str) -> Dict[str, Any] | None:
        flow = self.capture.current_flows.get(flow_key)
        if flow is None:
            return None

        features = flow.preview_features()
        record = self.inference.classify_preview(features)
        if record is None:
            record = build_alert_record(
                features,
                translate_prediction_label("Benign"),
                0.0,
                translate_risk_label("Low"),
            )

        live_record = dict(record)
        live_record["FlowID"] = flow_key
        return live_record

    def build_live_payload(self, flow_key: str) -> Dict[str, Any] | None:
        record = self.build_live_record(flow_key)
        if record is None:
            return None

        payload = self.inference.build_stream_payload(record)
        payload["id"] = flow_key
        payload["isProvisional"] = True
        return payload

    def start_capture(self) -> None:
        with self.thread_lock:
            if self.worker_thread is None or not self.worker_thread.is_alive():
                self.worker_thread = self.socketio.start_background_task(self._run_flow_worker)
                self.logger.info("Worker thread started.")
            if self.capture_thread is not None and self.capture_thread.is_alive():
                return
            self.capture_thread = self.socketio.start_background_task(self.capture.sniff_forever, self.thread_stop_event)
            self.logger.info("Capture thread started.")

    def reset_runtime_data(self, clear_csv_logs: bool = True) -> None:
        self.repository.reset_runtime_data(clear_csv_logs=clear_csv_logs)
        with self.thread_lock:
            self.capture.current_flows.clear()
            self.capture._last_live_update.clear()

        while True:
            try:
                features = self.flow_queue.get_nowait()
            except Empty:
                break
            else:
                self.flow_queue.task_done()

        with self.metrics_lock:
            self.dropped_flows = 0
            self.worker_errors = 0
            self.processed_flows = 0
            self.started_at = time.time()
            self.source_counts = Counter()

    def _run_flow_worker(self) -> None:
        while not self.thread_stop_event.is_set() or not self.flow_queue.empty():
            try:
                features = self.flow_queue.get(timeout=1.0)
            except Empty:
                continue

            try:
                self._process_terminated_flow(features)
            except Exception:
                with self.metrics_lock:
                    self.worker_errors += 1
                self.logger.exception("Unhandled error while processing terminated flow.")
            finally:
                self.flow_queue.task_done()

    def _process_terminated_flow(self, features: list) -> None:
        record = self.inference.classify(features)
        if record is None:
            return

        stored_record = self.repository.save_alert(record)
        self._register_source(stored_record.get("Src"))
        with self.metrics_lock:
            self.processed_flows += 1
        payload = self.inference.build_stream_payload(stored_record)
        self.socketio.emit(
            "newresult",
            {
                "result": payload,
                "ips": self.top_sources_snapshot(limit=10),
            },
            namespace="/test",
        )

    def _register_source(self, source_ip: str | None) -> None:
        if not source_ip:
            return
        with self.metrics_lock:
            self.source_counts[source_ip] += 1

    def top_sources_snapshot(self, limit: int = 10) -> list[dict[str, int | str]]:
        with self.metrics_lock:
            most_common = self.source_counts.most_common(limit)
        return [{"SourceIP": source_ip, "count": count} for source_ip, count in most_common]

    def status_snapshot(self) -> Dict[str, Any]:
        with self.metrics_lock:
            return {
                "queue_size": self.flow_queue.qsize(),
                "queue_capacity": self.config.queue_size,
                "dropped_flows": self.dropped_flows,
                "worker_errors": self.worker_errors,
                "processed_flows": self.processed_flows,
                "known_sources": len(self.source_counts),
                "active_flows": len(self.capture.current_flows),
                "capture_alive": bool(self.capture_thread and self.capture_thread.is_alive()),
                "worker_alive": bool(self.worker_thread and self.worker_thread.is_alive()),
                "uptime_seconds": int(time.time() - self.started_at),
                "flow_timeout": self.config.flow_timeout,
                "sniff_timeout": self.config.sniff_timeout,
                "geolocation_enabled": self.config.enable_geolocation,
                "explanations_enabled": self.config.enable_explanations,
            }


def _extract_filters(args: Dict[str, Any]) -> Dict[str, str]:
    return {
        "q": (args.get("q") or "").strip(),
        "risk": (args.get("risk") or "").strip(),
        "prediction": (args.get("prediction") or "").strip(),
        "protocol": (args.get("protocol") or "").strip().upper(),
    }


def create_app() -> tuple[Flask, SocketIO]:
    project_root = Path(__file__).resolve().parent.parent
    config = AppConfig.from_env(project_root)
    logger = setup_logging(config.log_level, config.log_file)
    app = Flask(
        __name__,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
    )
    app.config["SECRET_KEY"] = config.secret_key
    app.config["DEBUG"] = config.debug

    socketio = SocketIO(app, async_mode=None, logger=config.socketio_logging, engineio_logger=config.socketio_logging)
    repository = AlertRepository(
        db_path=config.db_path,
        output_csv_path=config.output_csv_path,
        input_csv_path=config.input_csv_path,
        write_compatibility_logs=config.write_compatibility_logs,
    )
    if config.reset_data_on_start:
        repository.reset_runtime_data(clear_csv_logs=True)
    inference = InferenceService(
        enable_geolocation=config.enable_geolocation,
        enable_explanations=config.enable_explanations,
        enable_service_bruteforce_heuristics=config.enable_service_bruteforce_heuristics,
        logger=logger.getChild("inference"),
    )
    runtime = AppRuntime(socketio, repository, inference, config, logger.getChild("runtime"))
    app.extensions["apt_runtime"] = runtime
    app.extensions["apt_config"] = config
    logger.info(
        "Application initialized. DB=%s, queue_size=%s, reset_on_start=%s, auto_start_capture=%s",
        config.db_path,
        config.queue_size,
        config.reset_data_on_start,
        config.auto_start_capture,
    )
    if config.auto_start_capture:
        runtime.start_capture()
        logger.info("Capture auto-start is enabled.")

    @app.route("/")
    def index():
        runtime.reset_runtime_data(clear_csv_logs=True)
        runtime.start_capture()
        return render_template(
            "index.html",
            prediction_filter_options=demo_prediction_filter_labels(),
        )

    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory(app.static_folder, "images/mlogo.png", mimetype="image/png")

    @app.route("/flow-detail")
    def flow_detail():
        flow_id = request.args.get("flow_id", default=-1, type=int)
        flow_key = (request.args.get("flow_key") or "").strip()
        record = repository.get_alert(flow_id)
        if record is None and flow_key:
            record = runtime.build_live_record(flow_key)
        if record is None:
            abort(404)

        detail_context = inference.build_detail_context(record)
        return render_template(
            "detail.html",
            tables=[detail_context["flow_table"]],
            exp=detail_context["explanation_html"],
            ae_plot=detail_context["ae_plot"],
            risk=detail_context["risk_html"],
        )

    @app.route("/api/alerts")
    def api_alerts():
        filters = _extract_filters(request.args)
        limit = min(max(request.args.get("limit", default=200, type=int), 1), 500)
        offset = max(request.args.get("offset", default=0, type=int), 0)
        rows, total = repository.query_alerts(filters, limit=limit, offset=offset)
        top_sources = runtime.top_sources_snapshot(limit=10) if not any(filters.values()) else repository.top_sources(filters, limit=10)
        return jsonify(
            {
                "items": [inference.build_stream_payload(row) for row in rows],
                "total": total,
                "top_sources": top_sources,
            }
        )

    @app.route("/api/alerts/export")
    def export_alerts():
        filters = _extract_filters(request.args)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return Response(
            repository.iter_alerts_csv(filters),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="alerts_{timestamp}.csv"'},
        )

    @app.route("/api/runtime-status")
    def runtime_status():
        return jsonify(runtime.status_snapshot())

    @socketio.on("connect", namespace="/test")
    def test_connect():
        logger.info("Socket client connected.")
        runtime.start_capture()

    @socketio.on("disconnect", namespace="/test")
    def test_disconnect():
        logger.info("Socket client disconnected.")

    return app, socketio
