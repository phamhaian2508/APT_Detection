from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Lock
import traceback
from typing import Any, Dict

from flask import Flask, Response, abort, jsonify, render_template, request
from flask_socketio import SocketIO

from backend.capture import CaptureService
from backend.inference import InferenceService
from backend.storage import AlertRepository


class AppRuntime:
    def __init__(self, socketio: SocketIO, repository: AlertRepository, inference: InferenceService) -> None:
        self.socketio = socketio
        self.repository = repository
        self.inference = inference
        self.capture = CaptureService(self.handle_terminated_flow)
        self.thread_stop_event = Event()
        self.capture_thread = None
        self.worker_thread = None
        self.thread_lock = Lock()
        self.metrics_lock = Lock()
        self.flow_queue: Queue[list] = Queue(maxsize=5000)
        self.dropped_flows = 0
        self.worker_errors = 0
        self.source_counts = Counter(self.repository.load_source_counts())

    def handle_terminated_flow(self, features: list) -> None:
        try:
            self.flow_queue.put_nowait(list(features))
        except Full:
            with self.metrics_lock:
                self.dropped_flows += 1
            if self.dropped_flows % 100 == 1:
                print(f"Warning: flow queue full, dropped {self.dropped_flows} terminated flows.")
            return

    def start_capture(self) -> None:
        with self.thread_lock:
            if self.worker_thread is None or not self.worker_thread.is_alive():
                self.worker_thread = self.socketio.start_background_task(self._run_flow_worker)
            if self.capture_thread is not None and self.capture_thread.is_alive():
                return
            self.capture_thread = self.socketio.start_background_task(self.capture.sniff_forever, self.thread_stop_event)

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
                traceback.print_exc()
            finally:
                self.flow_queue.task_done()

    def _process_terminated_flow(self, features: list) -> None:
        record = self.inference.classify(features)
        if record is None:
            return

        stored_record = self.repository.save_alert(record)
        self._register_source(stored_record.get("Src"))
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
                "dropped_flows": self.dropped_flows,
                "worker_errors": self.worker_errors,
                "known_sources": len(self.source_counts),
                "capture_alive": bool(self.capture_thread and self.capture_thread.is_alive()),
                "worker_alive": bool(self.worker_thread and self.worker_thread.is_alive()),
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
    app = Flask(
        __name__,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
    )
    app.config["SECRET_KEY"] = "secret!"
    app.config["DEBUG"] = False

    socketio = SocketIO(app, async_mode=None, logger=False, engineio_logger=False)
    repository = AlertRepository()
    inference = InferenceService()
    runtime = AppRuntime(socketio, repository, inference)
    app.extensions["apt_runtime"] = runtime

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/flow-detail")
    def flow_detail():
        flow_id = request.args.get("flow_id", default=-1, type=int)
        record = repository.get_alert(flow_id)
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
        print("Client connected")
        runtime.start_capture()

    @socketio.on("disconnect", namespace="/test")
    def test_disconnect():
        print("Client disconnected")

    return app, socketio
