import logging
import unittest
from types import SimpleNamespace

from backend.web import AppRuntime


class _SocketStub:
    def __init__(self):
        self.emitted = []

    def emit(self, event, payload, namespace=None):
        self.emitted.append((event, payload, namespace))

    def start_background_task(self, target, *args, **kwargs):
        return None


class _RepositoryStub:
    def load_source_counts(self):
        return {}


class _InferenceStub:
    def __init__(self):
        self.preview_calls = []

    def classify_preview(self, features):
        self.preview_calls.append(list(features))
        return {
            "FlowID": "preview",
            "Src": "10.0.0.1",
            "SrcPort": 12345,
            "Dest": "10.0.0.2",
            "DestPort": 80,
            "Protocol": "TCP",
            "FlowStartTime": "2026-04-11 10:00:00",
            "FlowLastSeen": "2026-04-11 10:00:01",
            "PName": "app.exe",
            "PID": 100,
            "Classification": "Lưu lượng hợp lệ",
            "Probability": 0.73,
            "Risk": "Thấp",
        }

    def build_stream_payload(self, record):
        return {
            "id": record["FlowID"],
            "flowKey": "{src}-{dst}-{src_port}-{dst_port}-{protocol}".format(
                src=record["Src"],
                dst=record["Dest"],
                src_port=record["SrcPort"],
                dst_port=record["DestPort"],
                protocol=record["Protocol"],
            ),
            "src": record["Src"],
            "srcDisplay": record["Src"],
            "srcPort": record["SrcPort"],
            "dst": record["Dest"],
            "dstDisplay": record["Dest"],
            "dstPort": record["DestPort"],
            "protocol": record["Protocol"],
            "start": record["FlowStartTime"],
            "lastSeen": record["FlowLastSeen"],
            "appName": record["PName"],
            "pid": record["PID"],
            "prediction": record["Classification"],
            "probability": record["Probability"],
            "risk": record["Risk"],
            "isPriority": False,
            "isProvisional": False,
        }


class _FlowStub:
    def preview_features(self):
        return [0.0] * 48


class AppRuntimeTests(unittest.TestCase):
    def _runtime(self):
        socketio = _SocketStub()
        inference = _InferenceStub()
        config = SimpleNamespace(
            queue_size=16,
            flow_timeout=5,
            sniff_timeout=1.0,
            process_refresh_interval=1.0,
        )
        runtime = AppRuntime(
            socketio=socketio,
            repository=_RepositoryStub(),
            inference=inference,
            config=config,
            logger=logging.getLogger("tests.runtime"),
        )
        return runtime, socketio, inference

    def test_build_live_payload_includes_probability_for_provisional_flow(self):
        runtime, _, inference = self._runtime()
        runtime.capture.current_flows["flow-key"] = _FlowStub()

        payload = runtime.build_live_payload("flow-key")

        self.assertIsNotNone(payload)
        self.assertEqual(payload["id"], "flow-key")
        self.assertTrue(payload["isProvisional"])
        self.assertEqual(payload["probability"], 0.73)
        self.assertEqual(len(inference.preview_calls), 1)

    def test_handle_live_flow_update_defaults_missing_probability_to_zero(self):
        runtime, socketio, _ = self._runtime()

        runtime.handle_live_flow_update({"flowKey": "missing-flow", "probability": ""})

        self.assertEqual(len(socketio.emitted), 1)
        _, payload, _ = socketio.emitted[0]
        self.assertEqual(payload["result"]["probability"], 0.0)


if __name__ == "__main__":
    unittest.main()
