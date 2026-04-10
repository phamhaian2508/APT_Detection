from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, Tuple

from backend.features import risk_label_from_probability, translate_prediction_label, translate_risk_label


SSH_PORT = 22


@dataclass(frozen=True)
class SSHHeuristicMatch:
    classification: str
    probability: float
    risk: str
    attempts: int


class SSHBruteForceHeuristic:
    def __init__(
        self,
        window_seconds: int = 60,
        min_attempts: int = 4,
        service_min_attempts: int = 1,
        max_flow_duration_us: int = 15_000_000,
        service_max_flow_duration_us: int = 12_000_000,
        max_bwd_payload_bytes: int = 120,
        max_packet_len_bytes: int = 180,
        base_probability: float = 0.65,
        probability_step: float = 0.08,
    ) -> None:
        self.window_seconds = window_seconds
        self.min_attempts = min_attempts
        self.service_min_attempts = service_min_attempts
        self.max_flow_duration_us = max_flow_duration_us
        self.service_max_flow_duration_us = service_max_flow_duration_us
        self.max_bwd_payload_bytes = max_bwd_payload_bytes
        self.max_packet_len_bytes = max_packet_len_bytes
        self.base_probability = base_probability
        self.probability_step = probability_step
        self._recent_attempts: Dict[Tuple[str, str, int], Deque[float]] = {}

    def evaluate(self, record: Dict[str, object], current_prediction: str) -> SSHHeuristicMatch | None:
        if translate_prediction_label(current_prediction) != translate_prediction_label("Benign"):
            return None

        candidate = self._candidate_key(record)
        if candidate is None:
            return None

        key, event_time = candidate
        attempts = self._register_attempt(key, event_time)
        required_attempts = self.service_min_attempts if self._is_server_side_ssh_service(record) else self.min_attempts
        if attempts < required_attempts:
            return None

        score = min(self.base_probability + ((attempts - required_attempts) * self.probability_step), 0.98)
        return SSHHeuristicMatch(
            classification=translate_prediction_label("SSH-Patator"),
            probability=score,
            risk=translate_risk_label(risk_label_from_probability(score)),
            attempts=attempts,
        )

    def _candidate_key(self, record: Dict[str, object]) -> Tuple[Tuple[str, str, int], float] | None:
        protocol = str(record.get("Protocol") or "").upper()
        src = str(record.get("Src") or "")
        dest = str(record.get("Dest") or "")
        src_port = self._to_int(record.get("SrcPort"))
        dest_port = self._to_int(record.get("DestPort"))
        duration = self._to_float(record.get("FlowDuration"))
        syn_flags = self._to_float(record.get("SYNFlagCount"))
        ack_flags = self._to_float(record.get("ACKFlagCount"))
        psh_flags = self._to_float(record.get("PSHFlagCount"))
        bwd_packet_mean = self._to_float(record.get("BwdPacketLenMean"))
        avg_bwd_segment = self._to_float(record.get("AvgBwdSegmentSize"))
        max_packet_len = self._to_float(record.get("MaxPacketLen"))

        if protocol != "TCP":
            return None
        if src_port != SSH_PORT and dest_port != SSH_PORT:
            return None
        if duration <= 0 or duration > self.max_flow_duration_us:
            return None
        if syn_flags < 1 or ack_flags < 1:
            return None

        low_exchange = max(bwd_packet_mean, avg_bwd_segment) <= self.max_bwd_payload_bytes
        control_heavy = max_packet_len <= self.max_packet_len_bytes or psh_flags <= 1
        if not (low_exchange or control_heavy):
            return None

        event_time = self._parse_timestamp(record.get("FlowLastSeen")) or self._parse_timestamp(record.get("FlowStartTime"))
        if event_time is None:
            return None

        if dest_port == SSH_PORT:
            client_ip, server_ip = src, dest
        else:
            client_ip, server_ip = dest, src

        if not client_ip or not server_ip:
            return None

        return (client_ip, server_ip, SSH_PORT), event_time

    def _is_server_side_ssh_service(self, record: Dict[str, object]) -> bool:
        process_name = str(record.get("PName") or "").strip().lower()
        duration = self._to_float(record.get("FlowDuration"))
        src_port = self._to_int(record.get("SrcPort"))
        dest_port = self._to_int(record.get("DestPort"))

        if duration <= 0 or duration > self.service_max_flow_duration_us:
            return False
        if src_port != SSH_PORT and dest_port != SSH_PORT:
            return False
        return "sshd" in process_name or process_name == "ssh"

    def _register_attempt(self, key: Tuple[str, str, int], event_time: float) -> int:
        attempts = self._recent_attempts.setdefault(key, deque())
        cutoff = event_time - self.window_seconds
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        attempts.append(event_time)
        return len(attempts)

    @staticmethod
    def _parse_timestamp(value: object) -> float | None:
        if isinstance(value, datetime):
            return value.timestamp()
        if isinstance(value, str):
            try:
                return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                return None
        return None

    @staticmethod
    def _to_float(value: object) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _to_int(value: object) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0
