from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, Iterable, Tuple

from backend.features import risk_label_from_probability, translate_prediction_label, translate_risk_label


@dataclass(frozen=True)
class ServiceHeuristicMatch:
    classification: str
    probability: float
    risk: str
    attempts: int


class ServiceBruteForceHeuristic:
    def __init__(
        self,
        label: str,
        service_ports: Iterable[int],
        window_seconds: int = 60,
        min_attempts: int = 4,
        max_flow_duration_us: int = 15_000_000,
        max_packet_rate_threshold: float = 60.0,
        max_short_burst_forward_packets: float = 3.0,
        max_bwd_payload_bytes: int = 220,
        max_packet_len_bytes: int = 260,
        max_psh_flags: int = 2,
        base_probability: float = 0.64,
        probability_step: float = 0.08,
    ) -> None:
        self.label = label
        self.service_ports = tuple(sorted({int(port) for port in service_ports}))
        self.window_seconds = window_seconds
        self.min_attempts = min_attempts
        self.max_flow_duration_us = max_flow_duration_us
        self.max_packet_rate_threshold = max_packet_rate_threshold
        self.max_short_burst_forward_packets = max_short_burst_forward_packets
        self.max_bwd_payload_bytes = max_bwd_payload_bytes
        self.max_packet_len_bytes = max_packet_len_bytes
        self.max_psh_flags = max_psh_flags
        self.base_probability = base_probability
        self.probability_step = probability_step
        self._recent_attempts: Dict[Tuple[str, str, int], Deque[float]] = {}

    def evaluate(self, record: Dict[str, object], current_prediction: str) -> ServiceHeuristicMatch | None:
        candidate = self._candidate_key(record)
        if candidate is None:
            return None

        key, event_time = candidate
        attempts = self._register_attempt(key, event_time)
        if attempts < self.min_attempts:
            return None

        score = min(self.base_probability + ((attempts - self.min_attempts) * self.probability_step), 0.98)
        return ServiceHeuristicMatch(
            classification=translate_prediction_label(self.label),
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
        packet_rate = self._to_float(record.get("FwdPackets_s"))
        bwd_packet_mean = self._to_float(record.get("BwdPacketLenMean"))
        avg_bwd_segment = self._to_float(record.get("AvgBwdSegmentSize"))
        max_packet_len = self._to_float(record.get("MaxPacketLen"))

        if protocol != "TCP":
            return None
        if src_port not in self.service_ports and dest_port not in self.service_ports:
            return None
        if duration <= 0 or duration > self.max_flow_duration_us:
            return None
        estimated_forward_packets = packet_rate * (duration / 1_000_000.0)
        if (
            packet_rate > self.max_packet_rate_threshold
            and estimated_forward_packets > self.max_short_burst_forward_packets
        ):
            return None
        if syn_flags < 1 or ack_flags < 1:
            return None

        low_exchange = max(bwd_packet_mean, avg_bwd_segment) <= self.max_bwd_payload_bytes
        control_heavy = max_packet_len <= self.max_packet_len_bytes or psh_flags <= self.max_psh_flags
        if not (low_exchange or control_heavy):
            return None

        event_time = self._parse_timestamp(record.get("FlowLastSeen")) or self._parse_timestamp(record.get("FlowStartTime"))
        if event_time is None:
            return None

        if dest_port in self.service_ports:
            client_ip, server_ip, service_port = src, dest, dest_port
        else:
            client_ip, server_ip, service_port = dest, src, src_port

        if not client_ip or not server_ip:
            return None

        return (client_ip, server_ip, service_port), event_time

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


def build_rdp_bruteforce_heuristic() -> ServiceBruteForceHeuristic:
    return ServiceBruteForceHeuristic(
        label="RDP-Patator",
        service_ports=(3389,),
        max_flow_duration_us=18_000_000,
        max_packet_rate_threshold=32.0,
        max_bwd_payload_bytes=220,
        max_packet_len_bytes=280,
        base_probability=0.66,
    )


def build_smb_bruteforce_heuristic() -> ServiceBruteForceHeuristic:
    return ServiceBruteForceHeuristic(
        label="SMB-Patator",
        service_ports=(445,),
        max_flow_duration_us=15_000_000,
        max_packet_rate_threshold=40.0,
        max_bwd_payload_bytes=260,
        max_packet_len_bytes=320,
        base_probability=0.64,
    )


def build_ldap_bruteforce_heuristic() -> ServiceBruteForceHeuristic:
    return ServiceBruteForceHeuristic(
        label="LDAP-Patator",
        service_ports=(389, 636, 3268, 3269),
        max_flow_duration_us=16_000_000,
        max_packet_rate_threshold=34.0,
        max_bwd_payload_bytes=240,
        max_packet_len_bytes=300,
        base_probability=0.65,
    )


def build_telnet_bruteforce_heuristic() -> ServiceBruteForceHeuristic:
    return ServiceBruteForceHeuristic(
        label="Telnet-Patator",
        service_ports=(23,),
        max_flow_duration_us=12_000_000,
        max_packet_rate_threshold=24.0,
        max_bwd_payload_bytes=160,
        max_packet_len_bytes=220,
        max_psh_flags=1,
        base_probability=0.63,
    )


def build_smtp_bruteforce_heuristic() -> ServiceBruteForceHeuristic:
    return ServiceBruteForceHeuristic(
        label="SMTP-Patator",
        service_ports=(25, 587),
        max_flow_duration_us=18_000_000,
        max_packet_rate_threshold=36.0,
        max_bwd_payload_bytes=240,
        max_packet_len_bytes=320,
        base_probability=0.64,
    )
