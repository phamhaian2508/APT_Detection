from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, Tuple

from backend.features import translate_prediction_label, translate_risk_label


@dataclass(frozen=True)
class DNSHeuristicEvent:
    timestamp: float
    source_ip: str
    score: float


@dataclass(frozen=True)
class DNSHeuristicMatch:
    classification: str
    probability: float
    risk: str
    events: int
    unique_sources: int
    score: float


class DNSAbuseHeuristic:
    def __init__(
        self,
        window_seconds: int = 20,
        min_pair_events: int = 16,
        min_target_events: int = 24,
        min_multi_source_target_events: int = 18,
        min_multi_source_unique_sources: int = 3,
        max_flow_duration_us: int = 1_500_000,
        min_packet_rate_threshold: float = 24.0,
        high_packet_rate_threshold: float = 70.0,
        max_packet_len_bytes: int = 320,
        max_bwd_payload_bytes: int = 220,
    ) -> None:
        self.window_seconds = window_seconds
        self.min_pair_events = min_pair_events
        self.min_target_events = min_target_events
        self.min_multi_source_target_events = min_multi_source_target_events
        self.min_multi_source_unique_sources = min_multi_source_unique_sources
        self.max_flow_duration_us = max_flow_duration_us
        self.min_packet_rate_threshold = min_packet_rate_threshold
        self.high_packet_rate_threshold = high_packet_rate_threshold
        self.max_packet_len_bytes = max_packet_len_bytes
        self.max_bwd_payload_bytes = max_bwd_payload_bytes
        self._recent_pair_events: Dict[Tuple[str, str, str], Deque[DNSHeuristicEvent]] = {}
        self._recent_target_events: Dict[Tuple[str, str], Deque[DNSHeuristicEvent]] = {}

    def evaluate(self, record: Dict[str, object], current_prediction: str) -> DNSHeuristicMatch | None:
        normalized_prediction = translate_prediction_label(current_prediction)
        allowed_predictions = {
            translate_prediction_label("Benign"),
            translate_prediction_label("Probe"),
        }
        if normalized_prediction not in allowed_predictions:
            return None

        candidate = self._candidate(record)
        if candidate is None:
            return None

        pair_key, target_key, source_ip, event_time, packet_rate, flow_score = candidate
        event = DNSHeuristicEvent(timestamp=event_time, source_ip=source_ip, score=flow_score)
        pair_events, pair_score = self._register(self._recent_pair_events, pair_key, event)
        target_events, target_score = self._register(self._recent_target_events, target_key, event)
        unique_sources = len(Counter(item.source_ip for item in self._recent_target_events[target_key]))

        if not self._is_dns_abuse(pair_events, pair_score, target_events, target_score, unique_sources, packet_rate, flow_score):
            return None

        probability = self._probability(
            pair_events=pair_events,
            pair_score=pair_score,
            target_events=target_events,
            target_score=target_score,
            unique_sources=unique_sources,
            packet_rate=packet_rate,
            flow_score=flow_score,
        )
        return DNSHeuristicMatch(
            classification=translate_prediction_label("DNS-Abuse"),
            probability=probability,
            risk=translate_risk_label(
                self._risk_label(
                    pair_events=pair_events,
                    target_events=target_events,
                    unique_sources=unique_sources,
                    packet_rate=packet_rate,
                    flow_score=flow_score,
                )
            ),
            events=target_events,
            unique_sources=unique_sources,
            score=max(pair_score, target_score, flow_score),
        )

    def _candidate(
        self,
        record: Dict[str, object],
    ) -> Tuple[Tuple[str, str, str], Tuple[str, str], str, float, float, float] | None:
        protocol = str(record.get("Protocol") or "").upper()
        src = str(record.get("Src") or "")
        dest = str(record.get("Dest") or "")
        src_port = self._to_int(record.get("SrcPort"))
        dest_port = self._to_int(record.get("DestPort"))
        duration = self._to_float(record.get("FlowDuration"))
        packet_rate = self._to_float(record.get("FwdPackets_s"))
        max_packet_len = self._to_float(record.get("MaxPacketLen"))
        packet_len_mean = self._to_float(record.get("PacketLenMean"))
        avg_packet_size = self._to_float(record.get("AvgPacketSize"))
        bwd_packet_mean = self._to_float(record.get("BwdPacketLenMean"))
        avg_bwd_segment = self._to_float(record.get("AvgBwdSegmentSize"))

        if protocol not in {"UDP", "TCP"}:
            return None
        if not src or not dest:
            return None
        if dest_port != 53:
            return None
        if src_port == 53:
            return None
        if duration <= 0 or duration > self.max_flow_duration_us:
            return None
        if packet_rate < self.min_packet_rate_threshold:
            return None

        event_time = self._parse_timestamp(record.get("FlowLastSeen")) or self._parse_timestamp(record.get("FlowStartTime"))
        if event_time is None:
            return None

        positive_sizes = [value for value in (max_packet_len, packet_len_mean, avg_packet_size) if value > 0]
        characteristic_size = min(positive_sizes) if positive_sizes else 0.0
        if characteristic_size > self.max_packet_len_bytes:
            return None

        low_response = max(bwd_packet_mean, avg_bwd_segment) <= self.max_bwd_payload_bytes
        if not low_response:
            return None

        client_ip, server_ip = src, dest

        flow_score = self._flow_score(
            protocol=protocol,
            duration=duration,
            packet_rate=packet_rate,
            low_response=low_response,
            characteristic_size=characteristic_size,
        )
        pair_key = (client_ip, server_ip, protocol)
        target_key = (server_ip, protocol)
        return pair_key, target_key, client_ip, event_time, packet_rate, flow_score

    def _is_dns_abuse(
        self,
        pair_events: int,
        pair_score: float,
        target_events: int,
        target_score: float,
        unique_sources: int,
        packet_rate: float,
        flow_score: float,
    ) -> bool:
        average_pair_score = pair_score / max(pair_events, 1)
        if pair_events >= self.min_pair_events and average_pair_score >= 6.3 and packet_rate >= self.min_packet_rate_threshold:
            return True
        if target_events >= self.min_target_events and target_score >= 150.0 and unique_sources >= 2:
            return True
        if (
            target_events >= self.min_multi_source_target_events
            and unique_sources >= self.min_multi_source_unique_sources
            and target_score >= 110.0
        ):
            return True
        return packet_rate >= (self.high_packet_rate_threshold * 1.5) and flow_score >= 6.9

    def _probability(
        self,
        pair_events: int,
        pair_score: float,
        target_events: int,
        target_score: float,
        unique_sources: int,
        packet_rate: float,
        flow_score: float,
    ) -> float:
        average_pair_score = pair_score / max(pair_events, 1)
        pair_bonus = self._normalize(pair_events, lower=self.min_pair_events, upper=self.min_pair_events + 20)
        target_bonus = self._normalize(target_events, lower=self.min_target_events, upper=self.min_target_events + 28)
        source_bonus = self._normalize(
            unique_sources,
            lower=self.min_multi_source_unique_sources,
            upper=self.min_multi_source_unique_sources + 5,
        )
        score_bonus = self._normalize(average_pair_score, lower=6.3, upper=8.8)
        target_score_bonus = self._normalize(target_score, lower=110.0, upper=220.0)
        rate_bonus = self._normalize(
            packet_rate,
            lower=self.high_packet_rate_threshold,
            upper=max(self.high_packet_rate_threshold * 4.0, self.high_packet_rate_threshold + 1.0),
        )
        spike_bonus = self._normalize(flow_score, lower=6.8, upper=8.2)

        probability = (
            0.60
            + (pair_bonus * 0.08)
            + (target_bonus * 0.05)
            + (source_bonus * 0.04)
            + (score_bonus * 0.05)
            + (target_score_bonus * 0.04)
            + (rate_bonus * 0.04)
            + (spike_bonus * 0.03)
        )
        return min(probability, 0.972)

    def _risk_label(
        self,
        pair_events: int,
        target_events: int,
        unique_sources: int,
        packet_rate: float,
        flow_score: float,
    ) -> str:
        if (
            unique_sources >= self.min_multi_source_unique_sources
            and target_events >= self.min_multi_source_target_events + 2
            and packet_rate >= self.high_packet_rate_threshold
            and flow_score >= 7.4
        ):
            return "High"

        if (
            pair_events >= self.min_pair_events + 10
            and packet_rate >= (self.high_packet_rate_threshold * 1.35)
            and flow_score >= 7.6
        ):
            return "High"

        if (
            pair_events >= self.min_pair_events
            or target_events >= self.min_target_events
            or (
                unique_sources >= self.min_multi_source_unique_sources
                and target_events >= self.min_multi_source_target_events
            )
        ):
            return "Medium"

        return "Low"

    def _flow_score(
        self,
        protocol: str,
        duration: float,
        packet_rate: float,
        low_response: bool,
        characteristic_size: float,
    ) -> float:
        score = 4.8
        if protocol == "UDP":
            score += 0.6
        if duration <= 450_000:
            score += 0.9
        elif duration <= 900_000:
            score += 0.5
        elif duration <= 1_200_000:
            score += 0.3
        if packet_rate >= self.high_packet_rate_threshold:
            score += 1.4
        elif packet_rate >= self.min_packet_rate_threshold * 2.0:
            score += 0.7
        if low_response:
            score += 0.4
        if characteristic_size > 0 and characteristic_size <= 140:
            score += 0.7
        elif characteristic_size > 0 and characteristic_size <= 220:
            score += 0.3
        elif characteristic_size > 0 and characteristic_size <= 320:
            score += 0.2
        return score

    def _register(
        self,
        bucket: Dict[Tuple[str, ...], Deque[DNSHeuristicEvent]],
        key: Tuple[str, ...],
        event: DNSHeuristicEvent,
    ) -> Tuple[int, float]:
        events = bucket.setdefault(key, deque())
        cutoff = event.timestamp - self.window_seconds
        while events and events[0].timestamp < cutoff:
            events.popleft()
        events.append(event)
        return len(events), sum(item.score for item in events)

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

    @staticmethod
    def _normalize(value: float, lower: float, upper: float) -> float:
        if upper <= lower:
            return 1.0 if value >= upper else 0.0
        if value <= lower:
            return 0.0
        if value >= upper:
            return 1.0
        return (value - lower) / (upper - lower)
