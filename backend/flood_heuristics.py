from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Deque, Dict, Tuple

from backend.features import risk_label_from_probability, risk_rank, translate_prediction_label, translate_risk_label


@dataclass(frozen=True)
class FloodEvent:
    timestamp: float
    source_ip: str
    score: float


@dataclass(frozen=True)
class FloodHeuristicMatch:
    classification: str
    probability: float
    risk: str
    events: int
    unique_sources: int
    attack_family: str
    score: float


class FloodAttackHeuristic:
    def __init__(
        self,
        window_seconds: int = 30,
        dos_event_threshold: int = 12,
        ddos_event_threshold: int = 4,
        ddos_unique_sources_threshold: int = 3,
        high_packet_rate_threshold: float = 120.0,
        very_high_packet_rate_threshold: float = 320.0,
        max_microflow_duration_us: int = 1_500_000,
        max_control_packet_len_bytes: int = 220,
        max_bwd_payload_bytes: int = 96,
        dos_score_threshold: float = 7.0,
        ddos_score_threshold: float = 11.0,
        single_flow_dos_score_threshold: float = 6.5,
        dos_source_dominance_threshold: float = 0.68,
        ddos_source_dominance_max: float = 0.58,
        dos_high_rate_event_threshold: int = 10,
        dos_min_average_target_score: float = 6.8,
        dos_high_rate_average_target_score: float = 7.4,
        dos_extreme_single_flow_packet_rate_threshold: float = 700.0,
        target_pressure_medium_event_threshold: int = 6,
        target_pressure_high_event_threshold: int = 10,
        target_pressure_medium_unique_sources_threshold: int = 3,
        target_pressure_high_unique_sources_threshold: int = 6,
        target_pressure_medium_score_threshold: float = 34.0,
        target_pressure_high_score_threshold: float = 60.0,
        base_dos_probability: float = 0.68,
        base_ddos_probability: float = 0.84,
        probability_step: float = 0.035,
    ) -> None:
        self.window_seconds = window_seconds
        self.dos_event_threshold = dos_event_threshold
        self.ddos_event_threshold = ddos_event_threshold
        self.ddos_unique_sources_threshold = ddos_unique_sources_threshold
        self.high_packet_rate_threshold = high_packet_rate_threshold
        self.very_high_packet_rate_threshold = very_high_packet_rate_threshold
        self.max_microflow_duration_us = max_microflow_duration_us
        self.max_control_packet_len_bytes = max_control_packet_len_bytes
        self.max_bwd_payload_bytes = max_bwd_payload_bytes
        self.dos_score_threshold = dos_score_threshold
        self.ddos_score_threshold = ddos_score_threshold
        self.single_flow_dos_score_threshold = single_flow_dos_score_threshold
        self.dos_source_dominance_threshold = dos_source_dominance_threshold
        self.ddos_source_dominance_max = ddos_source_dominance_max
        self.dos_high_rate_event_threshold = dos_high_rate_event_threshold
        self.dos_min_average_target_score = dos_min_average_target_score
        self.dos_high_rate_average_target_score = dos_high_rate_average_target_score
        self.dos_extreme_single_flow_packet_rate_threshold = dos_extreme_single_flow_packet_rate_threshold
        self.target_pressure_medium_event_threshold = target_pressure_medium_event_threshold
        self.target_pressure_high_event_threshold = target_pressure_high_event_threshold
        self.target_pressure_medium_unique_sources_threshold = target_pressure_medium_unique_sources_threshold
        self.target_pressure_high_unique_sources_threshold = target_pressure_high_unique_sources_threshold
        self.target_pressure_medium_score_threshold = target_pressure_medium_score_threshold
        self.target_pressure_high_score_threshold = target_pressure_high_score_threshold
        self.base_dos_probability = base_dos_probability
        self.base_ddos_probability = base_ddos_probability
        self.probability_step = probability_step
        self._recent_target_events: Dict[Tuple[str, str, int, str], Deque[FloodEvent]] = {}
        self._recent_source_events: Dict[Tuple[str, str, str, int, str], Deque[FloodEvent]] = {}
        self._recent_source_target_events: Dict[Tuple[str, str, str, int, str], Deque[FloodEvent]] = {}

    def evaluate(self, record: Dict[str, object], current_prediction: str) -> FloodHeuristicMatch | None:
        normalized_prediction = translate_prediction_label(current_prediction)
        if not self._prediction_allows_flood_override(normalized_prediction):
            return None

        candidate = self._candidate(record)
        if candidate is None:
            return None

        target_key, source_key, source_target_key, source_ip, event_time, packet_rate, attack_family, flow_score, target_is_local = candidate
        event = FloodEvent(timestamp=event_time, source_ip=source_ip, score=flow_score)
        event_count, unique_sources, target_score = self._register_target_event(target_key, event)
        source_event_count, source_score = self._register_source_event(source_key, event)
        source_target_count, source_target_score = self._register_source_target_event(source_target_key, event)
        source_event_share = 0.0 if event_count <= 0 else source_target_count / event_count
        source_score_share = 0.0 if target_score <= 0 else source_target_score / target_score
        target_pressure_risk = self._target_pressure_risk_label(
            event_count=event_count,
            unique_sources=unique_sources,
            target_score=target_score,
        )

        if self._is_ddos(event_count, unique_sources, target_score, source_event_share, source_score_share, packet_rate, flow_score):
            score = self._ddos_probability(
                event_count=event_count,
                unique_sources=unique_sources,
                target_score=target_score,
                packet_rate=packet_rate,
                flow_score=flow_score,
            )
            return FloodHeuristicMatch(
                classification=translate_prediction_label("DDoS"),
                probability=score,
                risk=translate_risk_label(risk_label_from_probability(score)),
                events=event_count,
                unique_sources=unique_sources,
                attack_family=attack_family,
                score=target_score,
            )

        if self._is_dos(
            source_event_count,
            source_score,
            source_target_count,
            source_target_score,
            source_event_share,
            source_score_share,
            packet_rate,
            flow_score,
            target_is_local,
        ):
            score = self._dos_probability(
                source_target_count=source_target_count,
                source_target_score=source_target_score,
                source_event_share=source_event_share,
                source_score_share=source_score_share,
                packet_rate=packet_rate,
                flow_score=flow_score,
            )
            risk = self._dos_risk_label(
                source_target_count=source_target_count,
                source_target_score=source_target_score,
                source_event_share=source_event_share,
                source_score_share=source_score_share,
                packet_rate=packet_rate,
                flow_score=flow_score,
            )
            if target_pressure_risk is not None and risk_rank(target_pressure_risk) > risk_rank(risk):
                risk = target_pressure_risk
            if risk_rank(risk) > risk_rank("Medium"):
                risk = "Medium"
            return FloodHeuristicMatch(
                classification=translate_prediction_label("DoS"),
                probability=score,
                risk=translate_risk_label(risk),
                events=event_count,
                unique_sources=unique_sources,
                attack_family=attack_family,
                score=max(source_score, source_target_score, flow_score),
            )

        return None

    def _candidate(
        self,
        record: Dict[str, object],
    ) -> Tuple[Tuple[str, str, int, str], Tuple[str, str, str, int, str], Tuple[str, str, str, int, str], str, float, float, str, float, bool] | None:
        protocol = str(record.get("Protocol") or "").upper()
        src = str(record.get("Src") or "")
        dest = str(record.get("Dest") or "")
        dest_port = self._to_int(record.get("DestPort"))
        target_is_local = self._to_bool(record.get("TargetIsLocal"))
        duration = self._to_float(record.get("FlowDuration"))
        packet_rate = self._to_float(record.get("FwdPackets_s"))
        syn_flags = self._to_float(record.get("SYNFlagCount"))
        ack_flags = self._to_float(record.get("ACKFlagCount"))
        max_packet_len = self._to_float(record.get("MaxPacketLen"))
        packet_len_mean = self._to_float(record.get("PacketLenMean"))
        avg_packet_size = self._to_float(record.get("AvgPacketSize"))
        bwd_packet_mean = self._to_float(record.get("BwdPacketLenMean"))
        avg_bwd_segment = self._to_float(record.get("AvgBwdSegmentSize"))

        if not src or not dest or not protocol:
            return None

        event_time = self._parse_timestamp(record.get("FlowLastSeen")) or self._parse_timestamp(record.get("FlowStartTime"))
        if event_time is None:
            return None

        positive_sizes = [value for value in (max_packet_len, packet_len_mean, avg_packet_size) if value > 0]
        characteristic_size = min(positive_sizes) if positive_sizes else 0.0
        microflow = duration <= self.max_microflow_duration_us
        low_response = max(bwd_packet_mean, avg_bwd_segment) <= self.max_bwd_payload_bytes
        compact_packets = characteristic_size <= self.max_control_packet_len_bytes if characteristic_size > 0 else True

        attack_family = ""
        flow_score = 0.0
        if protocol == "TCP":
            syn_heavy = syn_flags >= 1 and syn_flags >= max(1.0, ack_flags * 1.5)
            if not syn_heavy:
                return None
            if not (microflow or packet_rate >= self.high_packet_rate_threshold):
                return None
            if not compact_packets:
                return None
            attack_family = "SYN"
            flow_score = self._score_tcp_candidate(microflow, packet_rate, syn_flags, ack_flags, low_response, characteristic_size)
        elif protocol == "UDP":
            if not ((microflow and low_response) or packet_rate >= self.high_packet_rate_threshold):
                return None
            if not compact_packets:
                return None
            attack_family = "UDP"
            flow_score = self._score_stateless_candidate(microflow, packet_rate, low_response, characteristic_size, protocol)
        elif protocol == "ICMP":
            if not (microflow or packet_rate >= self.high_packet_rate_threshold):
                return None
            if not compact_packets:
                return None
            dest_port = 0
            attack_family = "ICMP"
            flow_score = self._score_stateless_candidate(microflow, packet_rate, True, characteristic_size, protocol)
        else:
            return None

        target_key = (dest, protocol, dest_port, attack_family)
        source_key = (src, dest, protocol, dest_port, attack_family)
        source_target_key = (src, dest, protocol, dest_port, attack_family)
        return target_key, source_key, source_target_key, src, event_time, packet_rate, attack_family, flow_score, target_is_local

    def _register_target_event(self, key: Tuple[str, str, int, str], event: FloodEvent) -> Tuple[int, int, float]:
        events = self._recent_target_events.setdefault(key, deque())
        cutoff = event.timestamp - self.window_seconds
        while events and events[0].timestamp < cutoff:
            events.popleft()
        events.append(event)
        unique_sources = len(Counter(item.source_ip for item in events))
        total_score = sum(item.score for item in events)
        return len(events), unique_sources, total_score

    def _register_source_event(self, key: Tuple[str, str, str, int, str], event: FloodEvent) -> Tuple[int, float]:
        events = self._recent_source_events.setdefault(key, deque())
        cutoff = event.timestamp - self.window_seconds
        while events and events[0].timestamp < cutoff:
            events.popleft()
        events.append(event)
        total_score = sum(item.score for item in events)
        return len(events), total_score

    def _register_source_target_event(self, key: Tuple[str, str, str, int, str], event: FloodEvent) -> Tuple[int, float]:
        events = self._recent_source_target_events.setdefault(key, deque())
        cutoff = event.timestamp - self.window_seconds
        while events and events[0].timestamp < cutoff:
            events.popleft()
        events.append(event)
        total_score = sum(item.score for item in events)
        return len(events), total_score

    def _is_ddos(
        self,
        event_count: int,
        unique_sources: int,
        target_score: float,
        source_event_share: float,
        source_score_share: float,
        packet_rate: float,
        flow_score: float,
    ) -> bool:
        if source_event_share > self.dos_source_dominance_threshold or source_score_share > self.dos_source_dominance_threshold:
            return False
        if unique_sources >= self.ddos_unique_sources_threshold and event_count >= self.ddos_event_threshold:
            return True
        if unique_sources >= self.ddos_unique_sources_threshold and target_score >= self.ddos_score_threshold:
            return True
        if (
            unique_sources >= (self.ddos_unique_sources_threshold + 2)
            and flow_score >= self.single_flow_dos_score_threshold
            and source_event_share <= self.ddos_source_dominance_max
        ):
            return True
        return (
            packet_rate >= self.very_high_packet_rate_threshold
            and unique_sources >= self.ddos_unique_sources_threshold
            and source_score_share <= self.ddos_source_dominance_max
        )

    def _is_dos(
        self,
        source_event_count: int,
        source_score: float,
        source_target_count: int,
        source_target_score: float,
        source_event_share: float,
        source_score_share: float,
        packet_rate: float,
        flow_score: float,
        target_is_local: bool,
    ) -> bool:
        dominance_met = (
            source_event_share >= self.dos_source_dominance_threshold
            or source_score_share >= self.dos_source_dominance_threshold
        )
        average_target_score = source_target_score / max(source_target_count, 1)
        if (
            target_is_local
            and packet_rate >= self.high_packet_rate_threshold
            and flow_score >= max(self.single_flow_dos_score_threshold - 0.5, 5.8)
            and dominance_met
        ):
            return True
        if (
            packet_rate >= self.dos_extreme_single_flow_packet_rate_threshold
            and flow_score >= (self.single_flow_dos_score_threshold + 0.7)
            and dominance_met
        ):
            return True
        if (
            source_target_count >= self.dos_event_threshold
            and average_target_score >= self.dos_min_average_target_score
            and dominance_met
            and (
                packet_rate >= (self.high_packet_rate_threshold * 0.75)
                or source_target_count >= (self.dos_event_threshold + 3)
            )
        ):
            return True
        if (
            source_target_count >= self.dos_high_rate_event_threshold
            and average_target_score >= self.dos_high_rate_average_target_score
            and packet_rate >= self.very_high_packet_rate_threshold
            and dominance_met
        ):
            return True
        return False

    def _ddos_probability(
        self,
        event_count: int,
        unique_sources: int,
        target_score: float,
        packet_rate: float,
        flow_score: float,
    ) -> float:
        event_bonus = self._normalize(
            event_count,
            lower=self.ddos_event_threshold,
            upper=self.ddos_event_threshold + 10,
        )
        source_bonus = self._normalize(
            unique_sources,
            lower=self.ddos_unique_sources_threshold,
            upper=self.ddos_unique_sources_threshold + 8,
        )
        score_bonus = self._normalize(
            target_score,
            lower=self.ddos_score_threshold,
            upper=self.ddos_score_threshold + 36.0,
        )
        rate_bonus = self._normalize(
            packet_rate,
            lower=self.high_packet_rate_threshold,
            upper=max(self.very_high_packet_rate_threshold * 2.0, self.high_packet_rate_threshold + 1.0),
        )
        spike_bonus = self._normalize(
            flow_score,
            lower=self.single_flow_dos_score_threshold,
            upper=self.single_flow_dos_score_threshold + 3.0,
        )

        probability = (
            0.82
            + (event_bonus * 0.06)
            + (source_bonus * 0.05)
            + (score_bonus * 0.07)
            + (rate_bonus * 0.03)
            + (spike_bonus * 0.02)
        )
        return min(probability, 0.987)

    def _dos_probability(
        self,
        source_target_count: int,
        source_target_score: float,
        source_event_share: float,
        source_score_share: float,
        packet_rate: float,
        flow_score: float,
    ) -> float:
        average_target_score = source_target_score / max(source_target_count, 1)
        dominance = max(source_event_share, source_score_share)
        normalized_score = self._normalize(average_target_score, lower=6.2, upper=8.8)
        repetition = self._normalize(
            source_target_count,
            lower=self.dos_high_rate_event_threshold,
            upper=self.dos_event_threshold + 12,
        )
        dominance_bonus = self._normalize(dominance, lower=self.dos_source_dominance_threshold, upper=1.0)
        rate_bonus = self._normalize(
            packet_rate,
            lower=self.high_packet_rate_threshold,
            upper=max(self.dos_extreme_single_flow_packet_rate_threshold * 1.4, self.high_packet_rate_threshold + 1.0),
        )
        spike_bonus = self._normalize(
            flow_score,
            lower=self.single_flow_dos_score_threshold,
            upper=self.single_flow_dos_score_threshold + 2.2,
        )

        probability = (
            0.66
            + (normalized_score * 0.10)
            + (repetition * 0.09)
            + (dominance_bonus * 0.05)
            + (rate_bonus * 0.06)
            + (spike_bonus * 0.03)
        )
        return min(probability, 0.962)

    def _dos_risk_label(
        self,
        source_target_count: int,
        source_target_score: float,
        source_event_share: float,
        source_score_share: float,
        packet_rate: float,
        flow_score: float,
    ) -> str:
        average_target_score = source_target_score / max(source_target_count, 1)
        if (
            packet_rate >= self.dos_extreme_single_flow_packet_rate_threshold
            or average_target_score >= 7.0
            or (source_target_count >= self.dos_event_threshold and average_target_score >= 6.5)
        ):
            return "Medium"
        return "Low"

    def _target_pressure_risk_label(
        self,
        event_count: int,
        unique_sources: int,
        target_score: float,
    ) -> str | None:
        high_pressure = (
            event_count >= self.target_pressure_high_event_threshold
            and unique_sources >= self.target_pressure_high_unique_sources_threshold
            and target_score >= self.target_pressure_high_score_threshold
        )
        high_distribution = (
            unique_sources >= self.target_pressure_high_unique_sources_threshold
            and target_score >= self.target_pressure_high_score_threshold
        )
        if high_pressure or high_distribution:
            return "High"

        medium_pressure = (
            event_count >= self.target_pressure_medium_event_threshold
            and unique_sources >= self.target_pressure_medium_unique_sources_threshold
            and target_score >= self.target_pressure_medium_score_threshold
        )
        medium_distribution = (
            unique_sources >= self.target_pressure_medium_unique_sources_threshold
            and target_score >= (self.target_pressure_medium_score_threshold * 0.8)
        )
        if medium_pressure or medium_distribution:
            return "Medium"
        return None

    def _target_pressure_probability(
        self,
        event_count: int,
        unique_sources: int,
        target_score: float,
    ) -> float:
        event_bonus = self._normalize(
            event_count,
            lower=self.target_pressure_medium_event_threshold,
            upper=max(self.target_pressure_medium_event_threshold + 1, self.target_pressure_high_event_threshold),
        )
        source_bonus = self._normalize(
            unique_sources,
            lower=self.target_pressure_medium_unique_sources_threshold,
            upper=max(
                self.target_pressure_medium_unique_sources_threshold + 1,
                self.target_pressure_high_unique_sources_threshold,
            ),
        )
        score_bonus = self._normalize(
            target_score,
            lower=self.target_pressure_medium_score_threshold,
            upper=max(self.target_pressure_medium_score_threshold + 1.0, self.target_pressure_high_score_threshold),
        )
        probability = self.base_dos_probability + (event_bonus * 0.08) + (source_bonus * 0.1) + (score_bonus * 0.1)
        return min(probability, 0.95)

    def _score_tcp_candidate(
        self,
        microflow: bool,
        packet_rate: float,
        syn_flags: float,
        ack_flags: float,
        low_response: bool,
        characteristic_size: float,
    ) -> float:
        score = 0.0
        if microflow:
            score += 1.7
        if low_response:
            score += 1.3
        if ack_flags <= 0:
            score += 1.7
        elif syn_flags >= (ack_flags * 2):
            score += 1.0
        if characteristic_size and characteristic_size <= 96:
            score += 1.0
        elif characteristic_size and characteristic_size <= self.max_control_packet_len_bytes:
            score += 0.6
        score += self._packet_rate_score(packet_rate)
        return score

    def _score_stateless_candidate(
        self,
        microflow: bool,
        packet_rate: float,
        low_response: bool,
        characteristic_size: float,
        protocol: str,
    ) -> float:
        score = 0.0
        if microflow:
            score += 1.8
        if low_response:
            score += 1.5
        if characteristic_size and characteristic_size <= 96:
            score += 1.1
        elif characteristic_size and characteristic_size <= self.max_control_packet_len_bytes:
            score += 0.6
        if protocol == "ICMP":
            score += 0.5
        score += self._packet_rate_score(packet_rate)
        return score

    def _packet_rate_score(self, packet_rate: float) -> float:
        if packet_rate >= self.very_high_packet_rate_threshold:
            return 3.2
        if packet_rate >= self.high_packet_rate_threshold:
            return 2.0
        if packet_rate > 0:
            return 0.7
        return 0.0

    @staticmethod
    def _normalize(value: float, lower: float, upper: float) -> float:
        if upper <= lower:
            return 1.0 if value >= upper else 0.0
        if value <= lower:
            return 0.0
        if value >= upper:
            return 1.0
        return (value - lower) / (upper - lower)

    @staticmethod
    def _prediction_allows_flood_override(prediction_label: str) -> bool:
        blocked_predictions = {
            translate_prediction_label("Database-Patator"),
            translate_prediction_label("DNS-Abuse"),
            translate_prediction_label("FTP-Patator"),
            translate_prediction_label("LDAP-Patator"),
            translate_prediction_label("RDP-Patator"),
            translate_prediction_label("SMB-Patator"),
            translate_prediction_label("SSH-Patator"),
            translate_prediction_label("SMTP-Patator"),
            translate_prediction_label("Telnet-Patator"),
        }
        return prediction_label not in blocked_predictions

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
    def _to_bool(value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        return str(value or "").strip().lower() in {"1", "true", "yes", "on"}
