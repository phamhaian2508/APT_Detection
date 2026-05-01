import unittest

from backend.features import risk_rank, translate_prediction_label
from backend.flood_heuristics import FloodAttackHeuristic


def build_record(**overrides):
    record = {
        "FlowDuration": 200_000,
        "BwdPacketLenMean": 0,
        "AvgBwdSegmentSize": 0,
        "FwdPackets_s": 0,
        "MaxPacketLen": 64,
        "PacketLenMean": 48,
        "AvgPacketSize": 52,
        "SYNFlagCount": 1,
        "ACKFlagCount": 0,
        "Src": "192.168.1.10",
        "SrcPort": 45678,
        "Dest": "192.168.1.20",
        "DestPort": 80,
        "Protocol": "TCP",
        "FlowStartTime": "2026-04-10 10:00:00",
        "FlowLastSeen": "2026-04-10 10:00:00",
    }
    record.update(overrides)
    return record


class FloodHeuristicTests(unittest.TestCase):
    def test_repeated_low_intensity_syn_microflows_from_one_source_are_not_promoted_too_early(self):
        detector = FloodAttackHeuristic(window_seconds=30, dos_event_threshold=8, ddos_event_threshold=10)
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(8):
            matches.append(
                detector.evaluate(
                    build_record(
                        FlowStartTime=f"2026-04-10 10:00:0{second}",
                        FlowLastSeen=f"2026-04-10 10:00:0{second}",
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches, [None, None, None, None, None, None, None, None])

    def test_repeated_flows_from_one_source_to_same_target_are_treated_as_dos_pressure(self):
        detector = FloodAttackHeuristic(window_seconds=30, dos_event_threshold=12, ddos_event_threshold=10)
        prediction = translate_prediction_label("Benign")

        match = None
        for second in range(12):
            match = detector.evaluate(
                build_record(
                    Src="192.168.186.101",
                    Dest="192.168.186.134",
                    DestPort=80,
                    Protocol="TCP",
                    SYNFlagCount=2,
                    ACKFlagCount=0,
                    FlowDuration=900_000,
                    FwdPackets_s=180,
                    FlowStartTime=f"2026-04-10 10:05:{second:02d}",
                    FlowLastSeen=f"2026-04-10 10:05:{second:02d}",
                ),
                prediction,
            )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("DoS"))
        self.assertEqual(risk_rank(match.risk), risk_rank("Medium"))
        self.assertGreaterEqual(match.probability, 0.74)

    def test_only_extremely_large_repeated_single_source_pressure_is_capped_at_medium_dos_risk(self):
        detector = FloodAttackHeuristic(window_seconds=30, dos_event_threshold=12, ddos_event_threshold=10)
        prediction = translate_prediction_label("Benign")

        match = None
        for second in range(18):
            match = detector.evaluate(
                build_record(
                    Src="192.168.186.101",
                    Dest="192.168.186.134",
                    DestPort=80,
                    Protocol="TCP",
                    SYNFlagCount=5,
                    ACKFlagCount=0,
                    FlowDuration=900_000,
                    FwdPackets_s=620,
                    FlowStartTime=f"2026-04-10 10:07:{second:02d}",
                    FlowLastSeen=f"2026-04-10 10:07:{second:02d}",
                ),
                prediction,
            )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("DoS"))
        self.assertEqual(risk_rank(match.risk), risk_rank("Medium"))
        self.assertGreater(match.probability, 0.85)

    def test_common_client_burst_to_one_remote_host_is_not_mislabeled_as_dos(self):
        detector = FloodAttackHeuristic(window_seconds=30, dos_event_threshold=12, ddos_event_threshold=10)
        prediction = translate_prediction_label("Benign")

        match = None
        for second in range(14):
            match = detector.evaluate(
                build_record(
                    Src="192.168.1.15",
                    Dest="104.18.20.10",
                    DestPort=443,
                    Protocol="TCP",
                    SYNFlagCount=1,
                    ACKFlagCount=0,
                    FlowDuration=1_000_000,
                    FwdPackets_s=30,
                    MaxPacketLen=120,
                    PacketLenMean=120,
                    AvgPacketSize=128,
                    FlowStartTime=f"2026-04-10 10:04:{second:02d}",
                    FlowLastSeen=f"2026-04-10 10:04:{second:02d}",
                ),
                prediction,
            )

        self.assertIsNone(match)

    def test_single_low_rate_syn_microflow_is_not_immediately_promoted(self):
        detector = FloodAttackHeuristic()
        prediction = translate_prediction_label("Benign")

        match = detector.evaluate(
            build_record(
                FlowDuration=150_000,
                FwdPackets_s=0,
                SYNFlagCount=1,
                ACKFlagCount=0,
                FlowStartTime="2026-04-10 10:00:00",
                FlowLastSeen="2026-04-10 10:00:00",
            ),
            prediction,
        )

        self.assertIsNone(match)

    def test_udp_microflows_from_many_sources_are_promoted_to_ddos(self):
        detector = FloodAttackHeuristic(window_seconds=30, ddos_event_threshold=5, ddos_unique_sources_threshold=3)
        prediction = translate_prediction_label("Benign")

        match = None
        for index in range(5):
            match = detector.evaluate(
                build_record(
                    Protocol="UDP",
                    DestPort=53,
                    SYNFlagCount=0,
                    Src=f"10.0.0.{index + 1}",
                    FlowStartTime=f"2026-04-10 10:01:0{index}",
                    FlowLastSeen=f"2026-04-10 10:01:0{index}",
                ),
                prediction,
            )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("DDoS"))
        self.assertGreaterEqual(match.unique_sources, 3)
        self.assertLess(match.probability, 0.99)

    def test_balanced_syn_pressure_from_multiple_sources_is_not_mislabeled_as_dos(self):
        detector = FloodAttackHeuristic(window_seconds=30, dos_event_threshold=4, ddos_event_threshold=6, ddos_unique_sources_threshold=3)
        prediction = translate_prediction_label("Benign")

        match = None
        sources = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
        for index, source in enumerate(sources):
            match = detector.evaluate(
                build_record(
                    Src=source,
                    Dest="192.168.186.134",
                    DestPort=80,
                    Protocol="TCP",
                    SYNFlagCount=2,
                    ACKFlagCount=0,
                    FlowDuration=800_000,
                    FwdPackets_s=160,
                    FlowStartTime=f"2026-04-10 10:06:0{index}",
                    FlowLastSeen=f"2026-04-10 10:06:0{index}",
                ),
                prediction,
            )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("DDoS"))

    def test_existing_dos_predictions_are_not_kept_without_flood_confirmation(self):
        detector = FloodAttackHeuristic(
            window_seconds=30,
            dos_event_threshold=20,
            ddos_event_threshold=20,
            ddos_unique_sources_threshold=20,
        )
        prediction = translate_prediction_label("DoS")

        match = None
        for index in range(10):
            match = detector.evaluate(
                build_record(
                    Src=f"10.20.0.{index + 1}",
                    Dest="192.168.186.134",
                    DestPort=80,
                    Protocol="TCP",
                    SYNFlagCount=1,
                    ACKFlagCount=0,
                    FlowDuration=900_000,
                    FwdPackets_s=30,
                    MaxPacketLen=120,
                    PacketLenMean=120,
                    AvgPacketSize=128,
                    FlowStartTime=f"2026-04-10 10:09:{index:02d}",
                    FlowLastSeen=f"2026-04-10 10:09:{index:02d}",
                ),
                prediction,
            )

        self.assertIsNone(match)

    def test_icmp_microflows_from_many_sources_are_promoted_to_ddos(self):
        detector = FloodAttackHeuristic(window_seconds=30, ddos_event_threshold=4, ddos_unique_sources_threshold=3)
        prediction = translate_prediction_label("Benign")

        match = None
        for index in range(4):
            match = detector.evaluate(
                build_record(
                    Protocol="ICMP",
                    DestPort=0,
                    Src=f"172.16.0.{index + 1}",
                    SYNFlagCount=0,
                    ACKFlagCount=0,
                    MaxPacketLen=56,
                    PacketLenMean=56,
                    AvgPacketSize=56,
                    FlowStartTime=f"2026-04-10 10:02:0{index}",
                    FlowLastSeen=f"2026-04-10 10:02:0{index}",
                ),
                prediction,
            )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("DDoS"))

    def test_ddos_probability_varies_with_attack_intensity(self):
        prediction = translate_prediction_label("Benign")

        lower_detector = FloodAttackHeuristic(window_seconds=30, ddos_event_threshold=4, ddos_unique_sources_threshold=3)
        lower_match = None
        for index in range(4):
            lower_match = lower_detector.evaluate(
                build_record(
                    Protocol="UDP",
                    DestPort=53,
                    SYNFlagCount=0,
                    Src=f"10.1.0.{index + 1}",
                    FwdPackets_s=140,
                    FlowStartTime=f"2026-04-10 10:10:{index:02d}",
                    FlowLastSeen=f"2026-04-10 10:10:{index:02d}",
                ),
                prediction,
            )

        higher_detector = FloodAttackHeuristic(window_seconds=30, ddos_event_threshold=4, ddos_unique_sources_threshold=3)
        higher_match = None
        for index in range(10):
            higher_match = higher_detector.evaluate(
                build_record(
                    Protocol="UDP",
                    DestPort=53,
                    SYNFlagCount=0,
                    Src=f"10.2.0.{index + 1}",
                    FwdPackets_s=280,
                    FlowStartTime=f"2026-04-10 10:11:{index:02d}",
                    FlowLastSeen=f"2026-04-10 10:11:{index:02d}",
                ),
                prediction,
            )

        self.assertIsNotNone(lower_match)
        self.assertIsNotNone(higher_match)
        self.assertEqual(lower_match.classification, translate_prediction_label("DDoS"))
        self.assertEqual(higher_match.classification, translate_prediction_label("DDoS"))
        self.assertGreater(higher_match.probability, lower_match.probability)

    def test_extreme_single_source_syn_pressure_is_promoted_immediately(self):
        detector = FloodAttackHeuristic()
        prediction = translate_prediction_label("Benign")

        match = detector.evaluate(
            build_record(
                FlowDuration=4_000_000,
                FwdPackets_s=1300,
                SYNFlagCount=30,
                ACKFlagCount=0,
                FlowStartTime="2026-04-10 10:03:00",
                FlowLastSeen="2026-04-10 10:03:04",
            ),
            prediction,
        )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("DoS"))
        self.assertEqual(risk_rank(match.risk), risk_rank("Medium"))
        self.assertGreaterEqual(match.probability, 0.80)

    def test_dos_probability_varies_with_attack_intensity(self):
        prediction = translate_prediction_label("Benign")

        lower_detector = FloodAttackHeuristic(window_seconds=30, dos_event_threshold=12, ddos_event_threshold=10)
        lower_match = None
        for second in range(12):
            lower_match = lower_detector.evaluate(
                build_record(
                    Src="192.168.186.101",
                    Dest="192.168.186.134",
                    DestPort=80,
                    Protocol="TCP",
                    SYNFlagCount=2,
                    ACKFlagCount=0,
                    FlowDuration=900_000,
                    FwdPackets_s=180,
                    FlowStartTime=f"2026-04-10 10:12:{second:02d}",
                    FlowLastSeen=f"2026-04-10 10:12:{second:02d}",
                ),
                prediction,
            )

        higher_detector = FloodAttackHeuristic(window_seconds=30, dos_event_threshold=12, ddos_event_threshold=10)
        higher_match = None
        for second in range(18):
            higher_match = higher_detector.evaluate(
                build_record(
                    Src="192.168.186.101",
                    Dest="192.168.186.134",
                    DestPort=80,
                    Protocol="TCP",
                    SYNFlagCount=5,
                    ACKFlagCount=0,
                    FlowDuration=900_000,
                    FwdPackets_s=620,
                    FlowStartTime=f"2026-04-10 10:13:{second:02d}",
                    FlowLastSeen=f"2026-04-10 10:13:{second:02d}",
                ),
                prediction,
            )

        self.assertIsNotNone(lower_match)
        self.assertIsNotNone(higher_match)
        self.assertEqual(lower_match.classification, translate_prediction_label("DoS"))
        self.assertEqual(higher_match.classification, translate_prediction_label("DoS"))
        self.assertGreater(higher_match.probability, lower_match.probability)


if __name__ == "__main__":
    unittest.main()
