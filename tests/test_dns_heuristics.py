import unittest

from backend.dns_heuristics import DNSAbuseHeuristic
from backend.features import translate_prediction_label, translate_risk_label


def build_record(**overrides):
    record = {
        "FlowDuration": 380_000,
        "BwdPacketLenMean": 72,
        "AvgBwdSegmentSize": 72,
        "MaxPacketLen": 118,
        "PacketLenMean": 96,
        "AvgPacketSize": 92,
        "FwdPackets_s": 46.0,
        "Src": "192.168.186.10",
        "SrcPort": 53000,
        "Dest": "192.168.186.134",
        "DestPort": 53,
        "Protocol": "UDP",
        "FlowStartTime": "2026-05-01 10:10:00",
        "FlowLastSeen": "2026-05-01 10:10:00",
        "PName": "dnsperf",
    }
    record.update(overrides)
    return record


class DNSAbuseHeuristicTests(unittest.TestCase):
    def test_repeated_dns_queries_from_one_source_are_promoted(self):
        detector = DNSAbuseHeuristic()
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(16):
            matches.append(
                detector.evaluate(
                    build_record(
                        FlowStartTime=f"2026-05-01 10:10:{second:02d}",
                        FlowLastSeen=f"2026-05-01 10:10:{second:02d}",
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches[:15], [None] * 15)
        self.assertIsNotNone(matches[15])
        self.assertEqual(matches[15].classification, translate_prediction_label("DNS-Abuse"))
        self.assertGreater(matches[15].probability, 0.60)
        self.assertEqual(matches[15].risk, translate_risk_label("Medium"))

    def test_multi_source_dns_pressure_is_promoted(self):
        detector = DNSAbuseHeuristic()
        prediction = translate_prediction_label("Benign")

        match = None
        for source_index, src in enumerate(("192.168.186.11", "192.168.186.12", "192.168.186.13")):
            for step in range(6):
                second = (source_index * 6) + step
                match = detector.evaluate(
                    build_record(
                        Src=src,
                        SrcPort=53000 + second,
                        FwdPackets_s=82.0,
                        FlowStartTime=f"2026-05-01 10:11:{second:02d}",
                        FlowLastSeen=f"2026-05-01 10:11:{second:02d}",
                    ),
                    prediction,
                )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("DNS-Abuse"))
        self.assertGreaterEqual(match.unique_sources, 3)
        self.assertGreater(match.probability, 0.64)
        self.assertEqual(match.risk, translate_risk_label("Medium"))

    def test_only_extreme_multi_source_dns_pressure_reaches_high_risk(self):
        detector = DNSAbuseHeuristic()
        prediction = translate_prediction_label("Benign")

        match = None
        for source_index, src in enumerate(("192.168.186.21", "192.168.186.22", "192.168.186.23", "192.168.186.24")):
            for step in range(8):
                second = (source_index * 8) + step
                match = detector.evaluate(
                    build_record(
                        Src=src,
                        SrcPort=54000 + second,
                        FwdPackets_s=128.0,
                        FlowDuration=260_000,
                        MaxPacketLen=102,
                        PacketLenMean=84,
                        AvgPacketSize=80,
                        FlowStartTime=f"2026-05-01 10:14:{second:02d}",
                        FlowLastSeen=f"2026-05-01 10:14:{second:02d}",
                    ),
                    prediction,
                )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("DNS-Abuse"))
        self.assertEqual(match.risk, translate_risk_label("High"))

    def test_non_dns_traffic_does_not_trigger(self):
        detector = DNSAbuseHeuristic()
        prediction = translate_prediction_label("Benign")

        match = detector.evaluate(build_record(DestPort=443, SrcPort=54000), prediction)

        self.assertIsNone(match)

    def test_normal_resolver_queries_do_not_trigger(self):
        detector = DNSAbuseHeuristic()
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(16):
            matches.append(
                detector.evaluate(
                    build_record(
                        FwdPackets_s=12.0,
                        FlowDuration=1_100_000,
                        BwdPacketLenMean=140,
                        AvgBwdSegmentSize=140,
                        MaxPacketLen=248,
                        PacketLenMean=176,
                        AvgPacketSize=172,
                        FlowStartTime=f"2026-05-01 10:12:{second:02d}",
                        FlowLastSeen=f"2026-05-01 10:12:{second:02d}",
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches, [None] * 16)

    def test_existing_flood_prediction_does_not_force_dns_abuse(self):
        detector = DNSAbuseHeuristic()
        prediction = translate_prediction_label("DoS")

        match = detector.evaluate(
            build_record(
                FwdPackets_s=82.0,
                FlowStartTime="2026-05-01 10:13:00",
                FlowLastSeen="2026-05-01 10:13:00",
            ),
            prediction,
        )

        self.assertIsNone(match)


if __name__ == "__main__":
    unittest.main()
