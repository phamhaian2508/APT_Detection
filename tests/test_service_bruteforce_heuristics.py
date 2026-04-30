import unittest

from backend.features import translate_prediction_label
from backend.service_bruteforce_heuristics import (
    build_rdp_bruteforce_heuristic,
    build_smb_bruteforce_heuristic,
    build_smtp_bruteforce_heuristic,
    build_telnet_bruteforce_heuristic,
)


def build_record(**overrides):
    record = {
        "FlowDuration": 2_000_000,
        "BwdPacketLenMean": 72,
        "AvgBwdSegmentSize": 72,
        "MaxPacketLen": 160,
        "SYNFlagCount": 1,
        "ACKFlagCount": 1,
        "PSHFlagCount": 1,
        "FwdPackets_s": 4.0,
        "Src": "192.168.1.10",
        "SrcPort": 41000,
        "Dest": "192.168.1.30",
        "DestPort": 3389,
        "Protocol": "TCP",
        "FlowStartTime": "2026-04-30 10:10:00",
        "FlowLastSeen": "2026-04-30 10:10:02",
        "PName": "",
    }
    record.update(overrides)
    return record


class ServiceBruteForceHeuristicTests(unittest.TestCase):
    def test_repeated_attempts_are_promoted_for_all_supported_services(self):
        prediction = translate_prediction_label("Benign")
        profiles = [
            ("RDP-Patator", build_rdp_bruteforce_heuristic(), 3389, 0.66),
            ("SMB-Patator", build_smb_bruteforce_heuristic(), 445, 0.64),
            ("Telnet-Patator", build_telnet_bruteforce_heuristic(), 23, 0.63),
            ("SMTP-Patator", build_smtp_bruteforce_heuristic(), 25, 0.64),
        ]

        for label, detector, port, min_probability in profiles:
            with self.subTest(label=label):
                matches = []
                for second in range(4):
                    matches.append(
                        detector.evaluate(
                            build_record(
                                DestPort=port,
                                FlowStartTime=f"2026-04-30 10:10:0{second}",
                                FlowLastSeen=f"2026-04-30 10:10:0{second + 1}",
                            ),
                            prediction,
                        )
                    )

                self.assertEqual(matches[:3], [None, None, None])
                self.assertIsNotNone(matches[3])
                self.assertEqual(matches[3].classification, translate_prediction_label(label))
                self.assertGreaterEqual(matches[3].probability, min_probability)

    def test_non_service_traffic_does_not_trigger(self):
        prediction = translate_prediction_label("Benign")
        detectors = [
            build_rdp_bruteforce_heuristic(),
            build_smb_bruteforce_heuristic(),
            build_telnet_bruteforce_heuristic(),
            build_smtp_bruteforce_heuristic(),
        ]

        for detector in detectors:
            with self.subTest(detector=detector.label):
                match = detector.evaluate(build_record(DestPort=443), prediction)
                self.assertIsNone(match)

    def test_probe_predictions_can_still_be_promoted_to_service_bruteforce(self):
        detector = build_rdp_bruteforce_heuristic()
        prediction = translate_prediction_label("Probe")

        matches = []
        for second in range(4):
            matches.append(
                detector.evaluate(
                    build_record(
                        DestPort=3389,
                        FlowStartTime=f"2026-04-30 10:20:0{second}",
                        FlowLastSeen=f"2026-04-30 10:20:0{second + 1}",
                    ),
                    prediction,
                )
            )

        self.assertIsNotNone(matches[3])
        self.assertEqual(matches[3].classification, translate_prediction_label("RDP-Patator"))

    def test_non_benign_model_predictions_do_not_block_service_hints(self):
        detector = build_rdp_bruteforce_heuristic()
        prediction = translate_prediction_label("DoS")

        matches = []
        for second in range(4):
            matches.append(
                detector.evaluate(
                    build_record(
                        DestPort=3389,
                        FlowStartTime=f"2026-04-30 10:30:0{second}",
                        FlowLastSeen=f"2026-04-30 10:30:0{second + 1}",
                    ),
                    prediction,
                )
            )

        self.assertIsNotNone(matches[3])
        self.assertEqual(matches[3].classification, translate_prediction_label("RDP-Patator"))

    def test_long_lived_sessions_are_not_treated_as_bruteforce(self):
        prediction = translate_prediction_label("Benign")
        profiles = [
            (build_rdp_bruteforce_heuristic(), 3389),
            (build_smb_bruteforce_heuristic(), 445),
            (build_telnet_bruteforce_heuristic(), 23),
            (build_smtp_bruteforce_heuristic(), 587),
        ]

        for detector, port in profiles:
            with self.subTest(detector=detector.label):
                match = detector.evaluate(
                    build_record(
                        DestPort=port,
                        FlowDuration=30_000_000,
                    ),
                    prediction,
                )
                self.assertIsNone(match)

    def test_high_packet_rate_microflows_are_not_treated_as_service_bruteforce(self):
        detector = build_rdp_bruteforce_heuristic()
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(4):
            matches.append(
                detector.evaluate(
                    build_record(
                        DestPort=3389,
                        FlowStartTime=f"2026-04-30 11:00:0{second}",
                        FlowLastSeen=f"2026-04-30 11:00:0{second + 1}",
                        FwdPackets_s=150.0,
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches, [None, None, None, None])


if __name__ == "__main__":
    unittest.main()
