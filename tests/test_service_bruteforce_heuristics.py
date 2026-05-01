import unittest

from backend.features import translate_prediction_label
from backend.service_bruteforce_heuristics import (
    build_ldap_bruteforce_heuristic,
    build_mysql_bruteforce_heuristic,
    build_postgresql_bruteforce_heuristic,
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
            ("Database-Patator", build_mysql_bruteforce_heuristic(), 3306, 0.65),
            ("Database-Patator", build_postgresql_bruteforce_heuristic(), 5432, 0.65),
            ("LDAP-Patator", build_ldap_bruteforce_heuristic(), 389, 0.65),
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
            build_mysql_bruteforce_heuristic(),
            build_postgresql_bruteforce_heuristic(),
            build_ldap_bruteforce_heuristic(),
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
            (build_mysql_bruteforce_heuristic(), 3306),
            (build_postgresql_bruteforce_heuristic(), 5432),
            (build_ldap_bruteforce_heuristic(), 389),
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

    def test_short_connect_checks_with_high_rate_still_match_service_bruteforce(self):
        detector = build_rdp_bruteforce_heuristic()
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(4):
            matches.append(
                detector.evaluate(
                    build_record(
                        DestPort=3389,
                        FlowDuration=20_000,
                        FwdPackets_s=100.0,
                        FlowStartTime=f"2026-05-01 11:10:0{second}",
                        FlowLastSeen=f"2026-05-01 11:10:0{second + 1}",
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches[:3], [None, None, None])
        self.assertIsNotNone(matches[3])
        self.assertEqual(matches[3].classification, translate_prediction_label("RDP-Patator"))

    def test_ldaps_port_is_treated_as_ldap_service(self):
        detector = build_ldap_bruteforce_heuristic()
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(4):
            matches.append(
                detector.evaluate(
                    build_record(
                        DestPort=636,
                        MaxPacketLen=220,
                        BwdPacketLenMean=84,
                        AvgBwdSegmentSize=84,
                        FlowStartTime=f"2026-05-01 11:20:0{second}",
                        FlowLastSeen=f"2026-05-01 11:20:0{second + 1}",
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches[:3], [None, None, None])
        self.assertIsNotNone(matches[3])
        self.assertEqual(matches[3].classification, translate_prediction_label("LDAP-Patator"))

    def test_mysql_port_is_treated_as_database_service(self):
        detector = build_mysql_bruteforce_heuristic()
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(4):
            matches.append(
                detector.evaluate(
                    build_record(
                        DestPort=3306,
                        MaxPacketLen=240,
                        BwdPacketLenMean=96,
                        AvgBwdSegmentSize=96,
                        FlowStartTime=f"2026-05-01 11:30:0{second}",
                        FlowLastSeen=f"2026-05-01 11:30:0{second + 1}",
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches[:3], [None, None, None])
        self.assertIsNotNone(matches[3])
        self.assertEqual(matches[3].classification, translate_prediction_label("Database-Patator"))

    def test_postgresql_port_is_treated_as_database_service(self):
        detector = build_postgresql_bruteforce_heuristic()
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(4):
            matches.append(
                detector.evaluate(
                    build_record(
                        DestPort=5432,
                        MaxPacketLen=260,
                        BwdPacketLenMean=104,
                        AvgBwdSegmentSize=104,
                        FlowStartTime=f"2026-05-01 11:40:0{second}",
                        FlowLastSeen=f"2026-05-01 11:40:0{second + 1}",
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches[:3], [None, None, None])
        self.assertIsNotNone(matches[3])
        self.assertEqual(matches[3].classification, translate_prediction_label("Database-Patator"))


if __name__ == "__main__":
    unittest.main()
