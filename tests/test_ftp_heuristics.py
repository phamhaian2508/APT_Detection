import unittest

from backend.features import translate_prediction_label
from backend.ftp_heuristics import FTPBruteForceHeuristic


def build_record(**overrides):
    record = {
        "FlowDuration": 2_000_000,
        "BwdPacketLenMean": 96,
        "AvgBwdSegmentSize": 96,
        "MaxPacketLen": 180,
        "SYNFlagCount": 1,
        "ACKFlagCount": 1,
        "PSHFlagCount": 1,
        "Src": "192.168.1.10",
        "SrcPort": 41000,
        "Dest": "192.168.1.30",
        "DestPort": 21,
        "Protocol": "TCP",
        "FlowStartTime": "2026-04-10 10:10:00",
        "FlowLastSeen": "2026-04-10 10:10:02",
        "PName": "",
    }
    record.update(overrides)
    return record


class FTPHeuristicTests(unittest.TestCase):
    def test_repeated_short_lived_ftp_attempts_are_promoted_to_ftp_patator(self):
        detector = FTPBruteForceHeuristic(window_seconds=60, min_attempts=4)
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(4):
            matches.append(
                detector.evaluate(
                    build_record(
                        FlowStartTime=f"2026-04-10 10:10:0{second}",
                        FlowLastSeen=f"2026-04-10 10:10:0{second + 2}",
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches[:3], [None, None, None])
        self.assertIsNotNone(matches[3])
        self.assertEqual(matches[3].classification, translate_prediction_label("FTP-Patator"))
        self.assertGreaterEqual(matches[3].probability, 0.62)

    def test_non_ftp_traffic_does_not_trigger_heuristic(self):
        detector = FTPBruteForceHeuristic(window_seconds=60, min_attempts=4)
        prediction = translate_prediction_label("Benign")

        match = detector.evaluate(build_record(DestPort=443), prediction)

        self.assertIsNone(match)

    def test_short_ftp_server_flow_is_promoted_immediately_for_filtering(self):
        detector = FTPBruteForceHeuristic(window_seconds=60, min_attempts=4, service_min_attempts=1)
        prediction = translate_prediction_label("Benign")

        match = detector.evaluate(
            build_record(
                Src="192.168.186.129",
                SrcPort=40444,
                Dest="192.168.186.134",
                DestPort=21,
                FlowStartTime="2026-04-10 12:05:13",
                FlowLastSeen="2026-04-10 12:05:20",
                FlowDuration=7_000_000,
                PName="vsftpdPID 812",
            ),
            prediction,
        )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("FTP-Patator"))


if __name__ == "__main__":
    unittest.main()
