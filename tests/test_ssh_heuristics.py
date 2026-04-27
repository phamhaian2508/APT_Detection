import unittest

from backend.features import translate_prediction_label
from backend.ssh_heuristics import SSHBruteForceHeuristic


def build_record(**overrides):
    record = {
        "FlowDuration": 1_000_000,
        "BwdPacketLenMean": 40,
        "AvgBwdSegmentSize": 40,
        "MaxPacketLen": 90,
        "SYNFlagCount": 1,
        "ACKFlagCount": 1,
        "PSHFlagCount": 0,
        "Src": "192.168.1.10",
        "SrcPort": 45678,
        "Dest": "192.168.1.20",
        "DestPort": 22,
        "Protocol": "TCP",
        "FlowStartTime": "2026-04-10 10:00:00",
        "FlowLastSeen": "2026-04-10 10:00:01",
        "PName": "",
    }
    record.update(overrides)
    return record


class SSHHeuristicTests(unittest.TestCase):
    def test_repeated_short_lived_ssh_attempts_are_promoted_to_ssh_patator(self):
        detector = SSHBruteForceHeuristic(window_seconds=60, min_attempts=4)
        prediction = translate_prediction_label("Benign")

        matches = []
        for second in range(4):
            matches.append(
                detector.evaluate(
                    build_record(
                        FlowStartTime=f"2026-04-10 10:00:0{second}",
                        FlowLastSeen=f"2026-04-10 10:00:0{second + 1}",
                    ),
                    prediction,
                )
            )

        self.assertEqual(matches[:3], [None, None, None])
        self.assertIsNotNone(matches[3])
        self.assertEqual(matches[3].classification, translate_prediction_label("SSH-Patator"))
        self.assertGreaterEqual(matches[3].probability, 0.65)

    def test_non_ssh_traffic_does_not_trigger_heuristic(self):
        detector = SSHBruteForceHeuristic(window_seconds=60, min_attempts=4)
        prediction = translate_prediction_label("Benign")

        match = detector.evaluate(build_record(DestPort=443), prediction)

        self.assertIsNone(match)

    def test_long_lived_ssh_session_is_not_treated_as_bruteforce(self):
        detector = SSHBruteForceHeuristic(window_seconds=60, min_attempts=2)
        prediction = translate_prediction_label("Benign")

        match = detector.evaluate(build_record(FlowDuration=25_000_000), prediction)

        self.assertIsNone(match)

    def test_short_sshd_flow_is_promoted_immediately_for_ssh_filtering(self):
        detector = SSHBruteForceHeuristic(window_seconds=60, min_attempts=4, service_min_attempts=1)
        prediction = translate_prediction_label("Benign")

        match = detector.evaluate(
            build_record(
                Src="192.168.186.129",
                SrcPort=33120,
                Dest="192.168.186.134",
                DestPort=22,
                FlowStartTime="2026-04-10 11:41:23",
                FlowLastSeen="2026-04-10 11:41:33",
                FlowDuration=10_000_000,
                PName="sshdPID 5754",
            ),
            prediction,
        )

        self.assertIsNotNone(match)
        self.assertEqual(match.classification, translate_prediction_label("SSH-Patator"))


if __name__ == "__main__":
    unittest.main()
