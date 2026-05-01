import unittest

from flow.Flow import Flow


class FakePacket:
    def __init__(
        self,
        timestamp,
        payload_bytes,
        packet_size,
        src="10.0.0.1",
        dest="10.0.0.2",
        src_port=12345,
        dest_port=80,
        protocol="TCP",
        psh=False,
        fin=False,
        syn=False,
        ack=False,
        urg=False,
        win_bytes=1024,
        pid=100,
        process_name="app.exe",
        target_is_local=False,
    ):
        self.timestamp = timestamp
        self.payload_bytes = payload_bytes
        self.packet_size = packet_size
        self.src = src
        self.dest = dest
        self.src_port = src_port
        self.dest_port = dest_port
        self.protocol = protocol
        self.psh = psh
        self.fin = fin
        self.syn = syn
        self.ack = ack
        self.urg = urg
        self.win_bytes = win_bytes
        self.pid = pid
        self.process_name = process_name
        self.target_is_local = target_is_local

    def getDestPort(self):
        return self.dest_port

    def getPID(self):
        return self.pid

    def getPName(self):
        return self.process_name

    def getPSHFlag(self):
        return self.psh

    def getPayloadBytes(self):
        return self.payload_bytes

    def getFINFlag(self):
        return self.fin

    def getSYNFlag(self):
        return self.syn

    def getACKFlag(self):
        return self.ack

    def getURGFlag(self):
        return self.urg

    def getPacketSize(self):
        return self.packet_size

    def getWinBytes(self):
        return self.win_bytes

    def getSrc(self):
        return self.src

    def getDest(self):
        return self.dest

    def getSrcPort(self):
        return self.src_port

    def getProtocol(self):
        return self.protocol

    def getTimestamp(self):
        return self.timestamp

    def getTargetIsLocal(self):
        return self.target_is_local


class FlowTests(unittest.TestCase):
    def test_flow_terminated_calculates_incremental_statistics(self):
        first_packet = FakePacket(timestamp=0.0, payload_bytes=10, packet_size=30, syn=True)
        flow = Flow(first_packet)

        flow.new(FakePacket(timestamp=1.0, payload_bytes=20, packet_size=40, psh=True), "fwd")
        flow.new(
            FakePacket(
                timestamp=3.0,
                payload_bytes=30,
                packet_size=50,
                src="10.0.0.2",
                dest="10.0.0.1",
                src_port=80,
                dest_port=12345,
                ack=True,
            ),
            "bwd",
        )

        features = flow.terminated()

        self.assertEqual(features[0], 3000000)
        self.assertEqual(features[1], 30)
        self.assertEqual(features[2], 30)
        self.assertEqual(features[3], 30)
        self.assertEqual(features[5], 1500000)
        self.assertEqual(features[8], 1000000)
        self.assertEqual(features[9], 1000000)
        self.assertEqual(features[10], 1000000)
        self.assertEqual(features[12], 1000000)
        self.assertEqual(features[13], 1000000)
        self.assertEqual(features[19], 1)
        self.assertAlmostEqual(features[20], 2 / 3, places=6)
        self.assertEqual(features[21], 30)
        self.assertEqual(features[22], 20)
        self.assertAlmostEqual(features[23], 10.0, places=6)
        self.assertAlmostEqual(features[24], 100.0, places=6)
        self.assertAlmostEqual(features[30], 40.0, places=6)
        self.assertAlmostEqual(features[31], 30.0, places=6)
        self.assertEqual(features[32], 1024)
        self.assertEqual(features[39], "10.0.0.1")
        self.assertEqual(features[41], "10.0.0.2")

    def test_flow_counts_multiple_tcp_flags_instead_of_storing_binary_presence(self):
        flow = Flow(FakePacket(timestamp=0.0, payload_bytes=10, packet_size=30, syn=True))

        flow.new(FakePacket(timestamp=0.5, payload_bytes=10, packet_size=30, syn=True), "fwd")
        flow.new(FakePacket(timestamp=1.0, payload_bytes=10, packet_size=30, ack=True), "bwd")
        flow.new(FakePacket(timestamp=1.5, payload_bytes=10, packet_size=30, ack=True), "bwd")

        features = flow.terminated()

        self.assertEqual(features[26], 2)
        self.assertEqual(features[28], 2)

    def test_live_snapshot_marks_flow_as_provisional(self):
        flow = Flow(FakePacket(timestamp=0.0, payload_bytes=10, packet_size=30, syn=True))

        snapshot = flow.live_snapshot("10.0.0.1-10.0.0.2-12345-80-TCP")

        self.assertTrue(snapshot["isProvisional"])
        self.assertEqual(snapshot["id"], snapshot["flowKey"])

    def test_preview_features_matches_terminated_shape_without_mutating_flow(self):
        flow = Flow(FakePacket(timestamp=0.0, payload_bytes=10, packet_size=30, syn=True))
        flow.new(FakePacket(timestamp=1.0, payload_bytes=20, packet_size=40, ack=True), "bwd")

        preview = flow.preview_features()

        self.assertEqual(len(preview), len(flow.terminated()))
        self.assertEqual(flow.packet_count, 2)


if __name__ == "__main__":
    unittest.main()
