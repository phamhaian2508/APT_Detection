import unittest

from scapy.layers.inet import IP, TCP

from backend.capture import CaptureService


class _ResolverStub:
    def resolve(self, src_port, dest_port):
        return None, ""


class CaptureServiceTests(unittest.TestCase):
    def test_process_packet_emits_provisional_snapshot_immediately(self):
        terminated_flows = []
        live_updates = []
        capture = CaptureService(
            terminated_flows.append,
            on_flow_updated=live_updates.append,
            live_update_interval=60.0,
        )
        capture.process_resolver = _ResolverStub()

        packet = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S", window=1024)
        packet.time = 1000.0
        capture.process_packet(packet)

        self.assertEqual(len(live_updates), 1)
        snapshot = live_updates[0]
        self.assertTrue(snapshot["isProvisional"])
        self.assertEqual(snapshot["flowKey"], "10.0.0.1-10.0.0.2-12345-80-TCP")
        self.assertEqual(snapshot["id"], snapshot["flowKey"])
        self.assertEqual(terminated_flows, [])


if __name__ == "__main__":
    unittest.main()
