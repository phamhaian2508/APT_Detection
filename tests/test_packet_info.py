import unittest

from scapy.layers.inet import ICMP, IP

from flow.PacketInfo import PacketInfo


class PacketInfoTests(unittest.TestCase):
    def test_icmp_packets_are_captured_with_protocol_and_size(self):
        packet = IP(src="192.168.1.10", dst="192.168.1.20") / ICMP() / b"payload"
        info = PacketInfo()

        info.setSrc(packet)
        info.setDest(packet)
        info.setProtocol(packet)
        info.setPayloadBytes(packet)
        info.setHeaderBytes(packet)
        info.setPacketSize(packet)

        self.assertEqual(info.getProtocol(), "ICMP")
        self.assertEqual(info.getPayloadBytes(), len(b"payload"))
        self.assertGreater(info.getHeaderBytes(), 0)
        self.assertGreater(info.getPacketSize(), info.getPayloadBytes())


if __name__ == "__main__":
    unittest.main()
