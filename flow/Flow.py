import math

from flow.FlowFeature import FlowFeatures

from datetime import datetime
threshold = 5


class RunningStats:
    def __init__(self):
        self.count = 0
        self.total = 0.0
        self.mean_value = 0.0
        self.m2 = 0.0
        self.min_value = None
        self.max_value = None

    def add(self, value):
        numeric_value = float(value)
        self.count += 1
        self.total += numeric_value
        if self.min_value is None or numeric_value < self.min_value:
            self.min_value = numeric_value
        if self.max_value is None or numeric_value > self.max_value:
            self.max_value = numeric_value

        delta = numeric_value - self.mean_value
        self.mean_value += delta / self.count
        delta2 = numeric_value - self.mean_value
        self.m2 += delta * delta2

    def mean(self):
        return self.mean_value if self.count else 0

    def minimum(self):
        return self.min_value if self.min_value is not None else 0

    def maximum(self):
        return self.max_value if self.max_value is not None else 0

    def variance(self):
        if self.count < 2:
            return 0
        return self.m2 / (self.count - 1)

    def stdev(self):
        return math.sqrt(self.variance()) if self.count > 1 else 0


class Flow:
    def __init__(self, packet):
        self.packet_payload_stats = RunningStats()
        self.packet_size_stats = RunningStats()
        self.bwd_packet_payload_stats = RunningStats()
        self.flow_iat_stats = RunningStats()
        self.fwd_iat_stats = RunningStats()
        self.bwd_iat_stats = RunningStats()
        self.active_stats = RunningStats()
        self.idle_stats = RunningStats()

        self.packet_payload_stats.add(packet.getPayloadBytes())
        self.packet_size_stats.add(packet.getPacketSize())

        self.flowFeatures = FlowFeatures()
        self.flowFeatures.setDestPort(packet.getDestPort())

        self.flowFeatures.setPID(packet.getPID())
        self.flowFeatures.setPName(packet.getPName())



        self.flowFeatures.setFwdPSHFlags(1 if packet.getPSHFlag() else 0)
        self.flowFeatures.setMaxPacketLen(packet.getPayloadBytes())
        self.flowFeatures.setPacketLenMean(packet.getPayloadBytes())
        self.flowFeatures.setFINFlagCount(1 if packet.getFINFlag() else 0)
        self.flowFeatures.setSYNFlagCount(1 if packet.getSYNFlag() else 0)
        self.flowFeatures.setPSHFlagCount(1 if packet.getPSHFlag() else 0)
        self.flowFeatures.setACKFlagCount(1 if packet.getACKFlag() else 0)
        self.flowFeatures.setURGFlagCount(1 if packet.getURGFlag() else 0)

        self.flowFeatures.setAvgPacketSize(packet.getPacketSize())
        self.flowFeatures.setInitBytesFwd(packet.getWinBytes())

        self.flowFeatures.setSrc(packet.getSrc())
        self.flowFeatures.setDest(packet.getDest())
        self.flowFeatures.setSrcPort(packet.getSrcPort())
        self.flowFeatures.setProtocol(packet.getProtocol())


        self.flowLastSeen = packet.getTimestamp()
        self.fwdLastSeen = packet.getTimestamp()
        self.bwdLastSeen = 0
        self.flowStartTime = packet.getTimestamp()
        self.startActiveTime = packet.getTimestamp()
        self.endActiveTime = packet.getTimestamp()

        self.packet_count = 1
        self.fwd_packet_count = 1
        self.bwd_packet_count = 0

    def getFlowLastSeen(self):
        return self.flowLastSeen

    def getFlowStartTime(self):
        return self.flowStartTime

    def new(self, packetInfo, direction):
        if direction == 'bwd':
            if self.bwd_packet_count == 0:
                # first backward packet, do some initalising
                self.flowFeatures.setBwdPacketLenMax(packetInfo.getPayloadBytes())
                self.flowFeatures.setBwdPacketLenMin(packetInfo.getPayloadBytes())
                self.flowFeatures.setInitWinBytesBwd(packetInfo.getWinBytes())
                self.bwd_packet_payload_stats.add(packetInfo.getPayloadBytes())
            else:
                self.flowFeatures.setBwdPacketLenMax(
                    max(self.flowFeatures.bwd_packet_len_max, packetInfo.getPayloadBytes()))
                self.flowFeatures.setBwdPacketLenMin(
                    min(self.flowFeatures.bwd_packet_len_min, packetInfo.getPayloadBytes()))
                self.bwd_iat_stats.add((packetInfo.getTimestamp() - self.bwdLastSeen) * 1000 * 1000)
                self.bwd_packet_payload_stats.add(packetInfo.getPayloadBytes())

            self.bwd_packet_count = self.bwd_packet_count + 1
            self.bwdLastSeen = packetInfo.getTimestamp()

        else:
            self.fwd_iat_stats.add((packetInfo.getTimestamp() - self.fwdLastSeen) * 1000 * 1000)
            self.flowFeatures.setFwdPSHFlags(max(1 if packetInfo.getPSHFlag() else 0,
                                                 self.flowFeatures.getFwdPSHFlags()))
            self.fwd_packet_count = self.fwd_packet_count + 1
            self.fwdLastSeen = packetInfo.getTimestamp()

        self.flowFeatures.setMaxPacketLen(max(self.flowFeatures.getMaxPacketLen(), packetInfo.getPayloadBytes()))

        if packetInfo.getFINFlag():
            self.flowFeatures.setFINFlagCount(1)
        if packetInfo.getSYNFlag():
            self.flowFeatures.setSYNFlagCount(1)
        if packetInfo.getPSHFlag():
            self.flowFeatures.setPSHFlagCount(1)
        if packetInfo.getACKFlag():
            self.flowFeatures.setACKFlagCount(1)
        if packetInfo.getURGFlag():
            self.flowFeatures.setURGFlagCount(1)

        time = packetInfo.getTimestamp()
        if time - self.endActiveTime > threshold:
            if self.endActiveTime - self.startActiveTime > 0:
                self.active_stats.add(self.endActiveTime - self.startActiveTime)
            self.idle_stats.add(time - self.endActiveTime)
            self.startActiveTime = time
            self.endActiveTime = time
        else:
            self.endActiveTime = time

        self.packet_count = self.packet_count + 1
        self.packet_payload_stats.add(packetInfo.getPayloadBytes())
        self.packet_size_stats.add(packetInfo.getPacketSize())
        self.flow_iat_stats.add((packetInfo.getTimestamp() - self.flowLastSeen) * 1000 * 1000)
        self.flowLastSeen = packetInfo.getTimestamp()

    def terminated(self):
        duration = (self.flowLastSeen - self.flowStartTime) * 1000 * 1000
        self.flowFeatures.setFlowDuration(duration)

        if self.bwd_packet_payload_stats.count > 0:
            self.flowFeatures.setBwdPacketLenMean(self.bwd_packet_payload_stats.mean())
            if self.bwd_packet_payload_stats.count > 1:
                self.flowFeatures.setBwdPacketLenStd(self.bwd_packet_payload_stats.stdev())

        if self.flow_iat_stats.count > 0:
            self.flowFeatures.setFlowIATMean(self.flow_iat_stats.mean())
            self.flowFeatures.setFlowIATMax(self.flow_iat_stats.maximum())
            self.flowFeatures.setFlowIATMin(self.flow_iat_stats.minimum())
            if self.flow_iat_stats.count > 1:
                self.flowFeatures.setFlowIATStd(self.flow_iat_stats.stdev())

        if self.fwd_iat_stats.count > 0:
            self.flowFeatures.setFwdIATTotal(self.fwd_iat_stats.total)
            self.flowFeatures.setFwdIATMean(self.fwd_iat_stats.mean())
            self.flowFeatures.setFwdIATMax(self.fwd_iat_stats.maximum())
            self.flowFeatures.setFwdIATMin(self.fwd_iat_stats.minimum())
            if self.fwd_iat_stats.count > 1:
                self.flowFeatures.setFwdIATStd(self.fwd_iat_stats.stdev())

        if self.bwd_iat_stats.count > 0:
            self.flowFeatures.setBwdIATTotal(self.bwd_iat_stats.total)
            self.flowFeatures.setBwdIATMean(self.bwd_iat_stats.mean())
            self.flowFeatures.setBwdIATMax(self.bwd_iat_stats.maximum())
            self.flowFeatures.setBwdIATMin(self.bwd_iat_stats.minimum())
            if self.bwd_iat_stats.count > 1:
                self.flowFeatures.setBwdIATStd(self.bwd_iat_stats.stdev())

        self.flowFeatures.setFwdPackets_s(0 if duration == 0 else self.fwd_packet_count / (duration / (1000 * 1000)))

        if self.packet_payload_stats.count > 0:
            self.flowFeatures.setPacketLenMean(self.packet_payload_stats.mean())
            if self.packet_payload_stats.count > 1:
                self.flowFeatures.setPacketLenStd(self.packet_payload_stats.stdev())
                self.flowFeatures.setPacketLenVar(self.packet_payload_stats.variance())

        self.flowFeatures.setAvgPacketSize(self.packet_size_stats.mean())

        if self.bwd_packet_count != 0:
            self.flowFeatures.setAvgBwdSegmentSize(self.bwd_packet_payload_stats.mean())

        if self.active_stats.count > 0:
            self.flowFeatures.setActiveMin(self.active_stats.minimum())

        if self.idle_stats.count > 0:
            self.flowFeatures.setIdleMean(self.idle_stats.mean())
            self.flowFeatures.setIdleMax(self.idle_stats.maximum())
            self.flowFeatures.setIdleMin(self.idle_stats.minimum())
            if self.idle_stats.count > 1:
                self.flowFeatures.setIdleStd(self.idle_stats.stdev())

        return [
                self.flowFeatures.getFlowDuration(),
                self.flowFeatures.getBwdPacketLenMax(),
                self.flowFeatures.getBwdPacketLenMin(),
                self.flowFeatures.getBwdPacketLenMean(),
                self.flowFeatures.getBwdPacketLenStd(),
                self.flowFeatures.getFlowIATMean(),
                self.flowFeatures.getFlowIATStd(),
                self.flowFeatures.getFlowIATMax(),
                self.flowFeatures.getFlowIATMin(),
                self.flowFeatures.getFwdIATTotal(),
                self.flowFeatures.getFwdIATMean(),
                self.flowFeatures.getFwdIATStd(),
                self.flowFeatures.getFwdIATMax(),
                self.flowFeatures.getFwdIATMin(),
                self.flowFeatures.getBwdIATTotal(),
                self.flowFeatures.getBwdIATMean(),
                self.flowFeatures.getBwdIATStd(),
                self.flowFeatures.getBwdIATMax(),
                self.flowFeatures.getBwdIATMin(),
                self.flowFeatures.getFwdPSHFlags(),
                self.flowFeatures.getFwdPackets_s(),
                self.flowFeatures.getMaxPacketLen(),
                self.flowFeatures.getPacketLenMean(),
                self.flowFeatures.getPacketLenStd(),
                self.flowFeatures.getPacketLenVar(),
                self.flowFeatures.getFINFlagCount(),
                self.flowFeatures.getSYNFlagCount(),
                self.flowFeatures.getPSHFlagCount(),
                self.flowFeatures.getACKFlagCount(),
                self.flowFeatures.getURGFlagCount(),
                self.flowFeatures.getAvgPacketSize(),
                self.flowFeatures.getAvgBwdSegmentSize(),
                self.flowFeatures.getInitWinBytesFwd(),
                self.flowFeatures.getInitWinBytesBwd(),
                self.flowFeatures.getActiveMin(),
                self.flowFeatures.getIdleMean(),
                self.flowFeatures.getIdleStd(),
                self.flowFeatures.getIdleMax(),
                self.flowFeatures.getIdleMin(),

                
                self.flowFeatures.getSrc(),
                self.flowFeatures.getSrcPort(),
                self.flowFeatures.getDest(),
                self.flowFeatures.getDestPort(),
                self.flowFeatures.getProtocol(),
                datetime.fromtimestamp(self.getFlowStartTime()),
                datetime.fromtimestamp(self.getFlowLastSeen()),
                
                self.flowFeatures.getPName(),
                self.flowFeatures.getPID(),
                ]
