from __future__ import annotations

import time
import logging
from threading import Event
from typing import Callable, Dict, Optional, Tuple

import psutil
from scapy.sendrecv import sniff

from flow.Flow import Flow
from flow.PacketInfo import PacketInfo


class ProcessResolver:
    def __init__(self, refresh_interval: float = 2.0, logger: logging.Logger | None = None) -> None:
        self.refresh_interval = refresh_interval
        self._last_refresh = 0.0
        self._port_index: Dict[int, Tuple[Optional[int], str]] = {}
        self._pid_name_cache: Dict[int, str] = {}
        self.logger = logger or logging.getLogger("apt_detection.capture.process")

    def resolve(self, src_port: int, dest_port: int) -> Tuple[Optional[int], str]:
        now = time.monotonic()
        if now - self._last_refresh >= self.refresh_interval:
            self._refresh_snapshot(now)

        for port in (src_port, dest_port):
            if port in self._port_index:
                return self._port_index[port]
        return None, ""

    def _refresh_snapshot(self, now: float) -> None:
        port_index: Dict[int, Tuple[Optional[int], str]] = {}
        try:
            for connection in psutil.net_connections(kind="inet"):
                local_address = getattr(connection, "laddr", None)
                if not local_address:
                    continue

                port = getattr(local_address, "port", None)
                pid = getattr(connection, "pid", None)
                if port is None or port in port_index:
                    continue

                process_name = self._process_name(pid)
                port_index[int(port)] = (pid, process_name)
        except (psutil.Error, OSError):
            self.logger.debug("Could not refresh process snapshot.", exc_info=True)
            return

        if port_index:
            self._port_index = port_index
            self._last_refresh = now

    def _process_name(self, pid: Optional[int]) -> str:
        if pid is None:
            return ""
        if pid in self._pid_name_cache:
            return self._pid_name_cache[pid]

        try:
            name = psutil.Process(pid).name()
        except (psutil.Error, OSError):
            name = ""
        self._pid_name_cache[pid] = name
        return name


class CaptureService:
    def __init__(
        self,
        on_flow_terminated: Callable[[list], None],
        flow_timeout: int = 600,
        sniff_timeout: float = 1.0,
        process_refresh_interval: float = 2.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self.on_flow_terminated = on_flow_terminated
        self.flow_timeout = flow_timeout
        self.sniff_timeout = sniff_timeout
        self.current_flows: Dict[str, Flow] = {}
        self.logger = logger or logging.getLogger("apt_detection.capture")
        self.process_resolver = ProcessResolver(process_refresh_interval, logger=self.logger.getChild("process"))

    def process_packet(self, packet_data) -> None:
        try:
            packet = PacketInfo()
            packet.setDest(packet_data)
            packet.setSrc(packet_data)
            packet.setSrcPort(packet_data)
            packet.setDestPort(packet_data)
            packet.setProtocol(packet_data)
            packet.setTimestamp(packet_data)
            packet.setPSHFlag(packet_data)
            packet.setFINFlag(packet_data)
            packet.setSYNFlag(packet_data)
            packet.setACKFlag(packet_data)
            packet.setURGFlag(packet_data)
            packet.setRSTFlag(packet_data)
            packet.setPayloadBytes(packet_data)
            packet.setHeaderBytes(packet_data)
            packet.setPacketSize(packet_data)
            packet.setWinBytes(packet_data)
            packet.setFwdID()
            packet.setBwdID()
        except AttributeError:
            self.logger.debug("Skipping packet because required attributes were missing.", exc_info=True)
            return

        try:
            pid, process_name = self.process_resolver.resolve(packet.getSrcPort(), packet.getDestPort())
            packet.setProcess(pid, process_name)

            if packet.getFwdID() in self.current_flows:
                flow = self.current_flows[packet.getFwdID()]
                if self._is_expired(flow, packet.getTimestamp()):
                    self._finalize_flow(packet.getFwdID(), flow)
                    self.current_flows[packet.getFwdID()] = Flow(packet)
                elif packet.getFINFlag() or packet.getRSTFlag():
                    flow.new(packet, "fwd")
                    self._finalize_flow(packet.getFwdID(), flow)
                else:
                    flow.new(packet, "fwd")
                    self.current_flows[packet.getFwdID()] = flow
                return

            if packet.getBwdID() in self.current_flows:
                flow = self.current_flows[packet.getBwdID()]
                if self._is_expired(flow, packet.getTimestamp()):
                    self._finalize_flow(packet.getBwdID(), flow)
                    self.current_flows[packet.getFwdID()] = Flow(packet)
                elif packet.getFINFlag() or packet.getRSTFlag():
                    flow.new(packet, "bwd")
                    self._finalize_flow(packet.getBwdID(), flow)
                else:
                    flow.new(packet, "bwd")
                    self.current_flows[packet.getBwdID()] = flow
                return

            self.current_flows[packet.getFwdID()] = Flow(packet)
        except Exception:
            self.logger.exception("Unhandled error while processing packet.")

    def sniff_forever(self, stop_event: Event) -> None:
        self.logger.info("Capture loop started.")
        while not stop_event.is_set():
            sniff(
                prn=self.process_packet,
                store=False,
                timeout=self.sniff_timeout,
                stop_filter=lambda _: stop_event.is_set(),
            )
            self.reap_expired_flows()
        self.logger.info("Capture loop stopping, flushing active flows.")
        self.flush()

    def flush(self) -> None:
        self.reap_expired_flows(force=True)

    def reap_expired_flows(self, force: bool = False) -> None:
        now = time.time()
        expired_keys = [
            flow_key
            for flow_key, flow in self.current_flows.items()
            if force or self._is_expired(flow, now)
        ]
        for flow_key in expired_keys:
            flow = self.current_flows.pop(flow_key, None)
            if flow is not None:
                self.on_flow_terminated(flow.terminated())
        if expired_keys and not force:
            self.logger.debug("Reaped %s expired flows.", len(expired_keys))

    def _is_expired(self, flow: Flow, current_time: float) -> bool:
        return (current_time - flow.getFlowLastSeen()) > self.flow_timeout

    def _finalize_flow(self, flow_key: str, flow: Optional[Flow]) -> None:
        if flow_key in self.current_flows:
            del self.current_flows[flow_key]
        if flow is not None:
            self.on_flow_terminated(flow.terminated())
