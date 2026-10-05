import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any

from prototype.packet_engine import PacketData


@dataclass
class FlowRecord:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start_time: float
    last_seen: float
    duration_ms: float
    in_bytes: int
    out_bytes: int
    in_pkts: int
    out_pkts: int
    tcp_flags: int
    tcp_flags_str: str
    is_attack: bool = False
    attack_type: str | None = None
    status: str = "ACTIVE"  # "ACTIVE", "COMPLETED"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def key(self) -> tuple:
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)

    def to_feature_vector(self, num_features: int = 43) -> list[float]:
        """Encodes NetFlow statistics into a standardized numeric feature vector."""
        vec = [0.0] * num_features
        # Primary standard features matching NetFlow v3
        vec[0] = float(self.src_port) / 65535.0
        vec[1] = float(self.dst_port) / 65535.0
        vec[2] = float(self.protocol) / 255.0
        vec[3] = min(1.0, float(self.in_bytes) / 50000.0)
        vec[4] = min(1.0, float(self.out_bytes) / 50000.0)
        vec[5] = min(1.0, float(self.in_pkts) / 500.0)
        vec[6] = min(1.0, float(self.out_pkts) / 500.0)
        vec[7] = min(1.0, float(self.duration_ms) / 5000.0)
        vec[8] = float(self.tcp_flags) / 64.0

        # Derived ratios & packet sizes
        avg_pkt_in = self.in_bytes / max(1, self.in_pkts)
        avg_pkt_out = self.out_bytes / max(1, self.out_pkts)
        vec[9] = min(1.0, avg_pkt_in / 1500.0)
        vec[10] = min(1.0, avg_pkt_out / 1500.0)
        byte_ratio = self.in_bytes / max(1, self.in_bytes + self.out_bytes)
        vec[11] = float(byte_ratio)

        # Flag bits
        vec[12] = 1.0 if (self.tcp_flags & 0x02) else 0.0  # SYN
        vec[13] = 1.0 if (self.tcp_flags & 0x10) else 0.0  # ACK
        vec[14] = 1.0 if (self.tcp_flags & 0x04) else 0.0  # RST
        vec[15] = 1.0 if (self.tcp_flags & 0x01) else 0.0  # FIN
        vec[16] = 1.0 if (self.tcp_flags & 0x08) else 0.0  # PSH

        # Fill remaining with scaled variations
        for i in range(17, num_features):
            vec[i] = (vec[i % 17] * 0.73) % 1.0

        return vec


class FlowAggregator:
    """Aggregates streaming packet instances into bidirectional NetFlow sessions."""

    def __init__(self, flow_timeout_sec: float = 3.0):
        self.flow_timeout_sec = flow_timeout_sec
        self.active_flows: dict[tuple, FlowRecord] = {}
        self.completed_flows: list[FlowRecord] = []
        self.flow_counter = 0
        self.listeners: list[Callable[[FlowRecord], None]] = []

    def register_listener(self, callback: Callable[[FlowRecord], None]):
        self.listeners.append(callback)

    def process_packet(self, pkt: PacketData) -> FlowRecord:
        now = pkt.timestamp
        fwd_key = (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol_num)
        rev_key = (pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol_num)

        if fwd_key in self.active_flows:
            flow = self.active_flows[fwd_key]
            flow.in_bytes += pkt.length
            flow.in_pkts += 1
            flow.tcp_flags |= pkt.tcp_flags_hex
            flow.last_seen = now
            flow.duration_ms = (now - flow.start_time) * 1000.0
            if pkt.is_attack:
                flow.is_attack = True
                flow.attack_type = pkt.attack_type
        elif rev_key in self.active_flows:
            flow = self.active_flows[rev_key]
            flow.out_bytes += pkt.length
            flow.out_pkts += 1
            flow.tcp_flags |= pkt.tcp_flags_hex
            flow.last_seen = now
            flow.duration_ms = (now - flow.start_time) * 1000.0
            if pkt.is_attack:
                flow.is_attack = True
                flow.attack_type = pkt.attack_type
        else:
            self.flow_counter += 1
            flow_id = f"FL-{self.flow_counter:04d}"
            flow = FlowRecord(
                flow_id=flow_id,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=pkt.src_port,
                dst_port=pkt.dst_port,
                protocol=pkt.protocol_num,
                start_time=now,
                last_seen=now,
                duration_ms=0.0,
                in_bytes=pkt.length,
                out_bytes=0,
                in_pkts=1,
                out_pkts=0,
                tcp_flags=pkt.tcp_flags_hex,
                tcp_flags_str=", ".join(pkt.tcp_flags) if pkt.tcp_flags else "NONE",
                is_attack=pkt.is_attack,
                attack_type=pkt.attack_type,
            )
            self.active_flows[fwd_key] = flow

        # Check for TCP termination flags (FIN or RST)
        if pkt.tcp_flags_hex & (0x01 | 0x04):  # FIN or RST
            self._complete_flow(flow.key)

        return flow

    def cleanup_expired(self, current_time: float | None = None) -> list[FlowRecord]:
        now = current_time or time.time()
        expired_keys = []
        for key, flow in self.active_flows.items():
            if now - flow.last_seen > self.flow_timeout_sec:
                expired_keys.append(key)

        closed = []
        for key in expired_keys:
            closed.append(self._complete_flow(key))
        return closed

    def _complete_flow(self, key: tuple) -> FlowRecord:
        flow = self.active_flows.pop(key, None)
        if flow:
            flow.status = "COMPLETED"
            self.completed_flows.append(flow)
            if len(self.completed_flows) > 500:
                self.completed_flows.pop(0)
            for listener in self.listeners:
                listener(flow)
            return flow
        raise KeyError("Flow key not found")

    def get_recent_flows(self, limit: int = 50) -> list[FlowRecord]:
        all_flows = list(self.active_flows.values()) + list(reversed(self.completed_flows))
        return all_flows[:limit]
