import random
import time
from typing import Any, Dict, List
from prototype.packet_engine import PacketData


class PacketCrafter:
    """Forges educational, custom-crafted network packets to study firewall & AI responses."""

    FLAG_MASKS = {
        "FIN": 0x01,
        "SYN": 0x02,
        "RST": 0x04,
        "PSH": 0x08,
        "ACK": 0x10,
        "URG": 0x20,
    }

    @classmethod
    def craft(
        cls,
        dst_ip: str = "10.0.0.1",
        dst_port: int = 80,
        src_ip: str = "10.138.114.94",
        src_port: int = 0,
        protocol: str = "TCP",
        flags: List[str] = None,
        ttl: int = 64,
        preset: str = None,
        payload_text: str = "PROTOTYPE_CUSTOM_TEST_PACKET",
    ) -> PacketData:
        flags = flags or []
        proto_upper = protocol.upper()

        # Handle Presets
        if preset == "xmas":
            flags = ["FIN", "PSH", "URG"]
        elif preset == "null":
            flags = []
        elif preset == "syn":
            flags = ["SYN"]
        elif preset == "rst":
            flags = ["RST"]

        flag_hex = 0
        for f in flags:
            flag_hex |= cls.FLAG_MASKS.get(f.upper(), 0)

        if not src_port:
            src_port = random.randint(40000, 65000)

        # Payload hex and ascii
        payload_bytes = payload_text.encode("utf-8")
        hex_dump = " ".join(f"{b:02x}" for b in payload_bytes[:32])
        ascii_dump = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload_bytes[:32])

        is_tcp = proto_upper == "TCP"
        proto_num = 6 if is_tcp else 17

        # Determine if this combination is inherently suspicious / attack
        is_attack = False
        attack_type = None
        if preset == "xmas" or ("FIN" in flags and "PSH" in flags and "URG" in flags):
            is_attack = True
            attack_type = "XMAS_Tree_Scan"
        elif preset == "null" or (is_tcp and len(flags) == 0):
            is_attack = True
            attack_type = "NULL_Flags_Scan"
        elif "SYN" in flags and len(flags) == 1:
            is_attack = True
            attack_type = "SYN_Probe"
        elif "RST" in flags:
            is_attack = True
            attack_type = "RST_Teardown"

        flag_str = ", ".join(flags) if flags else "NONE"
        info = f"{src_port} → {dst_port} [{flag_str}] Crafted Probe (TTL={ttl})"

        return PacketData(
            id=random.randint(100000, 999999),
            timestamp=time.time(),
            src_mac="08:00:27:00:11:22",
            dst_mac="52:54:00:aa:bb:cc",
            eth_type="0x0800",
            src_ip=src_ip,
            dst_ip=dst_ip,
            ip_version=4,
            ttl=ttl,
            protocol_num=proto_num,
            protocol_name=proto_upper,
            ip_len=len(payload_bytes) + 40,
            src_port=src_port,
            dst_port=dst_port,
            tcp_seq=100000 if is_tcp else None,
            tcp_ack=0 if is_tcp else None,
            tcp_flags=flags if is_tcp else [],
            tcp_flags_hex=flag_hex if is_tcp else 0,
            length=len(payload_bytes) + 40,
            info=info,
            payload_hex=hex_dump,
            payload_ascii=ascii_dump,
            is_attack=is_attack,
            attack_type=attack_type,
        )
