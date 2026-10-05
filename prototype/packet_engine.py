import random
import struct
import time
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class PacketData:
    id: int
    timestamp: float
    src_mac: str
    dst_mac: str
    eth_type: str
    src_ip: str
    dst_ip: str
    ip_version: int
    ttl: int
    protocol_num: int
    protocol_name: str
    ip_len: int
    src_port: int
    dst_port: int
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_flags: list[str] = field(default_factory=list)
    tcp_flags_hex: int = 0
    length: int = 0
    info: str = ""
    payload_hex: str = ""
    payload_ascii: str = ""
    is_attack: bool = False
    attack_type: str | None = None
    domain: str | None = None
    http_method: str | None = None
    http_uri: str | None = None
    dns_query: str | None = None
    sni: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PacketDissector:
    """Decodes raw binary packet buffers into structured OSI layer objects."""

    @staticmethod
    def dissect_ethernet(data: bytes) -> tuple[str, str, int, bytes]:
        if len(data) < 14:
            raise ValueError("Buffer too small for Ethernet header")
        dst_mac = ":".join(f"{b:02x}" for b in data[0:6])
        src_mac = ":".join(f"{b:02x}" for b in data[6:12])
        eth_type = struct.unpack("!H", data[12:14])[0]
        return dst_mac, src_mac, eth_type, data[14:]

    @staticmethod
    def dissect_ipv4(data: bytes) -> tuple[dict, bytes]:
        if len(data) < 20:
            raise ValueError("Buffer too small for IPv4 header")
        v_ihl, tos, total_length, ident, flags_frag, ttl, proto, checksum, src, dst = (
            struct.unpack("!BBHHHBBH4s4s", data[:20])
        )
        version = v_ihl >> 4
        ihl = (v_ihl & 0x0F) * 4
        src_ip = ".".join(str(b) for b in src)
        dst_ip = ".".join(str(b) for b in dst)
        header_info = {
            "version": version,
            "ihl": ihl,
            "ttl": ttl,
            "protocol": proto,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "total_length": total_length,
        }
        return header_info, data[ihl:]

    @staticmethod
    def dissect_tcp(data: bytes) -> tuple[dict, bytes]:
        if len(data) < 20:
            raise ValueError("Buffer too small for TCP header")
        src_port, dst_port, seq, ack, offset_reserved, flags, window, checksum, urgent = (
            struct.unpack("!HHIIBBHHH", data[:20])
        )
        offset = (offset_reserved >> 4) * 4
        flag_names = []
        if flags & 0x01:
            flag_names.append("FIN")
        if flags & 0x02:
            flag_names.append("SYN")
        if flags & 0x04:
            flag_names.append("RST")
        if flags & 0x08:
            flag_names.append("PSH")
        if flags & 0x10:
            flag_names.append("ACK")
        if flags & 0x20:
            flag_names.append("URG")

        header_info = {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": flag_names,
            "flags_hex": flags,
            "window": window,
        }
        return header_info, data[offset:]


class TrafficGenerator:
    """Generates authentic network traffic streams for educational cybersecurity scenarios."""

    def __init__(self):
        self.packet_counter = 0
        self.client_ip = "192.168.1.105"
        self.gateway_ip = "192.168.1.1"
        self.web_server_ip = "10.0.0.1"
        self.db_server_ip = "10.0.0.50"
        self.attacker_ip = "192.168.1.250"
        self.seq_num = 100000

    def _format_payload(self, text: str) -> tuple[str, str]:
        raw = text.encode("utf-8")
        hex_dump = " ".join(f"{b:02x}" for b in raw[:32])
        ascii_dump = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw[:32])
        return hex_dump, ascii_dump

    def generate_packet(self, scenario: str) -> PacketData:
        self.packet_counter += 1
        self.seq_num += random.randint(10, 1000)
        now = time.time()

        if scenario == "syn_scan":
            # Nmap Stealth SYN Port Scan: cycle ports rapidly with naked SYN
            dst_port = random.choice(
                [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
            )
            src_port = random.randint(40000, 65000)
            hex_dump, ascii_dump = self._format_payload("NMAP_PROBE_\x00\x01")
            return PacketData(
                id=self.packet_counter,
                timestamp=now,
                src_mac="08:00:27:fa:91:0a",
                dst_mac="52:54:00:12:34:56",
                eth_type="0x0800",
                src_ip=self.attacker_ip,
                dst_ip=self.web_server_ip,
                ip_version=4,
                ttl=random.randint(45, 55),
                protocol_num=6,
                protocol_name="TCP",
                ip_len=44,
                src_port=src_port,
                dst_port=dst_port,
                tcp_seq=self.seq_num,
                tcp_ack=0,
                tcp_flags=["SYN"],
                tcp_flags_hex=0x02,
                length=44,
                info=f"{src_port} → {dst_port} [SYN] Port Probe (Nmap)",
                payload_hex=hex_dump,
                payload_ascii=ascii_dump,
                is_attack=True,
                attack_type="SYN_Port_Scan",
            )

        elif scenario == "syn_flood":
            # DDoS SYN Flood: high rate from spoofed bot IPs
            bot_ip = f"172.{random.randint(16, 31)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            hex_dump, ascii_dump = self._format_payload("\x90" * 16)
            return PacketData(
                id=self.packet_counter,
                timestamp=now,
                src_mac="00:1a:2b:3c:4d:5e",
                dst_mac="52:54:00:12:34:56",
                eth_type="0x0800",
                src_ip=bot_ip,
                dst_ip=self.web_server_ip,
                ip_version=4,
                ttl=random.randint(30, 48),
                protocol_num=6,
                protocol_name="TCP",
                ip_len=40,
                src_port=src_port,
                dst_port=80,
                tcp_seq=random.randint(1000000, 9999999),
                tcp_ack=0,
                tcp_flags=["SYN"],
                tcp_flags_hex=0x02,
                length=40,
                info=f"{src_port} → 80 [SYN] DDoS Flood Packet",
                payload_hex=hex_dump,
                payload_ascii=ascii_dump,
                is_attack=True,
                attack_type="DDoS_SYN_Flood",
            )

        elif scenario == "dns_tunnel":
            # DNS Exfiltration: Base64 payload in DNS query
            chunk = "".join(
                random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16)
            )
            query_name = f"{chunk}.exfil.attacker-c2.net"
            hex_dump, ascii_dump = self._format_payload(query_name)
            return PacketData(
                id=self.packet_counter,
                timestamp=now,
                src_mac="08:00:27:12:34:56",
                dst_mac="00:50:56:c0:00:01",
                eth_type="0x0800",
                src_ip=self.client_ip,
                dst_ip=self.gateway_ip,
                ip_version=4,
                ttl=64,
                protocol_num=17,
                protocol_name="UDP",
                ip_len=92,
                src_port=random.randint(50000, 60000),
                dst_port=53,
                tcp_seq=None,
                tcp_ack=None,
                tcp_flags=[],
                tcp_flags_hex=0,
                length=92,
                info=f"Standard query 0x{random.randint(1000, 9999):x} TXT {query_name}",
                payload_hex=hex_dump,
                payload_ascii=ascii_dump,
                is_attack=True,
                attack_type="DNS_Data_Exfiltration",
            )

        else:
            # Normal Benign Traffic
            traffic_type = random.choice(["https", "http", "dns", "db"])
            if traffic_type == "https":
                domain, ip_dst = random.choice([
                    ("github.com", "140.82.121.4"),
                    ("www.google.com", "142.250.190.46"),
                    ("api.cloudflare.com", "104.16.132.229"),
                    ("en.wikipedia.org", "198.35.26.96"),
                    ("cdn.discordapp.com", "162.159.130.233"),
                ])
                payload = f"Client Hello TLS 1.3 (SNI: {domain})"
                hex_dump, ascii_dump = self._format_payload(payload)
                return PacketData(
                    id=self.packet_counter,
                    timestamp=now,
                    src_mac="08:00:27:12:34:56",
                    dst_mac="52:54:00:12:34:56",
                    eth_type="0x0800",
                    src_ip=self.client_ip,
                    dst_ip=ip_dst,
                    ip_version=4,
                    ttl=64,
                    protocol_num=6,
                    protocol_name="TLS/HTTPS",
                    ip_len=len(payload) + 40,
                    src_port=random.randint(45000, 60000),
                    dst_port=443,
                    tcp_seq=self.seq_num,
                    tcp_ack=self.seq_num + 50,
                    tcp_flags=["PSH", "ACK"],
                    tcp_flags_hex=0x18,
                    length=len(payload) + 40,
                    info=f"TLS Client Hello (SNI: {domain})",
                    payload_hex=hex_dump,
                    payload_ascii=ascii_dump,
                    is_attack=False,
                    domain=domain,
                    sni=domain,
                    http_method="TLS 1.3",
                    http_uri=f"https://{domain}/",
                )
            elif traffic_type == "http":
                is_req = random.random() > 0.5
                src_ip = self.client_ip if is_req else self.web_server_ip
                dst_ip = self.web_server_ip if is_req else self.client_ip
                src_p = 51234 if is_req else 80
                dst_p = 80 if is_req else 51234
                flags = ["PSH", "ACK"]
                info = (
                    "GET /api/v1/status HTTP/1.1"
                    if is_req
                    else "HTTP/1.1 200 OK (application/json)"
                )
                payload = (
                    "Host: portal.internal\r\nUser-Agent: Mozilla/5.0"
                    if is_req
                    else '{"status":"healthy","uptime":3600}'
                )
                hex_dump, ascii_dump = self._format_payload(payload)
                return PacketData(
                    id=self.packet_counter,
                    timestamp=now,
                    src_mac="08:00:27:12:34:56",
                    dst_mac="52:54:00:12:34:56",
                    eth_type="0x0800",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ip_version=4,
                    ttl=64,
                    protocol_num=6,
                    protocol_name="HTTP",
                    ip_len=len(payload) + 40,
                    src_port=src_p,
                    dst_port=dst_p,
                    tcp_seq=self.seq_num,
                    tcp_ack=self.seq_num + 50,
                    tcp_flags=flags,
                    tcp_flags_hex=0x18,
                    length=len(payload) + 40,
                    info=f"{src_p} → {dst_p} [{', '.join(flags)}] {info}",
                    payload_hex=hex_dump,
                    payload_ascii=ascii_dump,
                    is_attack=False,
                    domain="portal.internal",
                    http_method="GET",
                    http_uri="/api/v1/status",
                )
            elif traffic_type == "dns":
                lookup_domain = random.choice([
                    "github.com", "google.com", "cloudflare.com", "wikipedia.org"
                ])
                hex_dump, ascii_dump = self._format_payload(f"{lookup_domain}\x00")
                return PacketData(
                    id=self.packet_counter,
                    timestamp=now,
                    src_mac="08:00:27:12:34:56",
                    dst_mac="00:50:56:c0:00:01",
                    eth_type="0x0800",
                    src_ip=self.client_ip,
                    dst_ip=self.gateway_ip,
                    ip_version=4,
                    ttl=64,
                    protocol_num=17,
                    protocol_name="DNS",
                    ip_len=68,
                    src_port=53211,
                    dst_port=53,
                    tcp_seq=None,
                    tcp_ack=None,
                    tcp_flags=[],
                    tcp_flags_hex=0,
                    length=68,
                    info=f"Standard query A {lookup_domain}",
                    payload_hex=hex_dump,
                    payload_ascii=ascii_dump,
                    is_attack=False,
                    domain=lookup_domain,
                    dns_query=lookup_domain,
                )
            else:
                # Internal database traffic
                payload = "SELECT * FROM telemetry WHERE id = 42"
                hex_dump, ascii_dump = self._format_payload(payload)
                return PacketData(
                    id=self.packet_counter,
                    timestamp=now,
                    src_mac="52:54:00:12:34:56",
                    dst_mac="52:54:00:ab:cd:ef",
                    eth_type="0x0800",
                    src_ip=self.web_server_ip,
                    dst_ip=self.db_server_ip,
                    ip_version=4,
                    ttl=64,
                    protocol_num=6,
                    protocol_name="TCP",
                    ip_len=len(payload) + 40,
                    src_port=48210,
                    dst_port=5432,
                    tcp_seq=self.seq_num,
                    tcp_ack=self.seq_num + 20,
                    tcp_flags=["PSH", "ACK"],
                    tcp_flags_hex=0x18,
                    length=len(payload) + 40,
                    info="48210 → 5432 [PSH, ACK] Postgres Query",
                    payload_hex=hex_dump,
                    payload_ascii=ascii_dump,
                    is_attack=False,
                )


import queue
import subprocess
import threading


class LivePacketSniffer:
    """Captures real-time packets from a physical Linux interface (e.g. wlo1) using tshark."""

    def __init__(self, interface: str = "wlo1"):
        self.interface = interface
        self.packet_queue: queue.Queue = queue.Queue(maxsize=1000)
        self.running = False
        self.thread: threading.Thread | None = None
        self.process: subprocess.Popen | None = None
        self.packet_counter = 0

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=1)
            except Exception:
                pass
            self.process = None

    def get_packet(self, timeout: float = 0.1) -> PacketData | None:
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def _parse_flags(self, flags_raw: str) -> tuple[list[str], int]:
        try:
            if flags_raw.startswith("0x"):
                val = int(flags_raw, 16)
            else:
                val = int(flags_raw)
        except Exception:
            return [], 0

        names = []
        if val & 0x01:
            names.append("FIN")
        if val & 0x02:
            names.append("SYN")
        if val & 0x04:
            names.append("RST")
        if val & 0x08:
            names.append("PSH")
        if val & 0x10:
            names.append("ACK")
        if val & 0x20:
            names.append("URG")
        return names, val

    def _capture_loop(self):
        cmd = [
            "tshark", "-i", self.interface, "-l", "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "ipv6.src",
            "-e", "ipv6.dst",
            "-e", "ip.proto",
            "-e", "ip.ttl",
            "-e", "ip.len",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.flags",
            "-e", "tcp.seq",
            "-e", "tcp.ack",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "_ws.col.Info",
            "-e", "data.data",
            "-e", "tls.handshake.extensions_server_name",
            "-e", "http.host",
            "-e", "http.request.method",
            "-e", "http.request.uri",
            "-e", "dns.qry.name",
        ]

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            for line in self.process.stdout:
                if not self.running:
                    break
                line = line.strip()
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) < 18:
                    continue

                self.packet_counter += 1
                try:
                    ts = float(parts[1]) if parts[1] else time.time()
                except ValueError:
                    ts = time.time()

                eth_src = parts[2] or "00:00:00:00:00:00"
                eth_dst = parts[3] or "ff:ff:ff:ff:ff:ff"

                # Check IPv4 or IPv6
                src_ip = parts[4] or parts[6] or "0.0.0.0"
                dst_ip = parts[5] or parts[7] or "0.0.0.0"
                ip_ver = 6 if parts[6] else 4

                # Protocol
                proto_raw = parts[8]
                if proto_raw:
                    try:
                        proto_num = int(proto_raw)
                    except ValueError:
                        proto_num = 6
                else:
                    proto_num = 6 if (parts[11] or parts[12]) else (17 if (parts[16] or parts[17]) else 6)

                proto_name = "TCP" if proto_num == 6 else ("UDP" if proto_num == 17 else "IP")
                if parts[11] == "443" or parts[12] == "443":
                    proto_name = "TLS/HTTPS"
                elif parts[11] == "80" or parts[12] == "80":
                    proto_name = "HTTP"
                elif parts[16] == "53" or parts[17] == "53":
                    proto_name = "DNS"

                try:
                    ttl = int(parts[9]) if parts[9] else 64
                except ValueError:
                    ttl = 64

                try:
                    ip_len = int(parts[10]) if parts[10] else 60
                except ValueError:
                    ip_len = 60

                # Ports
                sport_str = parts[11] or parts[16]
                dport_str = parts[12] or parts[17]
                try:
                    sport = int(sport_str) if sport_str else 0
                    dport = int(dport_str) if dport_str else 0
                except ValueError:
                    sport, dport = 0, 0

                # TCP Details
                flag_names, flag_hex = self._parse_flags(parts[13])
                try:
                    tcp_seq = int(parts[14]) if parts[14] else None
                    tcp_ack = int(parts[15]) if parts[15] else None
                except ValueError:
                    tcp_seq, tcp_ack = None, None

                info = parts[18] if len(parts) > 18 else f"{sport} → {dport}"

                # Hex & ASCII payload
                hex_data = parts[19] if len(parts) > 19 else ""
                if hex_data:
                    # Format hex with spaces
                    hex_formatted = " ".join(hex_data[i:i+2] for i in range(0, min(64, len(hex_data)), 2))
                    # Decode ascii
                    try:
                        ascii_chars = "".join(
                            chr(int(hex_data[i:i+2], 16)) if 32 <= int(hex_data[i:i+2], 16) <= 126 else "."
                            for i in range(0, min(64, len(hex_data)), 2)
                        )
                    except Exception:
                        ascii_chars = "."
                else:
                    hex_formatted = "00 00 00 00 00 00 00 00"
                    ascii_chars = "........"

                sni = parts[20].strip() if len(parts) > 20 else ""
                http_host = parts[21].strip() if len(parts) > 21 else ""
                http_method = parts[22].strip() if len(parts) > 22 else ""
                http_uri = parts[23].strip() if len(parts) > 23 else ""
                dns_query = parts[24].strip() if len(parts) > 24 else ""

                domain = sni or http_host or (dns_query.rstrip(".") if dns_query else None)
                if not domain and "SNI: " in info:
                    domain = info.split("SNI: ")[-1].split(")")[0].strip()
                if not domain and "query " in info and " A " in info:
                    domain = info.split(" A ")[-1].strip()

                if sni:
                    proto_name = "TLS/HTTPS"
                    if "Application Data" not in info:
                        info = f"TLS Client Hello (SNI: {sni})"
                elif http_host:
                    proto_name = "HTTP"
                    info = f"{http_method or 'GET'} {http_host}{http_uri or '/'}"
                elif dns_query:
                    proto_name = "DNS"
                    info = f"DNS Query: {dns_query}"

                pkt = PacketData(
                    id=self.packet_counter,
                    timestamp=ts,
                    src_mac=eth_src,
                    dst_mac=eth_dst,
                    eth_type="0x0800" if ip_ver == 4 else "0x86dd",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    ip_version=ip_ver,
                    ttl=ttl,
                    protocol_num=proto_num,
                    protocol_name=proto_name,
                    ip_len=ip_len,
                    src_port=sport,
                    dst_port=dport,
                    tcp_seq=tcp_seq,
                    tcp_ack=tcp_ack,
                    tcp_flags=flag_names,
                    tcp_flags_hex=flag_hex,
                    length=ip_len,
                    info=info,
                    payload_hex=hex_formatted,
                    payload_ascii=ascii_chars,
                    is_attack=False,
                    domain=domain if domain else None,
                    http_method=http_method if http_method else None,
                    http_uri=http_uri if http_uri else None,
                    dns_query=dns_query if dns_query else None,
                    sni=sni if sni else None,
                )

                if not self.packet_queue.full():
                    self.packet_queue.put(pkt)
        except Exception as e:
            print(f"[LiveSniffer Error] {e}")
        finally:
            self.running = False

