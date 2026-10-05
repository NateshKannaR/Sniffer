import struct

from prototype.flow_aggregator import FlowAggregator
from prototype.graph_engine import GraphEngine
from prototype.inference_runner import InferenceRunner
from prototype.packet_engine import PacketDissector, TrafficGenerator


def test_packet_dissector():
    # Construct a synthetic IPv4 TCP packet byte buffer
    # Ethernet header (14 bytes)
    eth_header = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    dst_mac, src_mac, eth_type, eth_payload = PacketDissector.dissect_ethernet(eth_header)
    assert dst_mac == "aa:bb:cc:dd:ee:ff"
    assert src_mac == "11:22:33:44:55:66"
    assert eth_type == 0x0800

    # IPv4 header (20 bytes)
    # v_ihl=0x45, tos=0, total_length=40, id=1, frag=0, ttl=64, proto=6 (TCP), checksum=0
    src_ip_bytes = bytes([192, 168, 1, 100])
    dst_ip_bytes = bytes([10, 0, 0, 1])
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 6, 0, src_ip_bytes, dst_ip_bytes
    )
    ip_info, ip_payload = PacketDissector.dissect_ipv4(ip_header)
    assert ip_info["version"] == 4
    assert ip_info["ttl"] == 64
    assert ip_info["protocol"] == 6
    assert ip_info["src_ip"] == "192.168.1.100"
    assert ip_info["dst_ip"] == "10.0.0.1"

    # TCP header (20 bytes)
    # src_port=8080, dst_port=80, seq=1000, ack=0, offset=0x50, flags=0x02 (SYN), win=65535
    tcp_header = struct.pack(
        "!HHIIBBHHH", 8080, 80, 1000, 0, 0x50, 0x02, 65535, 0, 0
    )
    tcp_info, _ = PacketDissector.dissect_tcp(tcp_header)
    assert tcp_info["src_port"] == 8080
    assert tcp_info["dst_port"] == 80
    assert "SYN" in tcp_info["flags"]


def test_traffic_generator():
    gen = TrafficGenerator()
    pkt_norm = gen.generate_packet("normal")
    assert pkt_norm.id == 1
    assert pkt_norm.is_attack is False

    pkt_scan = gen.generate_packet("syn_scan")
    assert pkt_scan.id == 2
    assert pkt_scan.is_attack is True
    assert "SYN" in pkt_scan.tcp_flags
    assert pkt_scan.attack_type == "SYN_Port_Scan"


def test_flow_aggregator():
    agg = FlowAggregator(flow_timeout_sec=2.0)
    gen = TrafficGenerator()

    # Ingest multiple packets
    p1 = gen.generate_packet("normal")
    p1.src_ip = "192.168.1.10"
    p1.dst_ip = "10.0.0.5"
    p1.src_port = 50000
    p1.dst_port = 80
    p1.protocol_num = 6
    p1.length = 100
    p1.tcp_flags_hex = 0x02  # SYN

    flow1 = agg.process_packet(p1)
    assert flow1.in_bytes == 100
    assert flow1.in_pkts == 1

    # Ingest second packet in same flow
    p2 = gen.generate_packet("normal")
    p2.src_ip = "192.168.1.10"
    p2.dst_ip = "10.0.0.5"
    p2.src_port = 50000
    p2.dst_port = 80
    p2.protocol_num = 6
    p2.length = 200
    p2.tcp_flags_hex = 0x10  # ACK

    flow2 = agg.process_packet(p2)
    assert flow2.flow_id == flow1.flow_id
    assert flow2.in_bytes == 300
    assert flow2.in_pkts == 2

    # Feature vector validation
    vec = flow2.to_feature_vector(43)
    assert len(vec) == 43
    assert 0.0 <= vec[0] <= 1.0


def test_graph_engine_and_inference():
    gen = TrafficGenerator()
    agg = FlowAggregator()
    graph_engine = GraphEngine(window_size=16)
    inference = InferenceRunner(num_features=43, threshold=0.042)

    # Ingest 10 packets
    for _ in range(10):
        pkt = gen.generate_packet("normal")
        flow = agg.process_packet(pkt)
        graph_engine.add_flow(flow)

    pyg_data = graph_engine.to_pyg_data()
    assert pyg_data is not None
    assert pyg_data.edge_index.shape[0] == 2
    assert pyg_data.edge_attr.shape[1] == 43

    # Run inference
    results, mean_mse = inference.evaluate_graph(graph_engine)
    assert len(results) == len(graph_engine.flow_history)
    assert mean_mse >= 0.0

    # Test an attack packet insertion and verify IPS mitigation
    atk_pkt = gen.generate_packet("syn_scan")
    atk_flow = agg.process_packet(atk_pkt)
    graph_engine.add_flow(atk_flow)

    results2, mean_mse2 = inference.evaluate_graph(graph_engine)
    ips_status = inference.get_ips_status()
    assert ips_status["blocked_count"] >= 1
    assert "192.168.1.250" in ips_status["blocked_ips"]
