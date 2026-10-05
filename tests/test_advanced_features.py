from prototype.geoip_resolver import GeoIpResolver
from prototype.lan_scanner import LanScanner
from prototype.packet_crafter import PacketCrafter
from prototype.process_tracker import ProcessTracker


def test_process_tracker():
    tracker = ProcessTracker()
    mapping = tracker.refresh()
    assert isinstance(mapping, dict)

    # Calling with nonexistent port shouldn't error
    res = tracker.get_process_for_port(99999)
    assert res is None

    # Calling get_all_active_processes should return dict or list
    procs = tracker.get_all_active_processes()
    assert isinstance(procs, (dict, list))


def test_geoip_resolver():
    resolver = GeoIpResolver()

    # Test Google IP
    google_res = resolver.resolve("8.8.8.8")
    assert google_res["org"] == "Google LLC"
    assert google_res["asn"] == "AS15169"
    assert "United States" in google_res["country"]

    # Test Cloudflare IP
    cf_res = resolver.resolve("1.1.1.1")
    assert cf_res["org"] == "Cloudflare, Inc."
    assert cf_res["asn"] == "AS13335"

    # Test Local / Private IP
    local_res = resolver.resolve("10.138.114.94")
    assert local_res["asn"] == "RFC 1918"
    assert local_res["flag"] == "🏠"

    # Test caching
    cached_res = resolver.resolve("8.8.8.8")
    assert cached_res is google_res


def test_lan_scanner():
    scanner = LanScanner(interface="wlo1")

    # OUI vendor resolution
    vendor_intel = scanner.get_oui_vendor("50:2f:9b:12:34:56")
    assert "Intel" in vendor_intel

    vendor_apple = scanner.get_oui_vendor("f0:18:98:aa:bb:cc")
    assert "Apple" in vendor_apple

    # LAN scan execution
    devices = scanner.scan_lan()
    assert isinstance(devices, list)
    assert len(devices) > 0  # At minimum baseline gateway is included
    assert "ip" in devices[0]
    assert "mac" in devices[0]
    assert "vendor" in devices[0]


def test_packet_crafter():
    # Test Clean SYN packet
    pkt_syn = PacketCrafter.craft(
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        preset="syn"
    )
    assert pkt_syn.dst_ip == "10.0.0.1"
    assert pkt_syn.dst_port == 80
    assert pkt_syn.protocol_name == "TCP"
    assert "SYN" in pkt_syn.tcp_flags
    assert pkt_syn.tcp_flags_hex == 0x02

    # Test XMAS Tree Scan packet
    pkt_xmas = PacketCrafter.craft(
        dst_ip="10.0.0.1",
        dst_port=445,
        protocol="TCP",
        preset="xmas"
    )
    assert "FIN" in pkt_xmas.tcp_flags
    assert "PSH" in pkt_xmas.tcp_flags
    assert "URG" in pkt_xmas.tcp_flags
    assert pkt_xmas.is_attack is True
    assert pkt_xmas.attack_type == "XMAS_Tree_Scan"

    # Test NULL scan packet
    pkt_null = PacketCrafter.craft(
        dst_ip="10.0.0.1",
        dst_port=22,
        protocol="TCP",
        preset="null"
    )
    assert len(pkt_null.tcp_flags) == 0
    assert pkt_null.is_attack is True
    assert pkt_null.attack_type == "NULL_Flags_Scan"

    # Test custom payload & TTL
    pkt_custom = PacketCrafter.craft(
        dst_ip="1.1.1.1",
        dst_port=53,
        protocol="UDP",
        ttl=128,
        payload_text="CUSTOM_DNS_QUERY"
    )
    assert pkt_custom.protocol_name == "UDP"
    assert pkt_custom.ttl == 128
    assert "CUSTOM_DNS_QUERY" in pkt_custom.payload_ascii
