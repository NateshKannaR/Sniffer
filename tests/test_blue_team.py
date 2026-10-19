import time

from prototype.blue_team_engine import (
    BlueTeamEngine,
    DynamicNetworkDetector,
    GatewayIntegrityWatchdog,
    HostAttackSurfaceAuditor,
)


def test_dynamic_network_detector():
    profile = DynamicNetworkDetector.detect_network_profile()
    assert isinstance(profile, dict)
    assert "interface" in profile
    assert "host_ip" in profile
    assert "gateway_ip" in profile
    assert "subnet_cidr" in profile
    assert profile["status"] == "DETECTED"


def test_attack_surface_auditor_live():
    auditor = HostAttackSurfaceAuditor()
    listening_ports = auditor.audit_listening_ports()
    assert isinstance(listening_ports, list)
    # On any running Linux host with networking, there will be listening sockets (or empty list if isolated)
    for p in listening_ports:
        assert "proto" in p
        assert "port" in p
        assert "address" in p
        assert "process" in p
        assert "exposure" in p
        assert p["exposure"] in ("CRITICAL", "HIGH", "WARNING", "MEDIUM", "INFO", "SAFE")
        assert "risk_assessment" in p
        assert "recommendation" in p


def test_posture_scoring_logic():
    engine = BlueTeamEngine()

    # Scenario 1: Clean hardened system
    clean_surface = [
        {"proto": "TCP", "port": 5432, "address": "127.0.0.1", "process": "postgres", "exposure": "SAFE"},
        {"proto": "TCP", "port": 11434, "address": "127.0.0.1", "process": "ollama", "exposure": "SAFE"},
    ]
    clean_gateway = {"is_mitm_detected": False}
    score_clean = engine.compute_posture_score(clean_surface, clean_gateway, anomalies_count=0)
    assert score_clean["score"] == 100
    assert score_clean["grade"] == "A+"
    assert score_clean["badge_color"] == "emerald"

    # Scenario 2: Exposed SSH port (0.0.0.0:22)
    vuln_surface = [
        {"proto": "TCP", "port": 22, "address": "0.0.0.0", "process": "sshd", "exposure": "CRITICAL"},
        {"proto": "TCP", "port": 1716, "address": "*", "process": "kdeconnectd", "exposure": "WARNING"},
    ]
    score_vuln = engine.compute_posture_score(vuln_surface, clean_gateway, anomalies_count=0)
    assert score_vuln["score"] < 100
    assert score_vuln["counts"]["critical_exposed"] == 1
    assert any("SSH" in d["reason"] or "listening port" in d["reason"] for d in score_vuln["deductions"])

    # Scenario 3: MITM detected
    mitm_gateway = {"is_mitm_detected": True}
    score_mitm = engine.compute_posture_score(clean_surface, mitm_gateway, anomalies_count=2)
    assert score_mitm["score"] <= 65
    assert any("MITM" in d["category"] for d in score_mitm["deductions"])


def test_gateway_watchdog_mitm_detection():
    watchdog = GatewayIntegrityWatchdog(expected_gateway_ip="192.168.1.1", expected_gateway_mac="aa:bb:cc:dd:ee:ff")
    # Normal report
    res = watchdog.check_integrity()
    assert "status" in res
    assert "is_mitm_detected" in res
    assert isinstance(res["arp_table"], list)


def test_incident_triage_plain_english():
    engine = BlueTeamEngine()

    attack_surface = [
        {
            "proto": "TCP",
            "port": 22,
            "address": "0.0.0.0",
            "process": "sshd",
            "service_desc": "SSH Remote Access",
            "exposure": "CRITICAL",
            "recommendation": "Bind to 127.0.0.1",
        }
    ]
    gateway_integrity = {"is_mitm_detected": False}
    blocked_ips = {
        "198.51.100.4": {
            "timestamp": time.time(),
            "mse": 0.095,
            "reason": "Syn_Flood",
            "nft_command": "nft add element inet filter blocklist { 198.51.100.4 }",
        }
    }
    recent_anomalies = [
        {"src_ip": "203.0.113.5", "dst_ip": "10.0.0.1", "dst_port": 80, "attack_type": "SYN Port Scan", "mse": 0.082}
    ]

    incidents = engine.generate_incident_triage(
        attack_surface=attack_surface,
        gateway_integrity=gateway_integrity,
        blocked_ips=blocked_ips,
        recent_anomalies=recent_anomalies,
    )

    assert len(incidents) >= 2
    # Verify plain-English explainability
    ssh_incident = next((i for i in incidents if "SSH" in i["title"]), None)
    assert ssh_incident is not None
    assert ssh_incident["severity"] == "CRITICAL"
    assert "what_happened" in ssh_incident
    assert "why_it_matters" in ssh_incident
    assert "recommendation" in ssh_incident
    assert len(ssh_incident["what_happened"]) > 20
    assert len(ssh_incident["why_it_matters"]) > 20

    # Test incident acknowledgment
    engine.acknowledge_incident(ssh_incident["id"])
    incidents_after = engine.generate_incident_triage(
        attack_surface=attack_surface,
        gateway_integrity=gateway_integrity,
        blocked_ips=blocked_ips,
        recent_anomalies=recent_anomalies,
    )
    assert not any(i["id"] == ssh_incident["id"] for i in incidents_after)


def test_full_posture_report():
    engine = BlueTeamEngine()
    report = engine.get_full_posture_report()
    assert "network_profile" in report
    assert "posture" in report
    assert "attack_surface" in report
    assert "gateway_integrity" in report
    assert "incidents" in report
    assert "score" in report["posture"]
    assert "grade" in report["posture"]
