import math
import os
import re
import socket
import subprocess
import time
from collections import Counter
from typing import Any


class DynamicNetworkDetector:
    """Discovers active Linux network interfaces, local IP, gateway, and subnet CIDR dynamically."""

    @staticmethod
    def detect_network_profile() -> dict[str, Any]:
        profile = {
            "interface": "wlo1",
            "host_ip": "127.0.0.1",
            "gateway_ip": "127.0.0.1",
            "gateway_mac": "00:00:00:00:00:00",
            "subnet_cidr": "127.0.0.1/8",
            "status": "DETECTED",
        }

        # 1. Inspect default route via `ip route show default`
        try:
            res = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            for line in res.stdout.strip().split("\n"):
                if "default via" in line:
                    parts = line.split()
                    if "via" in parts:
                        profile["gateway_ip"] = parts[parts.index("via") + 1]
                    if "dev" in parts:
                        profile["interface"] = parts[parts.index("dev") + 1]
                    if "src" in parts:
                        profile["host_ip"] = parts[parts.index("src") + 1]
                    break
        except Exception:
            pass

        # Fallback to /proc/net/route if gateway wasn't found
        if profile["gateway_ip"] == "127.0.0.1" and os.path.exists("/proc/net/route"):
            try:
                with open("/proc/net/route") as f:
                    for line in f.readlines()[1:]:
                        fields = line.strip().split()
                        if len(fields) >= 3 and fields[1] == "00000000":  # Default destination
                            profile["interface"] = fields[0]
                            gw_hex = fields[2]
                            gw_bytes = bytes.fromhex(gw_hex)
                            profile["gateway_ip"] = ".".join(str(b) for b in reversed(gw_bytes))
                            break
            except Exception:
                pass

        # 2. Find local IP and subnet for detected interface
        if profile["interface"] != "lo":
            try:
                res = subprocess.run(
                    ["ip", "-br", "addr", "show", profile["interface"]],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                output = res.stdout.strip()
                match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)", output)
                if match:
                    cidr = match.group(1)
                    profile["subnet_cidr"] = cidr
                    profile["host_ip"] = cidr.split("/")[0]
            except Exception:
                pass

        # 3. Read gateway MAC address from /proc/net/arp
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp") as f:
                    for line in f.readlines()[1:]:
                        parts = line.strip().split()
                        if len(parts) >= 4 and parts[0] == profile["gateway_ip"]:
                            profile["gateway_mac"] = parts[3]
                            break
            except Exception:
                pass

        return profile


class HostAttackSurfaceAuditor:
    """Audits local Linux listening sockets to identify exposed ports and security risks."""

    KNOWN_SERVICES = {
        22: ("SSH Remote Access", "CRITICAL", "Allows remote terminal login; susceptible to brute-force attacks if open to WAN."),
        21: ("FTP File Transfer", "CRITICAL", "Unencrypted file transfer protocol; sends credentials in cleartext."),
        23: ("Telnet", "CRITICAL", "Legacy cleartext protocol; vulnerable to packet sniffing and credential theft."),
        80: ("HTTP Web Server", "WARNING", "Unencrypted web server; sensitive traffic should migrate to HTTPS."),
        443: ("HTTPS Web Server", "INFO", "Encrypted TLS web server."),
        1716: ("KDE Connect Device Sync", "WARNING", "Local device synchronization; broadcasts across local network."),
        3306: ("MySQL Database", "HIGH", "Database listener; should strictly bind to localhost (127.0.0.1)."),
        5432: ("PostgreSQL Database", "HIGH", "Database listener; must be protected from external network connections."),
        5037: ("Android Debug Bridge (ADB)", "INFO", "Local developer daemon."),
        5353: ("mDNS / Zeroconf", "INFO", "Multicast DNS discovery daemon on local network."),
        11434: ("Ollama AI LLM Server", "INFO", "Local AI model inference service."),
        3702: ("WS-Discovery / ONVIF", "INFO", "Local network device discovery protocol."),
    }

    def audit_listening_ports(self) -> list[dict[str, Any]]:
        """Executes real `ss -H -tulpn` socket query and returns structured security audit."""
        listening_ports = []
        try:
            res = subprocess.run(
                ["ss", "-H", "-tulpn"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            raw_lines = res.stdout.strip().split("\n")
        except Exception:
            raw_lines = []

        seen_keys = set()

        for line in raw_lines:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            proto = parts[0].upper()
            state = parts[1].upper()
            local_addr = parts[4]

            if proto == "TCP" and state != "LISTEN":
                continue

            try:
                if ":" in local_addr:
                    port_str = local_addr.rsplit(":", 1)[1]
                    addr_str = local_addr.rsplit(":", 1)[0]
                    port = int(port_str)
                else:
                    continue
            except ValueError:
                continue

            proc_name = "System Daemon"
            pid = None
            if len(parts) >= 7:
                users_field = " ".join(parts[6:])
                match = re.search(r'\("([^"]+)",pid=(\d+)', users_field)
                if match:
                    proc_name = match.group(1)
                    pid = int(match.group(2))

            if proc_name == "System Daemon":
                if port == 22:
                    proc_name = "sshd"
                elif port == 11434:
                    proc_name = "ollama"
                elif port == 5432:
                    proc_name = "postgres"
                elif port == 1716:
                    proc_name = "kdeconnectd"
                elif port == 5353:
                    proc_name = "avahi-daemon"
                else:
                    try:
                        serv = socket.getservbyport(port, proto.lower())
                        proc_name = f"{serv} (service)"
                    except (OSError, OverflowError):
                        proc_name = "Unknown Service"

            is_wan_exposed = addr_str in ("0.0.0.0", "*", "::") or addr_str.startswith("10.") or addr_str.startswith("192.168.")
            is_localhost = addr_str in ("127.0.0.1", "[::1]", "::1")

            known_info = self.KNOWN_SERVICES.get(port)
            service_desc = known_info[0] if known_info else f"Port {port} Listener"

            if is_wan_exposed:
                if port == 22:
                    exposure = "CRITICAL"
                    risk_assessment = "HIGH RISK: SSH port 22 is exposed to the local network / Wi-Fi. Any host on your subnet can attempt logins."
                    recommendation = "Edit /etc/ssh/sshd_config to bind ListenAddress 127.0.0.1, or restrict access via UFW firewall."
                elif port in (80, 8080, 3000, 5000, 8000):
                    exposure = "HIGH"
                    risk_assessment = f"Exposed Web Service: Port {port} accepts connections from anyone on your subnet."
                    recommendation = "Enable authentication or bind listener to 127.0.0.1 for local development."
                elif port in (3306, 5432, 6379, 27017):
                    exposure = "CRITICAL"
                    risk_assessment = f"Exposed Database: Port {port} is accessible across the physical network."
                    recommendation = "Reconfigure database to listen exclusively on 127.0.0.1."
                elif port in (1716, 5353, 3702):
                    exposure = "WARNING"
                    risk_assessment = f"Local Subnet Discovery: {service_desc} broadcasts device discovery packets on LAN."
                    recommendation = "Normal for KDE Connect/mDNS; restrict if operating on untrusted public Wi-Fi."
                else:
                    exposure = "MEDIUM"
                    risk_assessment = f"Network Bound Service: Listening on all interfaces ({addr_str})."
                    recommendation = "Review whether this service needs external network reachability."
            elif is_localhost:
                exposure = "SAFE"
                risk_assessment = "PROTECTED: Bound strictly to loopback interface (127.0.0.1). Inaccessible to external devices."
                recommendation = "No action needed. Service adheres to security best practices."
            else:
                exposure = "INFO"
                risk_assessment = f"Bound to interface address {addr_str}."
                recommendation = "Verify intended scope of listener."

            key = (proto, port, addr_str)
            if key not in seen_keys:
                seen_keys.add(key)
                listening_ports.append({
                    "proto": proto,
                    "port": port,
                    "address": addr_str,
                    "process": proc_name,
                    "pid": pid,
                    "service_desc": service_desc,
                    "exposure": exposure,
                    "risk_assessment": risk_assessment,
                    "recommendation": recommendation,
                    "is_wan_exposed": is_wan_exposed,
                    "is_localhost": is_localhost,
                })

        order = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "MEDIUM": 3, "INFO": 4, "SAFE": 5}
        listening_ports.sort(key=lambda x: order.get(x["exposure"], 99))
        return listening_ports


class GatewayIntegrityWatchdog:
    """Monitors local Wi-Fi router / default gateway for ARP poisoning and MITM attacks."""

    def __init__(self, expected_gateway_ip: str = "", expected_gateway_mac: str = ""):
        self.gateway_ip = expected_gateway_ip
        self.gateway_mac = expected_gateway_mac
        self.last_check_time = 0.0

    def check_integrity(self) -> dict[str, Any]:
        result = {
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "status": "SECURE",
            "is_mitm_detected": False,
            "details": "Gateway ARP resolution is authentic and stable.",
            "arp_table": [],
        }

        arp_path = "/proc/net/arp"
        if not os.path.exists(arp_path):
            return result

        mac_to_ips: dict[str, list[str]] = {}
        try:
            with open(arp_path) as f:
                lines = f.readlines()[1:]

            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3].lower()
                    if mac == "00:00:00:00:00:00" or ":" not in mac:
                        continue

                    mac_to_ips.setdefault(mac, []).append(ip)
                    result["arp_table"].append({"ip": ip, "mac": mac, "iface": parts[5] if len(parts) >= 6 else "wlo1"})

                    if ip == self.gateway_ip:
                        result["gateway_mac"] = mac
                        if self.gateway_mac and self.gateway_mac != "00:00:00:00:00:00" and self.gateway_mac != mac:
                            result["status"] = "ALERT_MITM"
                            result["is_mitm_detected"] = True
                            result["details"] = (
                                f"WARNING: Gateway MAC changed from {self.gateway_mac} to {mac}! "
                                "Possible ARP Spoofing / Man-In-The-Middle attack on this Wi-Fi network."
                            )

            for mac, ips in mac_to_ips.items():
                if len(ips) > 1 and mac != "ff:ff:ff:ff:ff:ff":
                    result["status"] = "ALERT_ARP_POISON"
                    result["is_mitm_detected"] = True
                    result["details"] = (
                        f"CRITICAL: MAC address {mac} is claiming multiple IP addresses ({', '.join(ips)}). "
                        "High probability of ARP spoofing attack on your local network!"
                    )
                    break
        except Exception as e:
            result["details"] = f"ARP audit note: {e}"

        return result


class KernelSecurityAuditor:
    """Audits real Linux kernel sysctl network parameters (/proc/sys/net/ipv4/*)."""

    SYSCTL_PARAMETERS = {
        "tcp_syncookies": {
            "path": "/proc/sys/net/ipv4/tcp_syncookies",
            "name": "TCP SYN Cookies (Anti-DoS)",
            "expected": 1,
            "severity": "CRITICAL",
            "risk": "Without SYN cookies, the kernel connection backlog can be exhausted by simple SYN flood attacks.",
            "remediation": "sudo sysctl -w net.ipv4.tcp_syncookies=1",
        },
        "rp_filter": {
            "path": "/proc/sys/net/ipv4/conf/all/rp_filter",
            "name": "Reverse Path Filtering (Anti-Spoofing)",
            "expected": 1,
            "severity": "HIGH",
            "risk": "Disabled or relaxed reverse path filtering allows spoofed IP packets to pass through the network stack.",
            "remediation": "sudo sysctl -w net.ipv4.conf.all.rp_filter=1",
        },
        "accept_redirects": {
            "path": "/proc/sys/net/ipv4/conf/all/accept_redirects",
            "name": "ICMP Redirect Acceptance (Anti-Route MITM)",
            "expected": 0,
            "severity": "HIGH",
            "risk": "Accepting ICMP redirects allows rogue devices on the Wi-Fi LAN to alter your kernel routing table and intercept traffic.",
            "remediation": "sudo sysctl -w net.ipv4.conf.all.accept_redirects=0",
        },
        "ip_forward": {
            "path": "/proc/sys/net/ipv4/ip_forward",
            "name": "IP Packet Forwarding",
            "expected": 0,
            "severity": "WARNING",
            "risk": "Unintentional packet forwarding turns your personal host into an unauthorized network router/bridge for third parties.",
            "remediation": "sudo sysctl -w net.ipv4.ip_forward=0",
        },
        "icmp_echo_ignore_broadcasts": {
            "path": "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
            "name": "Smurf Amplification Defense (Broadcast Ping Ignore)",
            "expected": 1,
            "severity": "MEDIUM",
            "risk": "Replying to broadcast ICMP echoes can participate in network Smurf amplification attacks.",
            "remediation": "sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1",
        },
    }

    @classmethod
    def audit_kernel_stack(cls) -> dict[str, Any]:
        results = {}
        for key, conf in cls.SYSCTL_PARAMETERS.items():
            path = conf["path"]
            val = None
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        val = int(f.read().strip())
                except (ValueError, OSError):
                    val = None

            is_compliant = (val == conf["expected"])
            results[key] = {
                "name": conf["name"],
                "path": path,
                "current_val": val,
                "expected_val": conf["expected"],
                "compliant": is_compliant,
                "severity": conf["severity"],
                "risk": conf["risk"],
                "remediation": conf["remediation"],
            }
        return results


class ThreatIntelligenceClassifier:
    """Evaluates outbound network sessions, domain Shannon entropy, and suspicious ports."""

    SUSPICIOUS_REMOTE_PORTS = {
        4444: ("Metasploit Default Listener / Reverse Shell", "CRITICAL"),
        1337: ("Hacker / PoC Exploit Listener", "CRITICAL"),
        6667: ("IRC Botnet Command & Control (C2)", "CRITICAL"),
        2323: ("Mirai IoT Telnet Alternate", "HIGH"),
        3389: ("Exposed Remote Desktop Protocol (RDP)", "WARNING"),
        5555: ("Android ADB Unsecured Shell", "HIGH"),
        8888: ("Generic Alternate Web / C2 Proxy", "INFO"),
    }

    @staticmethod
    def calculate_domain_entropy(domain: str) -> float:
        """Calculates Shannon entropy for domain name string to detect DGA/C2 domains."""
        if not domain or len(domain) < 4:
            return 0.0
        parts = domain.split(".")
        main_label = parts[0] if len(parts) >= 2 else domain
        length = len(main_label)
        if length == 0:
            return 0.0
        counts = Counter(main_label.lower())
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def analyze_session(cls, dst_ip: str, dst_port: int, domain: str = "", uri: str = "") -> dict[str, Any]:
        flags = []
        severity = "CLEAN"

        if dst_port in cls.SUSPICIOUS_REMOTE_PORTS:
            desc, sev = cls.SUSPICIOUS_REMOTE_PORTS[dst_port]
            flags.append(f"Suspicious Outbound Port {dst_port}: {desc}")
            severity = sev

        entropy = cls.calculate_domain_entropy(domain)
        if entropy >= 3.85 and len(domain.split(".")[0]) >= 12:
            flags.append(f"High Domain Entropy ({entropy:.2f}): Possible DGA / C2 beacon ({domain})")
            if severity != "CRITICAL":
                severity = "HIGH"

        if uri and any(s in uri.lower() for s in ("password=", "passwd=", "secret=", "apikey=", "token=")):
            flags.append("Cleartext Credential Transmission in URI query string")
            if severity not in ("CRITICAL", "HIGH"):
                severity = "WARNING"

        return {
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "domain": domain,
            "entropy": entropy,
            "is_suspicious": len(flags) > 0,
            "severity": severity,
            "indicators": flags,
        }


class ReconnaissanceDetector:
    """Sliding-window detector for multi-port sweeps and network reconnaissance."""

    def __init__(self, window_sec: float = 12.0, threshold_ports: int = 4):
        self.window_sec = window_sec
        self.threshold_ports = threshold_ports
        self.ip_port_history: dict[str, list[tuple[float, int]]] = {}
        self.detected_scans: dict[str, dict[str, Any]] = {}

    def record_probe(self, src_ip: str, dst_port: int, now: float = None) -> dict[str, Any] | None:
        if not src_ip or dst_port <= 0:
            return None
        now = now or time.time()

        cutoff = now - self.window_sec
        history = [entry for entry in self.ip_port_history.get(src_ip, []) if entry[0] >= cutoff]
        history.append((now, dst_port))
        self.ip_port_history[src_ip] = history

        unique_ports = {entry[1] for entry in history}
        if len(unique_ports) >= self.threshold_ports:
            scan_event = {
                "src_ip": src_ip,
                "ports_probed": sorted(list(unique_ports)),
                "count": len(unique_ports),
                "timestamp": now,
                "window_sec": self.window_sec,
                "first_seen": history[0][0],
            }
            self.detected_scans[src_ip] = scan_event
            return scan_event
        return None

    def get_recent_scans(self) -> list[dict[str, Any]]:
        now = time.time()
        return [s for s in self.detected_scans.values() if now - s["timestamp"] <= 60.0]


class BlueTeamEngine:
    """The central Robo Blue Hat Team brain: audits host exposure, triages threats, computes posture score."""

    def __init__(self):
        self.network_detector = DynamicNetworkDetector()
        self.network_profile = self.network_detector.detect_network_profile()
        self.auditor = HostAttackSurfaceAuditor()
        self.kernel_auditor = KernelSecurityAuditor()
        self.threat_classifier = ThreatIntelligenceClassifier()
        self.recon_detector = ReconnaissanceDetector()
        self.gateway_watchdog = GatewayIntegrityWatchdog(
            expected_gateway_ip=self.network_profile["gateway_ip"],
            expected_gateway_mac=self.network_profile["gateway_mac"],
        )
        self.acknowledged_incident_ids: set[str] = set()
        self.active_countermeasures: list[dict[str, Any]] = []

    def refresh_profile(self):
        self.network_profile = self.network_detector.detect_network_profile()
        self.gateway_watchdog.gateway_ip = self.network_profile["gateway_ip"]
        if self.network_profile["gateway_mac"] != "00:00:00:00:00:00":
            self.gateway_watchdog.gateway_mac = self.network_profile["gateway_mac"]

    def reaudit(self):
        """Forces fresh discovery of network profile, sockets, and clears dismissed status."""
        self.acknowledged_incident_ids.clear()
        self.refresh_profile()

    def compute_posture_score(
        self,
        attack_surface: list[dict[str, Any]],
        gateway_integrity: dict[str, Any],
        anomalies_count: int = 0,
        unencrypted_flows_count: int = 0,
        kernel_stack: dict[str, Any] = None,
        recon_scans_count: int = 0,
    ) -> dict[str, Any]:
        """Calculates 0-100% Host Security Posture Score, Grade, and breakdown."""
        score = 100
        deductions = []

        critical_exposed = [p for p in attack_surface if p["exposure"] == "CRITICAL"]
        high_exposed = [p for p in attack_surface if p["exposure"] == "HIGH"]
        warning_exposed = [p for p in attack_surface if p["exposure"] == "WARNING"]

        if critical_exposed:
            pts = min(40, len(critical_exposed) * 18)
            score -= pts
            deductions.append({
                "category": "Attack Surface",
                "points": -pts,
                "reason": f"{len(critical_exposed)} Critical listening port(s) exposed to WAN (e.g. SSH port {critical_exposed[0]['port']})",
            })

        if high_exposed:
            pts = min(20, len(high_exposed) * 8)
            score -= pts
            deductions.append({
                "category": "High Risk Services",
                "points": -pts,
                "reason": f"{len(high_exposed)} Exposed service(s) accepting external connections",
            })

        if warning_exposed:
            pts = min(10, len(warning_exposed) * 3)
            score -= pts
            deductions.append({
                "category": "LAN Broadcasts",
                "points": -pts,
                "reason": f"{len(warning_exposed)} LAN broadcast listener(s) (e.g. KDE Connect / mDNS)",
            })

        if gateway_integrity.get("is_mitm_detected"):
            score -= 35
            deductions.append({
                "category": "Network Layer MITM",
                "points": -35,
                "reason": "Gateway ARP spoofing or duplicate hardware MAC detected!",
            })

        if anomalies_count > 0:
            pts = min(30, anomalies_count * 10)
            score -= pts
            deductions.append({
                "category": "Active Anomalies",
                "points": -pts,
                "reason": f"{anomalies_count} Network anomaly pattern(s) flagged by GNN engine",
            })

        if unencrypted_flows_count > 0:
            pts = min(15, unencrypted_flows_count * 3)
            score -= pts
            deductions.append({
                "category": "Cleartext Protocols",
                "points": -pts,
                "reason": f"{unencrypted_flows_count} Unencrypted web/data session(s) detected",
            })

        if kernel_stack:
            for k_key, k_info in kernel_stack.items():
                if not k_info.get("compliant", True):
                    k_pts = 8 if k_info.get("severity") in ("CRITICAL", "HIGH") else 4
                    score -= k_pts
                    deductions.append({
                        "category": "Kernel Hardening",
                        "points": -k_pts,
                        "reason": f"Kernel sysctl weakness: {k_info.get('name')} ({k_info.get('remediation')})",
                    })

        if recon_scans_count > 0:
            r_pts = min(25, recon_scans_count * 12)
            score -= r_pts
            deductions.append({
                "category": "Port Reconnaissance",
                "points": -r_pts,
                "reason": f"{recon_scans_count} Active Port Sweep / Reconnaissance Probe(s) detected",
            })

        final_score = max(15, min(100, score))

        if final_score >= 95:
            grade = "A+"
            badge_color = "emerald"
            verdict = "EXCELLENT - Hardened Host"
        elif final_score >= 90:
            grade = "A"
            badge_color = "emerald"
            verdict = "SECURE - Minimal Risk"
        elif final_score >= 80:
            grade = "B+"
            badge_color = "blue"
            verdict = "GOOD - Minor Attack Surface Exposure"
        elif final_score >= 70:
            grade = "B"
            badge_color = "amber"
            verdict = "FAIR - Attack Surface Needs Attention"
        elif final_score >= 60:
            grade = "C"
            badge_color = "orange"
            verdict = "WARNING - Multiple Vulnerabilities Detected"
        else:
            grade = "D"
            badge_color = "rose"
            verdict = "CRITICAL - High Host Exposure"

        return {
            "score": final_score,
            "grade": grade,
            "badge_color": badge_color,
            "verdict": verdict,
            "deductions": deductions,
            "counts": {
                "critical_exposed": len(critical_exposed),
                "high_exposed": len(high_exposed),
                "warning_exposed": len(warning_exposed),
                "safe_localhost": len([p for p in attack_surface if p["exposure"] == "SAFE"]),
                "total_listening": len(attack_surface),
            },
        }

    def generate_incident_triage(
        self,
        attack_surface: list[dict[str, Any]],
        gateway_integrity: dict[str, Any],
        blocked_ips: dict[str, Any],
        recent_anomalies: list[dict[str, Any]],
        kernel_stack: dict[str, Any] = None,
        recon_scans: list[dict[str, Any]] = None,
        threat_sessions: list[dict[str, Any]] = None,
    ) -> list[dict[str, Any]]:
        """Synthesizes raw host events into plain-English Blue Team incident reports."""
        incidents = []
        now = time.time()

        for item in attack_surface:
            if item["exposure"] in ("CRITICAL", "HIGH"):
                inc_id = f"exposure_{item['proto']}_{item['port']}"
                if inc_id in self.acknowledged_incident_ids:
                    continue

                if item["port"] == 22:
                    incidents.append({
                        "id": inc_id,
                        "timestamp": now,
                        "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                        "severity": "CRITICAL",
                        "title": "WAN Attack Surface: Open SSH Daemon (Port 22)",
                        "target": f"{item['address']}:{item['port']}",
                        "process": item["process"],
                        "what_happened": (
                            f"Your Linux computer is running an OpenSSH server listening on address '{item['address']}:22'. "
                            f"This means any device on your Wi-Fi network ({self.network_profile.get('subnet_cidr', 'local subnet')}) "
                            "can connect to your machine."
                        ),
                        "why_it_matters": (
                            "Attackers or compromised smart devices on the same Wi-Fi can launch dictionary attacks "
                            "against your user account or attempt to exploit unpatched SSH vulnerabilities."
                        ),
                        "recommendation": (
                            "If you only use SSH locally, bind it to 127.0.0.1 in /etc/ssh/sshd_config. "
                            "Alternatively, enable Linux UFW firewall: 'sudo ufw default deny incoming'."
                        ),
                        "automated_defense": "Robo Blue Team has flagged this port and is actively monitoring for incoming connection bursts.",
                        "action_label": "Quarantine / Isolate",
                        "action_type": "isolate_port",
                        "remediation_cmd": "sudo iptables -A INPUT -p tcp --dport 22 -s 127.0.0.1 -j ACCEPT && sudo iptables -A INPUT -p tcp --dport 22 -j DROP",
                    })
                else:
                    incidents.append({
                        "id": inc_id,
                        "timestamp": now,
                        "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                        "severity": item["exposure"],
                        "title": f"Exposed Listener: {item['service_desc']} (Port {item['port']})",
                        "target": f"{item['address']}:{item['port']}",
                        "process": item["process"],
                        "what_happened": f"A service ({item['process']}) is listening on {item['address']}:{item['port']}.",
                        "why_it_matters": "Exposing network listeners increases your laptop's attack surface to unauthorized network traffic.",
                        "recommendation": item["recommendation"],
                        "automated_defense": "Active socket auditing enabled.",
                        "action_label": "Dismiss",
                        "action_type": "acknowledge",
                    })

        if gateway_integrity.get("is_mitm_detected"):
            inc_id = "mitm_gateway_discrepancy"
            if inc_id not in self.acknowledged_incident_ids:
                incidents.append({
                    "id": inc_id,
                    "timestamp": now,
                    "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                    "severity": "CRITICAL",
                    "title": "Local Network Threat: Potential ARP Spoofing / MITM",
                    "target": gateway_integrity.get("gateway_ip", "Gateway"),
                    "process": "Kernel ARP Subsystem",
                    "what_happened": gateway_integrity.get("details", "Duplicate MAC addresses detected on LAN."),
                    "why_it_matters": (
                        "A malicious computer on your Wi-Fi may be impersonating your router to intercept your passwords, "
                        "unencrypted traffic, and DNS queries."
                    ),
                    "recommendation": "Disconnect from this public Wi-Fi or enable a trusted VPN immediately.",
                    "automated_defense": "Blue Team watchdog has logged the suspicious MAC address.",
                    "action_label": "Acknowledge",
                    "action_type": "acknowledge",
                })

        for ip, blk_data in blocked_ips.items():
            inc_id = f"blocked_ip_{ip}"
            incidents.append({
                "id": inc_id,
                "timestamp": blk_data.get("timestamp", now),
                "time_str": time.strftime("%H:%M:%S", time.localtime(blk_data.get("timestamp", now))),
                "severity": "HIGH",
                "title": f"Autonomous Mitigation: Attacker IP Quarantined ({ip})",
                "target": ip,
                "process": "Kernel Firewall (nftables / iptables)",
                "what_happened": f"Host {ip} triggered anomaly threshold (MSE {blk_data.get('mse', 0.05):.4f}) via {blk_data.get('reason', 'GraphIDS anomaly')}.",
                "why_it_matters": "Active attack vectors like Port Scans or SYN floods can destabilize network connectivity or compromise local services.",
                "recommendation": "IP has been automatically blocked. Review connection logs or unblock if false-positive.",
                "automated_defense": f"Automated kernel rule executed: {blk_data.get('nft_command', 'nft block')}",
                "action_label": "Unblock IP",
                "action_type": "unblock_ip",
            })

        for anom in recent_anomalies[:5]:
            src = anom.get("src_ip", "0.0.0.0")
            if src in blocked_ips or src in ("127.0.0.1", "::1"):
                continue
            inc_id = f"anom_{anom.get('flow_id', src)}"
            if inc_id in self.acknowledged_incident_ids:
                continue

            incidents.append({
                "id": inc_id,
                "timestamp": now,
                "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                "severity": "HIGH",
                "title": f"Behavioral Anomaly: {anom.get('attack_type', 'Network Graph Deviation')}",
                "target": f"{src} → {anom.get('dst_ip', '')}:{anom.get('dst_port', '')}",
                "process": "GNN GraphIDS Engine",
                "what_happened": f"Network flow exceeded normal topological manifold (MSE: {anom.get('mse', 0.0):.4f}).",
                "why_it_matters": "Abnormal burst patterns or port sweeps frequently indicate automated vulnerability discovery tools.",
                "recommendation": "Inspect process and target destination.",
                "automated_defense": "Flagged for automatic quarantine upon threshold repetition.",
                "action_label": "Acknowledge",
                "action_type": "acknowledge",
            })

        if kernel_stack:
            for k_key, k_info in kernel_stack.items():
                if not k_info.get("compliant", True):
                    inc_id = f"kernel_sysctl_{k_key}"
                    if inc_id in self.acknowledged_incident_ids:
                        continue
                    incidents.append({
                        "id": inc_id,
                        "timestamp": now,
                        "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                        "severity": k_info.get("severity", "HIGH"),
                        "title": f"Linux Kernel Weakness: {k_info.get('name')}",
                        "target": f"sysctl {k_key}",
                        "process": "Linux Kernel Network Stack",
                        "what_happened": f"Kernel parameter '{k_info.get('path')}' is set to {k_info.get('current_val')} (Recommended secure value: {k_info.get('expected_val')}).",
                        "why_it_matters": k_info.get("risk", "Security exposure in kernel network processing."),
                        "recommendation": f"Run hardening command: '{k_info.get('remediation')}'.",
                        "automated_defense": "Robo Blue Hat has generated a kernel sysctl hardening rule.",
                        "action_label": "Apply Kernel Hardening",
                        "action_type": "harden_sysctl",
                        "remediation_cmd": k_info.get("remediation"),
                    })

        if recon_scans:
            for scan in recon_scans:
                src_ip = scan.get("src_ip", "0.0.0.0")
                inc_id = f"recon_{src_ip}_{int(scan.get('first_seen', now))}"
                if inc_id in self.acknowledged_incident_ids:
                    continue
                probed_str = ", ".join(str(p) for p in scan.get("ports_probed", [])[:8])
                incidents.append({
                    "id": inc_id,
                    "timestamp": scan.get("timestamp", now),
                    "time_str": time.strftime("%H:%M:%S", time.localtime(scan.get("timestamp", now))),
                    "severity": "HIGH",
                    "title": f"Active Reconnaissance: Port Sweep Detected ({src_ip})",
                    "target": src_ip,
                    "process": "Reconnaissance Hunter Engine",
                    "what_happened": f"Host '{src_ip}' probed {scan.get('count')} distinct ports ({probed_str}) in under {scan.get('window_sec', 12)} seconds.",
                    "why_it_matters": "Automated network sweeps are the primary precursor to exploitation, mapping which daemons and vulnerabilities exist on your host.",
                    "recommendation": f"Quarantine host {src_ip} via kernel firewall to block further reconnaissance.",
                    "automated_defense": f"Automated IPS rule generated: sudo iptables -A INPUT -s {src_ip} -j DROP",
                    "action_label": "Quarantine Scanner",
                    "action_type": "block_ip",
                    "remediation_cmd": f"sudo iptables -A INPUT -s {src_ip} -j DROP",
                })

        if threat_sessions:
            for sess in threat_sessions:
                if sess.get("is_suspicious"):
                    inc_id = f"threat_{sess.get('dst_ip')}_{sess.get('dst_port')}"
                    if inc_id in self.acknowledged_incident_ids:
                        continue
                    indicators_str = "; ".join(sess.get("indicators", []))
                    incidents.append({
                        "id": inc_id,
                        "timestamp": now,
                        "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                        "severity": sess.get("severity", "HIGH"),
                        "title": f"Outbound Threat Intelligence Flag: {sess.get('domain') or sess.get('dst_ip')}",
                        "target": f"{sess.get('dst_ip')}:{sess.get('dst_port')}",
                        "process": "Threat Intelligence Classifier",
                        "what_happened": f"Outbound traffic triggered behavioral indicators: {indicators_str}.",
                        "why_it_matters": "High-entropy domain names or non-standard remote ports strongly correlate with Command & Control (C2) or unauthorized data exfiltration.",
                        "recommendation": "Inspect initiating desktop application and block outbound destination.",
                        "automated_defense": "Connection logged for behavioral correlation.",
                        "action_label": "Acknowledge",
                        "action_type": "acknowledge",
                    })

        sev_rank = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "MEDIUM": 3, "INFO": 4}
        incidents.sort(key=lambda x: (sev_rank.get(x["severity"], 99), -x["timestamp"]))
        return incidents

    def acknowledge_incident(self, incident_id: str):
        self.acknowledged_incident_ids.add(incident_id)

    def get_full_posture_report(self, blocked_ips: dict[str, Any] = None, recent_anomalies: list[dict[str, Any]] = None, threat_sessions: list[dict[str, Any]] = None) -> dict[str, Any]:
        """Assembles comprehensive live Blue Team state."""
        self.refresh_profile()
        attack_surface = self.auditor.audit_listening_ports()
        gateway_integrity = self.gateway_watchdog.check_integrity()
        kernel_stack = self.kernel_auditor.audit_kernel_stack()
        recon_scans = self.recon_detector.get_recent_scans()
        blocked_ips = blocked_ips or {}
        recent_anomalies = recent_anomalies or []
        threat_sessions = threat_sessions or []

        posture = self.compute_posture_score(
            attack_surface=attack_surface,
            gateway_integrity=gateway_integrity,
            anomalies_count=len(recent_anomalies),
            unencrypted_flows_count=0,
            kernel_stack=kernel_stack,
            recon_scans_count=len(recon_scans),
        )

        incidents = self.generate_incident_triage(
            attack_surface=attack_surface,
            gateway_integrity=gateway_integrity,
            blocked_ips=blocked_ips,
            recent_anomalies=recent_anomalies,
            kernel_stack=kernel_stack,
            recon_scans=recon_scans,
            threat_sessions=threat_sessions,
        )

        return {
            "network_profile": self.network_profile,
            "posture": posture,
            "attack_surface": attack_surface,
            "gateway_integrity": gateway_integrity,
            "kernel_hardening": kernel_stack,
            "recon_scans": recon_scans,
            "incidents": incidents,
            "active_countermeasures": self.active_countermeasures,
            "timestamp": time.time(),
        }

    def generate_security_audit_export(self, blocked_ips: dict[str, Any] = None, recent_anomalies: list[dict[str, Any]] = None) -> dict[str, Any]:
        """Produces a structured compliance and threat audit report for export."""
        report = self.get_full_posture_report(blocked_ips=blocked_ips, recent_anomalies=recent_anomalies)
        now = time.time()
        time_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now))

        return {
            "title": "Robo Blue Hat Team - Host & Network Security Audit Report",
            "audit_timestamp": now,
            "audit_time_utc": time_str,
            "host_profile": report["network_profile"],
            "executive_summary": {
                "posture_score": report["posture"]["score"],
                "security_grade": report["posture"]["grade"],
                "verdict": report["posture"]["verdict"],
                "total_listening_daemons": report["posture"]["counts"]["total_listening"],
                "critical_wan_exposed": report["posture"]["counts"]["critical_exposed"],
                "high_exposed": report["posture"]["counts"]["high_exposed"],
                "safe_localhost_services": report["posture"]["counts"]["safe_localhost"],
            },
            "posture_deductions": report["posture"]["deductions"],
            "kernel_hardening_audit": report["kernel_hardening"],
            "listening_attack_surface": report["attack_surface"],
            "gateway_arp_integrity": report["gateway_integrity"],
            "active_security_incidents": report["incidents"],
            "active_countermeasures": report["active_countermeasures"],
        }
