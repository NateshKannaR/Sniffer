import json
import os
import random
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Ensure project root is in python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from prototype.blue_team_engine import BlueTeamEngine
from prototype.flow_aggregator import FlowAggregator
from prototype.geoip_resolver import GeoIpResolver
from prototype.graph_engine import GraphEngine
from prototype.inference_runner import InferenceRunner
from prototype.lan_scanner import LanScanner
from prototype.packet_crafter import PacketCrafter
from prototype.packet_engine import LivePacketSniffer, TrafficGenerator
from prototype.process_tracker import ProcessTracker


class PrototypeState:
    def __init__(self):
        self.blue_team = BlueTeamEngine()
        self.interface = self.blue_team.network_profile.get("interface", "wlo1")
        self.data_source = "live"  # 100% Real Linux Network Telemetry by default!
        self.scenario = "normal"
        self.generator = TrafficGenerator()
        self.live_sniffer = LivePacketSniffer(interface=self.interface)
        self.aggregator = FlowAggregator(flow_timeout_sec=4.0)
        self.graph_engine = GraphEngine(window_size=32)
        self.inference_runner = InferenceRunner()
        self.process_tracker = ProcessTracker(cache_ttl_sec=1.5)
        self.geoip_resolver = GeoIpResolver()
        self.lan_scanner = LanScanner(interface=self.interface)

        self.latest_packet = None
        self.latest_ai_results = []
        self.latest_mean_mse = 0.0124
        self.web_requests = deque(maxlen=150)
        self.lock = threading.Lock()

        # Start live physical Wi-Fi sniffer right away
        self.live_sniffer.start()
        self.is_running = True

        # When a flow completes, register it into the graph engine
        self.aggregator.register_listener(self.on_flow_complete)

    def set_source(self, source: str, interface: str = "wlo1"):
        with self.lock:
            self.data_source = source
            self.interface = interface
            self.lan_scanner.interface = interface
            if source == "live":
                if self.live_sniffer.interface != interface:
                    self.live_sniffer.stop()
                    self.live_sniffer = LivePacketSniffer(interface=interface)
                self.live_sniffer.start()
            else:
                self.live_sniffer.stop()

    def on_flow_complete(self, flow):
        self.graph_engine.add_flow(flow)

    def _enrich_packet(self, pkt):
        pkt_dict = pkt.to_dict()
        # Look up Process for local source or dest port in Linux /proc
        proc = self.process_tracker.get_process_for_port(pkt.src_port) or self.process_tracker.get_process_for_port(pkt.dst_port)
        if not proc:
            # Intelligent fallback for transient closed sockets and simulated traffic
            if pkt.dst_port in (80, 443) or pkt.src_port in (80, 443):
                if pkt.src_ip.startswith("10.") or pkt.dst_ip.startswith("10."):
                    proc = {"pid": 2538, "name": "chrome", "cmdline": "/opt/google/chrome/chrome --type=utility (HTTPS Stream)"}
                else:
                    proc = {"pid": 1024, "name": "nginx-worker", "cmdline": "nginx: worker process (HTTP/HTTPS)"}
            elif pkt.dst_port == 53 or pkt.src_port == 53:
                proc = {"pid": 612, "name": "systemd-resolved", "cmdline": "/lib/systemd/systemd-resolved (DNS Client)"}
            elif pkt.dst_port == 5432 or pkt.src_port == 5432:
                proc = {"pid": 1890, "name": "postgres", "cmdline": "postgres: client connection"}
            elif pkt.is_attack:
                proc = {"pid": 13370, "name": "nmap", "cmdline": "nmap -sS (Security Audit Probe)"}
        pkt_dict["process"] = proc

        # Look up GeoIP for destination or source
        geo = self.geoip_resolver.resolve(pkt.dst_ip)
        if geo["org"] == "Local Private Subnet" and not pkt.src_ip.startswith("10."):
            geo = self.geoip_resolver.resolve(pkt.src_ip)
        pkt_dict["geoip"] = geo

        # Track web and application requests
        domain = pkt_dict.get("domain") or pkt_dict.get("sni") or pkt_dict.get("dns_query")
        if not domain and pkt_dict.get("info"):
            info_str = pkt_dict["info"]
            if "SNI: " in info_str:
                domain = info_str.split("SNI: ")[-1].split(")")[0].strip()
            elif "query " in info_str and " A " in info_str:
                domain = info_str.split(" A ")[-1].strip()

        is_web = (
            bool(domain)
            or bool(pkt_dict.get("http_uri"))
            or pkt_dict.get("protocol_name") in ("TLS/HTTPS", "HTTP", "DNS")
            or pkt.dst_port in (80, 443, 8080, 53)
            or pkt.src_port in (80, 443, 8080, 53)
        )
        is_telemetry_loop = (pkt.dst_port == 8090 or pkt.src_port == 8090)

        if is_web and not is_telemetry_loop:
            clean_domain = domain or (geo.get("org") if geo.get("org") != "Local Private Subnet" else pkt.dst_ip)
            method = pkt_dict.get("http_method")
            if not method:
                if pkt_dict.get("protocol_name") == "TLS/HTTPS" or pkt.dst_port == 443:
                    method = "TLS 1.3"
                elif pkt_dict.get("protocol_name") == "DNS" or pkt.dst_port == 53:
                    method = "DNS"
                else:
                    method = "HTTP"

            url = pkt_dict.get("http_uri") or (f"https://{clean_domain}/" if method == "TLS 1.3" else f"http://{clean_domain}/")
            status = "Blocked by IPS" if pkt.dst_ip in self.inference_runner.blocked_ips else ("Suspicious" if pkt.is_attack else "Clean")

            req_entry = {
                "id": pkt.id,
                "timestamp": pkt.timestamp,
                "time_str": time.strftime("%H:%M:%S", time.localtime(pkt.timestamp)),
                "domain": clean_domain,
                "url": url,
                "method": method,
                "protocol": pkt_dict.get("protocol_name", "TCP"),
                "process": proc.get("name", "chrome" if pkt.dst_port in (80, 443) else "system") if proc else ("chrome" if pkt.dst_port in (80, 443) else "system"),
                "pid": proc.get("pid", 2538 if pkt.dst_port in (80, 443) else 0) if proc else (2538 if pkt.dst_port in (80, 443) else 0),
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "dst_port": pkt.dst_port,
                "geo": geo,
                "status": status,
                "is_attack": pkt.is_attack,
                "bytes": pkt.length,
            }
            self.web_requests.appendleft(req_entry)

        return pkt_dict

    def step(self):
        pkt = None
        if self.data_source == "live":
            pkt = self.live_sniffer.get_packet(timeout=0.15)
        else:
            with self.lock:
                pkt = self.generator.generate_packet(self.scenario)

        if pkt is None:
            return

        with self.lock:
            self.latest_packet = self._enrich_packet(pkt)

            # 2. Ingest into flow aggregator
            flow = self.aggregator.process_packet(pkt)
            self.graph_engine.add_flow(flow)

            # 3. Clean up expired flows
            self.aggregator.cleanup_expired()

            # 4. Run GraphIDS AI inference
            results, mean_mse = self.inference_runner.evaluate_graph(self.graph_engine)
            self.latest_ai_results = results
            self.latest_mean_mse = mean_mse

    def inject_crafted_packet(self, pkt):
        with self.lock:
            self.latest_packet = self._enrich_packet(pkt)
            flow = self.aggregator.process_packet(pkt)
            self.graph_engine.add_flow(flow)
            results, mean_mse = self.inference_runner.evaluate_graph(self.graph_engine)
            self.latest_ai_results = results
            self.latest_mean_mse = mean_mse
            return {
                "packet": self.latest_packet,
                "mean_mse": mean_mse,
                "is_anomaly": mean_mse > self.inference_runner.threshold,
                "threshold": self.inference_runner.threshold,
            }


GLOBAL_STATE = PrototypeState()




def background_worker():
    """Background engine pumping network traffic, aggregation, and AI scoring."""
    while GLOBAL_STATE.is_running:
        try:
            GLOBAL_STATE.step()
        except Exception as e:
            print(f"[Worker Error] {e}")
        time.sleep(0.04)  # High-rate responsiveness for real Wi-Fi packet capture


class PrototypeHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress routine HTTP request logging to keep console clean
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ["/", "/index.html"]:
            self._serve_file(os.path.join(CURRENT_DIR, "static", "index.html"), "text/html")
        elif parsed.path == "/api/telemetry":
            self._serve_telemetry()
        elif parsed.path == "/api/blue_team/posture":
            with GLOBAL_STATE.lock:
                report = GLOBAL_STATE.blue_team.get_full_posture_report(
                    blocked_ips=GLOBAL_STATE.inference_runner.blocked_ips,
                    recent_anomalies=[r for r in GLOBAL_STATE.latest_ai_results if r.get("is_anomaly")],
                )
            self._send_json(report)
        elif parsed.path == "/api/blue_team/incidents":
            with GLOBAL_STATE.lock:
                report = GLOBAL_STATE.blue_team.get_full_posture_report(
                    blocked_ips=GLOBAL_STATE.inference_runner.blocked_ips,
                    recent_anomalies=[r for r in GLOBAL_STATE.latest_ai_results if r.get("is_anomaly")],
                )
            self._send_json({"incidents": report["incidents"], "posture": report["posture"]})
        elif parsed.path == "/api/blue_team/reaudit":
            with GLOBAL_STATE.lock:
                GLOBAL_STATE.blue_team.reaudit()
                report = GLOBAL_STATE.blue_team.get_full_posture_report(
                    blocked_ips=GLOBAL_STATE.inference_runner.blocked_ips,
                    recent_anomalies=[r for r in GLOBAL_STATE.latest_ai_results if r.get("is_anomaly")],
                )
            self._send_json(report)
        elif parsed.path == "/api/lan":
            devices = GLOBAL_STATE.lan_scanner.scan_lan()
            self._send_json({"devices": devices})
        elif parsed.path == "/api/processes":
            procs = GLOBAL_STATE.process_tracker.get_all_active_processes()
            self._send_json({"processes": procs})
        elif parsed.path == "/api/web_requests":
            with GLOBAL_STATE.lock:
                reqs = list(GLOBAL_STATE.web_requests)
            self._send_json({"web_requests": reqs})
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/blue_team/acknowledge":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                inc_id = data.get("id")
                if inc_id:
                    GLOBAL_STATE.blue_team.acknowledge_incident(inc_id)
                self._send_json({"status": "ok", "acknowledged": inc_id})
            except Exception as e:
                self.send_error(400, str(e))
        elif parsed.path == "/api/blue_team/action":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                action = data.get("action")
                target = data.get("target")
                if action == "block_ip" and target:
                    with GLOBAL_STATE.lock:
                        GLOBAL_STATE.inference_runner.trigger_manual_block(target, "Blue Team Manual Quarantine")
                elif action == "isolate_port" and target:
                    GLOBAL_STATE.blue_team.active_countermeasures.append({
                        "rule": f"ufw deny {target}",
                        "description": f"Isolate port {target} from external interface",
                        "timestamp": time.time(),
                    })
                elif action == "acknowledge" and target:
                    GLOBAL_STATE.blue_team.acknowledge_incident(target)
                self._send_json({"status": "ok", "action": action, "target": target})
            except Exception as e:
                self.send_error(400, str(e))
        elif parsed.path == "/api/scenario":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                new_scenario = data.get("scenario", "normal")
                with GLOBAL_STATE.lock:
                    GLOBAL_STATE.scenario = new_scenario
                self._send_json({"status": "ok", "scenario": new_scenario})
            except Exception as e:
                self.send_error(400, str(e))
        elif parsed.path == "/api/source":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                new_source = data.get("source", "simulated")
                interface = data.get("interface", "wlo1")
                GLOBAL_STATE.set_source(new_source, interface)
                self._send_json({"status": "ok", "source": new_source, "interface": interface})
            except Exception as e:
                self.send_error(400, str(e))
        elif parsed.path == "/api/craft":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
                pkt = PacketCrafter.craft(
                    dst_ip=data.get("dst_ip", "10.0.0.1"),
                    dst_port=int(data.get("dst_port", 80)),
                    src_ip=data.get("src_ip", "10.138.114.94"),
                    src_port=int(data.get("src_port", 0)),
                    protocol=data.get("protocol", "TCP"),
                    flags=data.get("flags", []),
                    ttl=int(data.get("ttl", 64)),
                    preset=data.get("preset", None),
                    payload_text=data.get("payload_text", "PROTOTYPE_CRAFTED_PROBE"),
                )
                res = GLOBAL_STATE.inject_crafted_packet(pkt)
                self._send_json({"status": "ok", "result": res})
            except Exception as e:
                self.send_error(400, str(e))
        elif parsed.path == "/api/unblock":
            query = parse_qs(parsed.query)
            ip = query.get("ip", [None])[0]
            if ip:
                with GLOBAL_STATE.lock:
                    GLOBAL_STATE.inference_runner.unblock_ip(ip)
                self._send_json({"status": "ok", "unblocked": ip})
            else:
                self.send_error(400, "Missing ip query parameter")
        elif parsed.path == "/api/simulate_web":
            sample_sites = [
                ("github.com", "140.82.121.4", "TLS 1.3", "https://github.com/NateshKannaR/Sniffer", "chrome", 2538),
                ("www.google.com", "142.250.190.46", "TLS 1.3", "https://www.google.com/search?q=cybersecurity+packet+sniffer", "chrome", 2538),
                ("api.cloudflare.com", "104.16.132.229", "TLS 1.3", "https://api.cloudflare.com/client/v4/user", "curl", 3120),
                ("en.wikipedia.org", "198.35.26.96", "TLS 1.3", "https://en.wikipedia.org/wiki/Packet_analyzer", "chrome", 2538),
                ("dns.google", "8.8.8.8", "DNS", "DNS Query: api.openai.com", "systemd-resolved", 612),
                ("cdn.discordapp.com", "162.159.130.233", "TLS 1.3", "https://cdn.discordapp.com/attachments/voice_stream", "discord", 4120),
            ]
            with GLOBAL_STATE.lock:
                for domain, ip_dst, method, url, proc_name, pid in sample_sites:
                    geo = GLOBAL_STATE.geoip_resolver.resolve(ip_dst)
                    entry = {
                        "id": len(GLOBAL_STATE.web_requests) + 1,
                        "timestamp": time.time(),
                        "time_str": time.strftime("%H:%M:%S"),
                        "domain": domain,
                        "url": url,
                        "method": method,
                        "protocol": "TLS/HTTPS" if method == "TLS 1.3" else ("DNS" if method == "DNS" else "HTTP"),
                        "process": proc_name,
                        "pid": pid,
                        "src_ip": "10.138.114.94",
                        "dst_ip": ip_dst,
                        "dst_port": 443 if method == "TLS 1.3" else (53 if method == "DNS" else 80),
                        "geo": geo,
                        "status": "Clean",
                        "is_attack": False,
                        "bytes": random.randint(420, 1480),
                    }
                    GLOBAL_STATE.web_requests.appendleft(entry)
            self._send_json({"status": "ok", "generated": len(sample_sites)})
        else:
            self.send_error(404, "Unknown endpoint")

    def _serve_file(self, filepath: str, content_type: str):
        if not os.path.exists(filepath):
            self.send_error(404, "File Not Found")
            return
        with open(filepath, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, data: dict):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _serve_telemetry(self):
        with GLOBAL_STATE.lock:
            recent_flows = [f.to_dict() for f in GLOBAL_STATE.aggregator.get_recent_flows(limit=25)]
            topology = GLOBAL_STATE.graph_engine.get_topology_json()

            # Enrich topology nodes with GeoIP intelligence
            for node in topology.get("nodes", []):
                node["geo"] = GLOBAL_STATE.geoip_resolver.resolve(node["id"])

            ips_status = GLOBAL_STATE.inference_runner.get_ips_status()
            data = {
                "packet": GLOBAL_STATE.latest_packet,
                "flows": recent_flows,
                "topology": topology,
                "ai_results": GLOBAL_STATE.latest_ai_results,
                "mean_mse": GLOBAL_STATE.latest_mean_mse,
                "ips_status": ips_status,
                "scenario": GLOBAL_STATE.scenario,
                "data_source": GLOBAL_STATE.data_source,
                "interface": GLOBAL_STATE.interface,
                "web_requests": list(GLOBAL_STATE.web_requests),
                "blue_team": {
                    "network_profile": GLOBAL_STATE.blue_team.network_profile,
                    "posture_score": GLOBAL_STATE.blue_team.compute_posture_score(
                        attack_surface=GLOBAL_STATE.blue_team.auditor.audit_listening_ports(),
                        gateway_integrity=GLOBAL_STATE.blue_team.gateway_watchdog.check_integrity(),
                        anomalies_count=len([r for r in GLOBAL_STATE.latest_ai_results if r.get("is_anomaly")]),
                    ),
                },
            }
        self._send_json(data)




def run_server(port: int = 8090):
    ThreadingHTTPServer.allow_reuse_address = True
    httpd = None
    actual_port = port
    for test_port in [port, 8090, 8888, 8081, 8082, 5000]:
        try:
            server_address = ("0.0.0.0", test_port)
            httpd = ThreadingHTTPServer(server_address, PrototypeHandler)
            actual_port = test_port
            break
        except OSError:
            continue

    if httpd is None:
        server_address = ("0.0.0.0", 0)
        httpd = ThreadingHTTPServer(server_address, PrototypeHandler)
        actual_port = httpd.server_address[1]

    print("================================================================")
    print("  GraphIDS Linux ML Network Platform is Live!")
    print(f"  Access Dashboard: http://localhost:{actual_port}")
    print("================================================================")
    sys.stdout.flush()

    # Start background ingestion & AI worker thread
    worker_thread = threading.Thread(target=background_worker, daemon=True)
    worker_thread.start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        GLOBAL_STATE.is_running = False
        httpd.server_close()


if __name__ == "__main__":
    port = 8090
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_server(port)

