import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# Ensure project root is in python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

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
        self.data_source = "simulated"  # "simulated" or "live"
        self.scenario = "normal"
        self.interface = "wlo1"
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
        self.lock = threading.Lock()
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
        # Look up Process for local source or dest port
        proc = self.process_tracker.get_process_for_port(pkt.src_port) or self.process_tracker.get_process_for_port(pkt.dst_port)
        pkt_dict["process"] = proc

        # Look up GeoIP for destination
        geo = self.geoip_resolver.resolve(pkt.dst_ip)
        pkt_dict["geoip"] = geo
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
        time.sleep(0.18)  # ~5-6 packets/sec for clear visual streaming


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
        elif parsed.path == "/api/lan":
            devices = GLOBAL_STATE.lan_scanner.scan_lan()
            self._send_json({"devices": devices})
        elif parsed.path == "/api/processes":
            procs = GLOBAL_STATE.process_tracker.get_all_active_processes()
            self._send_json({"processes": procs})
        else:
            self.send_error(404, "File Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scenario":
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

    print(f"================================================================")
    print(f"  GraphIDS Linux ML Network Platform is Live!")
    print(f"  Access Dashboard: http://localhost:{actual_port}")
    print(f"================================================================")
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

