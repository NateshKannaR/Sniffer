from typing import Any

from prototype.flow_aggregator import FlowRecord

try:
    import torch
    from torch_geometric.data import Data
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False
    torch = None
    Data = None


class GraphEngine:
    """Maintains a dynamic sliding-window network graph and prepares PyG batches."""

    def __init__(self, window_size: int = 64, num_edge_features: int = 43):
        self.window_size = window_size
        self.num_edge_features = num_edge_features
        self.flow_history: list[FlowRecord] = []
        self.node_to_idx: dict[str, int] = {}
        self.idx_to_node: dict[int, str] = {}

    def add_flow(self, flow: FlowRecord):
        self.flow_history.append(flow)
        if len(self.flow_history) > self.window_size:
            self.flow_history.pop(0)

        # Update IP mappings
        for ip in [flow.src_ip, flow.dst_ip]:
            if ip not in self.node_to_idx:
                new_idx = len(self.node_to_idx)
                self.node_to_idx[ip] = new_idx
                self.idx_to_node[new_idx] = ip

    def to_pyg_data(self) -> Any | None:
        """Converts the current sliding window into a PyTorch Geometric Data object."""
        if not self.flow_history:
            return None

        # Build fresh node index for the current active window
        window_ips = set()
        for f in self.flow_history:
            window_ips.add(f.src_ip)
            window_ips.add(f.dst_ip)

        local_node_to_idx = {ip: idx for idx, ip in enumerate(sorted(window_ips))}
        num_nodes = len(local_node_to_idx)

        src_indices = [local_node_to_idx[f.src_ip] for f in self.flow_history]
        dst_indices = [local_node_to_idx[f.dst_ip] for f in self.flow_history]
        features = [f.to_feature_vector(self.num_edge_features) for f in self.flow_history]

        if HAS_TORCH:
            edge_index = torch.tensor([src_indices, dst_indices], dtype=torch.long)
            edge_attr = torch.tensor(features, dtype=torch.float)
            x = torch.ones((num_nodes, self.num_edge_features), dtype=torch.float)
            edge_couples = edge_index.t().contiguous()

            data = Data(
                x=x,
                edge_index=edge_index,
                edge_attr=edge_attr,
                num_nodes=num_nodes,
            )
            data.edge_couples = edge_couples
            return data
        else:
            # Fallback lightweight dict representation
            class MockData:
                def __init__(self, src_idx, dst_idx, feats, n_nodes):
                    self.src_indices = src_idx
                    self.dst_indices = dst_idx
                    self.features = feats
                    self.num_nodes = n_nodes

            return MockData(src_indices, dst_indices, features, num_nodes)

    def get_topology_json(self) -> dict[str, Any]:
        """Returns node and edge structures for frontend interactive rendering."""
        window_ips = set()
        for f in self.flow_history:
            window_ips.add(f.src_ip)
            window_ips.add(f.dst_ip)

        from prototype.blue_team_engine import DynamicNetworkDetector
        net_profile = DynamicNetworkDetector.detect_network_profile()
        host_ip = net_profile.get("host_ip", "127.0.0.1")
        gateway_ip = net_profile.get("gateway_ip", "")
        subnet_prefix = host_ip.rsplit(".", 1)[0] + "." if "." in host_ip and host_ip != "127.0.0.1" else ""

        nodes = []
        for ip in sorted(window_ips):
            # Check if associated with an attack
            is_attack_node = any(
                f.is_attack for f in self.flow_history if f.src_ip == ip or f.dst_ip == ip
            )
            is_my_machine = ip in (host_ip, "127.0.0.1", "::1", "localhost")
            is_gw = (ip == gateway_ip or (not gateway_ip and ip.endswith(".1")))
            is_lan_peer = (subnet_prefix and ip.startswith(subnet_prefix) and not is_my_machine and not is_gw)

            if is_attack_node:
                node_type = "attacker"
                role = "Attacker / Scanner"
            elif is_my_machine:
                node_type = "client"
                role = "My Machine (Local)"
            elif is_gw or any(f.dst_port == 53 for f in self.flow_history if f.dst_ip == ip):
                node_type = "gateway"
                role = "Gateway / DNS"
            elif is_lan_peer or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("fe80:"):
                node_type = "client"
                role = "LAN Peer"
            else:
                node_type = "server"
                role = "Cloud / Web Host"

            # In/Out degree count
            in_deg = sum(1 for f in self.flow_history if f.dst_ip == ip)
            out_deg = sum(1 for f in self.flow_history if f.src_ip == ip)

            nodes.append({
                "id": ip,
                "label": ip,
                "type": node_type,
                "role": role,
                "in_degree": in_deg,
                "out_degree": out_deg,
            })


        edges = []
        for idx, f in enumerate(self.flow_history):
            edges.append({
                "id": f.flow_id,
                "source": f.src_ip,
                "target": f.dst_ip,
                "protocol": f.protocol,
                "src_port": f.src_port,
                "dst_port": f.dst_port,
                "bytes": f.in_bytes + f.out_bytes,
                "is_attack": f.is_attack,
                "attack_type": f.attack_type,
                "tcp_flags": f.tcp_flags_str,
            })

        return {"nodes": nodes, "edges": edges}
