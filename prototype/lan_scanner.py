import os
import subprocess
import time
from typing import Any


class LanScanner:
    """Discovers neighboring devices on the local Wi-Fi LAN using ARP and OUI inspection."""

    OUI_VENDORS = {
        "ce:a3:10": "Wi-Fi Router / Gateway",
        "50:2f:9b": "Intel Corporate (Wi-Fi 6E)",
        "08:00:27": "Oracle VirtualBox",
        "00:0c:29": "VMware Virtual Host",
        "00:50:56": "VMware Infrastructure",
        "b8:27:eb": "Raspberry Pi Foundation",
        "dc:a6:32": "Raspberry Pi Foundation",
        "00:1a:11": "Google Nest / Chromecast",
        "f0:18:98": "Apple, Inc. (iPhone/Mac)",
        "a4:83:e7": "Apple, Inc. (iPad/Watch)",
        "ac:5f:3e": "Samsung Electronics",
        "70:2c:1f": "Samsung Electronics",
        "68:db:f5": "TP-Link Technologies",
        "50:c7:bf": "TP-Link Smart Home",
        "24:4b:fe": "Espressif IoT (ESP32/ESP8266)",
        "84:f3:eb": "Xiaomi Communications",
    }

    def __init__(self, interface: str = "wlo1"):
        self.interface = interface
        self.last_scan_time = 0.0
        self.cached_devices: list[dict[str, Any]] = []

    def get_oui_vendor(self, mac: str) -> str:
        if not mac:
            return "Unknown Device"
        clean_mac = mac.lower().strip()
        prefix = clean_mac[:8]
        if prefix in self.OUI_VENDORS:
            return self.OUI_VENDORS[prefix]

        # Check standard prefixes
        if clean_mac.startswith("00:00:00") or clean_mac == "ff:ff:ff:ff:ff:ff":
            return "Broadcast / Multicast"
        return "Generic Network Device"

    def scan_lan(self) -> list[dict[str, Any]]:
        """Parses Linux kernel ARP table and inspects local neighborhood."""
        devices = []
        mac_seen = {}
        arp_path = "/proc/net/arp"

        if not os.path.exists(arp_path):
            return []

        try:
            with open(arp_path) as f:
                lines = f.readlines()[1:]  # Skip header

            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 6:
                    ip = parts[0]
                    mac = parts[3]
                    device_iface = parts[5]

                    # Filter invalid / incomplete MACs
                    if mac == "00:00:00:00:00:00" or ":" not in mac:
                        continue

                    vendor = self.get_oui_vendor(mac)
                    from prototype.blue_team_engine import DynamicNetworkDetector
                    net_profile = DynamicNetworkDetector.detect_network_profile()
                    is_gateway = ip == net_profile.get("gateway_ip") or ip.endswith(".1") or "Router" in vendor

                    # Check for ARP Spoofing (duplicate MAC for multiple distinct IPs)
                    arp_spoof_risk = False
                    if mac in mac_seen and mac_seen[mac] != ip:
                        arp_spoof_risk = True

                    mac_seen[mac] = ip

                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "vendor": vendor,
                        "interface": device_iface,
                        "is_gateway": is_gateway,
                        "arp_spoof_risk": arp_spoof_risk,
                        "status": "ONLINE",
                        "last_seen": time.time(),
                    })
        except Exception as e:
            print(f"[LanScanner Error] {e}")

        # If ARP proc is empty, query kernel ip neigh for active physical neighbors
        if not devices:
            try:
                res = subprocess.run(
                    ["ip", "neigh", "show", "dev", self.interface],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=1.0,
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 5 and "lladdr" in parts:
                            idx = parts.index("lladdr")
                            ip = parts[0]
                            mac = parts[idx + 1]
                            if mac != "00:00:00:00:00:00" and ":" in mac:
                                from prototype.blue_team_engine import DynamicNetworkDetector
                                net_profile = DynamicNetworkDetector.detect_network_profile()
                                is_gateway = ip == net_profile.get("gateway_ip") or ip.endswith(".1")
                                vendor = self.get_oui_vendor(mac)
                                devices.append({
                                    "ip": ip,
                                    "mac": mac,
                                    "vendor": vendor,
                                    "interface": self.interface,
                                    "is_gateway": is_gateway,
                                    "arp_spoof_risk": False,
                                    "status": "ONLINE",
                                    "last_seen": time.time(),
                                })
            except Exception:
                pass

        self.last_scan_time = time.time()
        self.cached_devices = devices
        return devices
