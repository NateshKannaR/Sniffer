import socket
from typing import Any, Dict


class GeoIpResolver:
    """Resolves IP addresses to Organization, ASN, Country, and Hostname."""

    def __init__(self):
        self.cache: Dict[str, Dict[str, Any]] = {}

    def resolve(self, ip: str) -> Dict[str, Any]:
        if not ip or ip == "0.0.0.0":
            return {"org": "Unknown", "asn": "-", "country": "Unknown", "flag": "🌐", "hostname": "-"}

        if ip in self.cache:
            return self.cache[ip]

        info = self._lookup_intelligence(ip)
        self.cache[ip] = info
        return info

    def _lookup_intelligence(self, ip: str) -> Dict[str, Any]:
        # 1. Private / Local LAN
        if (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("127.")
            or ip.startswith("fe80:")
            or ip in ["::1", "localhost"]
        ):
            return {
                "org": "Local Private Subnet",
                "asn": "RFC 1918",
                "country": "Local LAN",
                "flag": "🏠",
                "hostname": "local.lan",
            }

        # 2. Multicast / Broadcast
        if ip == "239.255.255.250" or ip.startswith("224."):
            return {
                "org": "Multicast / SSDP Discovery",
                "asn": "IANA-RESERVED",
                "country": "Local Network",
                "flag": "📡",
                "hostname": "multicast.local",
            }

        # 3. Google Services
        if (
            ip.startswith("2001:4860:")
            or ip.startswith("142.250.")
            or ip.startswith("172.217.")
            or ip in ["8.8.8.8", "8.8.4.4"]
        ):
            return {
                "org": "Google LLC",
                "asn": "AS15169",
                "country": "United States",
                "flag": "🇺🇸",
                "hostname": "google.com",
            }

        # 4. Cloudflare Global CDN
        if (
            ip.startswith("2606:47")
            or ip.startswith("172.64.")
            or ip.startswith("104.16.")
            or ip.startswith("104.17.")
            or ip.startswith("104.18.")
            or ip in ["1.1.1.1", "1.0.0.1"]
        ):
            return {
                "org": "Cloudflare, Inc.",
                "asn": "AS13335",
                "country": "United States",
                "flag": "🇺🇸",
                "hostname": "cloudflare.net",
            }

        # 5. Reliance Jio / Indian ISPs
        if (
            ip.startswith("2409:40f")
            or ip.startswith("49.32.")
            or ip.startswith("49.33.")
            or ip.startswith("157.32.")
        ):
            return {
                "org": "Reliance Jio Infocomm",
                "asn": "AS55836",
                "country": "India",
                "flag": "🇮🇳",
                "hostname": "jio.com",
            }

        # 6. Bharti Airtel
        if ip.startswith("122.16") or ip.startswith("182.7"):
            return {
                "org": "Bharti Airtel Ltd",
                "asn": "AS9498",
                "country": "India",
                "flag": "🇮🇳",
                "hostname": "airtel.in",
            }

        # 7. Amazon AWS
        if (
            ip.startswith("3.")
            or ip.startswith("52.")
            or ip.startswith("54.")
            or ip.startswith("2600:1f")
        ):
            return {
                "org": "Amazon.com, Inc. (AWS)",
                "asn": "AS16509",
                "country": "United States",
                "flag": "🇺🇸",
                "hostname": "amazonaws.com",
            }

        # 8. Microsoft Azure
        if (
            ip.startswith("20.")
            or ip.startswith("40.")
            or ip.startswith("2603:10")
        ):
            return {
                "org": "Microsoft Corporation",
                "asn": "AS8075",
                "country": "United States",
                "flag": "🇺🇸",
                "hostname": "microsoft.com",
            }

        # 9. Generic Reverse DNS fallback
        hostname = ip
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            hostname = name
        except Exception:
            pass

        return {
            "org": "Public Internet Host",
            "asn": "AS-PUBLIC",
            "country": "Global Internet",
            "flag": "🌐",
            "hostname": hostname,
        }
