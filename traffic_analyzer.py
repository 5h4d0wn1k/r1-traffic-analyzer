#!/usr/bin/env python3
"""R1 — Network Traffic Analyzer v2.

Real pcap parsing, flow reconstruction, protocol stats, anomaly detection,
bandwidth analysis, and JSON/Markdown reporting. Stdlib-only.

Reworked into a working baseline:
  - CLI via argparse with --help
  - Fixture pcap generated deterministically (no external capture required)
  - JSON + Markdown reports written to reports/ (gitignored)
  - Deterministic offline tests
"""
import argparse
import collections
import json
import os
import struct
import sys
from datetime import datetime


class PcapParser:
    """Parse pcap files and extract raw packet data."""

    MAGIC_NATIVE = 0xA1B2C3D4
    MAGIC_SWAPPED = 0xD4C3B2A1
    MAGIC_NANO_NATIVE = 0xA1B23C4D
    MAGIC_NANO_SWAPPED = 0x4D3CB2A1

    def __init__(self):
        self.global_header = {}
        self.packets = []
        self.byte_order = ">"
        self.nanosecond = False

    def _read_header(self, f):
        magic_b = f.read(4)
        if len(magic_b) < 4:
            raise ValueError("File too short to be a pcap")
        magic = struct.unpack("I", magic_b)[0]
        if magic == self.MAGIC_NATIVE:
            self.byte_order = "<"
        elif magic == self.MAGIC_SWAPPED:
            self.byte_order = ">"
        elif magic == self.MAGIC_NANO_NATIVE:
            self.byte_order = "<"
            self.nanosecond = True
        elif magic == self.MAGIC_NANO_SWAPPED:
            self.byte_order = ">"
            self.nanosecond = True
        else:
            raise ValueError(f"Not a valid pcap file (magic: 0x{magic:08x})")

        hdr_fmt = f"{self.byte_order}HHiIII"
        hdr_data = f.read(struct.calcsize(hdr_fmt))
        if len(hdr_data) < struct.calcsize(hdr_fmt):
            raise ValueError("Truncated pcap global header")
        fields = struct.unpack(hdr_fmt, hdr_data)
        self.global_header = {
            "version_major": fields[0],
            "version_minor": fields[1],
            "thiszone": fields[2],
            "sigfigs": fields[3],
            "snaplen": fields[4],
            "network": fields[5],
        }

    def _read_packets(self, f):
        pkt_hdr_fmt = f"{self.byte_order}IIII"
        pkt_hdr_size = struct.calcsize(pkt_hdr_fmt)
        self.packets = []
        packet_num = 0
        while True:
            pkt_hdr = f.read(pkt_hdr_size)
            if len(pkt_hdr) < pkt_hdr_size:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(pkt_hdr_fmt, pkt_hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            if self.nanosecond:
                ts_usec = ts_usec / 1000.0
            self.packets.append({
                "number": packet_num,
                "timestamp": ts_sec + ts_usec / 1_000_000.0,
                "length": orig_len,
                "captured_length": incl_len,
                "data": data,
            })
            packet_num += 1
        return self.packets

    def parse_bytes(self, pcap_bytes):
        import io
        f = io.BytesIO(pcap_bytes)
        self._read_header(f)
        return self._read_packets(f)

    def parse_file(self, filepath):
        with open(filepath, "rb") as f:
            self._read_header(f)
            return self._read_packets(f)


class EthernetParser:
    HEADER_LEN = 14

    @staticmethod
    def parse(data):
        if len(data) < 14:
            return None
        dst_mac = ":".join(f"{b:02x}" for b in data[0:6])
        src_mac = ":".join(f"{b:02x}" for b in data[6:12])
        ethertype = struct.unpack("!H", data[12:14])[0]
        return {
            "dst_mac": dst_mac,
            "src_mac": src_mac,
            "ethertype": ethertype,
            "payload": data[14:],
        }


class IPParser:
    PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH"}

    @staticmethod
    def parse(data):
        if len(data) < 20:
            return None
        version_ihl = data[0]
        version = (version_ihl >> 4) & 0xF
        ihl = (version_ihl & 0xF) * 4
        if version != 4:
            return None
        if len(data) < ihl:
            return None
        total_length = struct.unpack("!H", data[2:4])[0]
        protocol_num = data[9]
        src_ip = ".".join(str(b) for b in data[12:16])
        dst_ip = ".".join(str(b) for b in data[16:20])
        protocol_name = IPParser.PROTOCOL_NAMES.get(protocol_num, f"PROTO_{protocol_num}")
        return {
            "version": version,
            "header_length": ihl,
            "total_length": total_length,
            "ttl": data[8],
            "protocol": protocol_num,
            "protocol_name": protocol_name,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "payload": data[ihl:],
        }


class TCPParser:
    FLAGS = ["CWR", "ECE", "URG", "ACK", "PSH", "RST", "SYN", "FIN"]

    @staticmethod
    def parse(data):
        if len(data) < 20:
            return None
        src_port = struct.unpack("!H", data[0:2])[0]
        dst_port = struct.unpack("!H", data[2:4])[0]
        seq_num = struct.unpack("!I", data[4:8])[0]
        ack_num = struct.unpack("!I", data[8:12])[0]
        data_offset = (data[12] >> 4) & 0xF
        header_len = data_offset * 4
        flags_raw = data[13]
        flags = []
        for i, name in enumerate(TCPParser.FLAGS):
            if flags_raw & (0x80 >> i):
                flags.append(name)
        window = struct.unpack("!H", data[14:16])[0]
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq_num": seq_num,
            "ack_num": ack_num,
            "header_length": header_len,
            "flags": flags,
            "flags_raw": flags_raw,
            "window": window,
            "payload": data[header_len:],
        }


class UDPParser:
    @staticmethod
    def parse(data):
        if len(data) < 8:
            return None
        src_port = struct.unpack("!H", data[0:2])[0]
        dst_port = struct.unpack("!H", data[2:4])[0]
        length = struct.unpack("!H", data[4:6])[0]
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "payload": data[8:],
        }


class FlowReconstructor:
    def __init__(self):
        self.flows = collections.defaultdict(lambda: {
            "packets": [],
            "start_time": None,
            "end_time": None,
            "flags": set(),
            "protocols": set(),
        })

    @staticmethod
    def _flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
        parts = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        return (parts[0][0], parts[0][1], parts[1][0], parts[1][1], protocol)

    def add_packet(self, packet, ip_info, transport_info):
        src_ip = ip_info["src_ip"]
        dst_ip = ip_info["dst_ip"]
        src_port = transport_info.get("src_port", 0) if transport_info else 0
        dst_port = transport_info.get("dst_port", 0) if transport_info else 0
        protocol = ip_info["protocol_name"]
        key = self._flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        flow = self.flows[key]
        flow["packets"].append(packet["number"])
        if transport_info and "flags" in transport_info:
            flow["flags"].update(transport_info["flags"])
        flow["protocols"].add(protocol)
        if flow["start_time"] is None or packet["timestamp"] < flow["start_time"]:
            flow["start_time"] = packet["timestamp"]
        if flow["end_time"] is None or packet["timestamp"] > flow["end_time"]:
            flow["end_time"] = packet["timestamp"]
        return key

    def get_flow_stats(self):
        stats = {}
        for key, flow in self.flows.items():
            src_ip, src_port, dst_ip, dst_port, protocol = key
            duration = (flow["end_time"] - flow["start_time"]) if flow["start_time"] and flow["end_time"] else 0
            str_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}"
            stats[str_key] = {
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_count": len(flow["packets"]),
                "duration": round(duration, 6),
                "start_time": flow["start_time"],
                "end_time": flow["end_time"],
                "flags": list(flow["flags"]),
            }
        return stats


class ProtocolAnalyzer:
    def __init__(self):
        self.protocol_counts = collections.Counter()
        self.port_counts = collections.Counter()
        self.ip_src_counts = collections.Counter()
        self.ip_dst_counts = collections.Counter()
        self.packet_sizes = []
        self.timestamps = []

    def analyze_packet(self, packet, ip_info=None, transport_info=None):
        self.packet_sizes.append(packet["length"])
        self.timestamps.append(packet["timestamp"])
        if ip_info:
            self.protocol_counts[ip_info["protocol_name"]] += 1
            self.ip_src_counts[ip_info["src_ip"]] += 1
            self.ip_dst_counts[ip_info["dst_ip"]] += 1
        if transport_info:
            self.port_counts[transport_info.get("src_port", 0)] += 1
            self.port_counts[transport_info.get("dst_port", 0)] += 1

    def get_stats(self):
        total = sum(self.protocol_counts.values())
        protocol_pct = {
            proto: {"count": c, "percentage": round(c / total * 100, 2) if total else 0}
            for proto, c in self.protocol_counts.most_common()
        }
        sizes = self.packet_sizes
        return {
            "total_packets": total,
            "total_bytes": sum(sizes),
            "avg_packet_size": round(sum(sizes) / len(sizes), 2) if sizes else 0,
            "min_packet_size": min(sizes) if sizes else 0,
            "max_packet_size": max(sizes) if sizes else 0,
            "protocol_distribution": protocol_pct,
            "top_source_ips": [{"ip": ip, "count": c} for ip, c in self.ip_src_counts.most_common(10)],
            "top_destination_ips": [{"ip": ip, "count": c} for ip, c in self.ip_dst_counts.most_common(10)],
            "top_ports": [{"port": p, "count": c} for p, c in self.port_counts.most_common(20)],
        }


class AnomalyDetector:
    def __init__(self):
        self.ip_packet_counts = collections.Counter()
        self.ip_byte_counts = collections.Counter()
        self.port_scan_suspects = collections.defaultdict(set)
        self.syn_flood_suspects = collections.Counter()
        self.anomalies = []

    def analyze_packet(self, packet, ip_info, transport_info):
        if not ip_info:
            return
        src_ip = ip_info["src_ip"]
        self.ip_packet_counts[src_ip] += 1
        self.ip_byte_counts[src_ip] += ip_info["total_length"]
        if transport_info and "flags" in transport_info:
            flags = transport_info["flags"]
            if "SYN" in flags and "ACK" not in flags:
                dst_port = transport_info.get("dst_port", 0)
                self.port_scan_suspects[src_ip].add(dst_port)
                self.syn_flood_suspects[src_ip] += 1

    def detect_anomalies(self, packet_threshold=1000, syn_threshold=100, scan_threshold=20):
        self.anomalies = []
        for ip, count in self.ip_packet_counts.items():
            if count > packet_threshold:
                self.anomalies.append({
                    "type": "HIGH_VOLUME",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "description": f"IP {ip} sent {count} packets (threshold: {packet_threshold})",
                })
        for ip, byte_count in self.ip_byte_counts.items():
            if byte_count > packet_threshold * 1400:
                self.anomalies.append({
                    "type": "HIGH_BANDWIDTH",
                    "severity": "MEDIUM",
                    "source_ip": ip,
                    "description": f"IP {ip} transferred {byte_count} bytes",
                })
        for ip, ports in self.port_scan_suspects.items():
            if len(ports) > scan_threshold:
                self.anomalies.append({
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "source_ip": ip,
                    "description": f"IP {ip} probed {len(ports)} unique ports",
                    "ports_sample": list(ports)[:50],
                })
        for ip, syn_count in self.syn_flood_suspects.items():
            if syn_count > syn_threshold:
                self.anomalies.append({
                    "type": "SYN_FLOOD",
                    "severity": "CRITICAL",
                    "source_ip": ip,
                    "description": f"IP {ip} sent {syn_count} SYN packets without ACK",
                })
        return self.anomalies


class BandwidthAnalyzer:
    def __init__(self, bucket_seconds=1.0):
        self.bucket_seconds = bucket_seconds
        self.buckets = collections.defaultdict(lambda: {"bytes": 0, "packets": 0})

    def add_packet(self, packet, ip_info=None):
        bucket = int(packet["timestamp"] / self.bucket_seconds) * self.bucket_seconds
        self.buckets[bucket]["bytes"] += packet["length"]
        self.buckets[bucket]["packets"] += 1

    def get_timeline(self):
        timeline = []
        for ts in sorted(self.buckets.keys()):
            b = self.buckets[ts]
            timeline.append({
                "timestamp": round(ts, 3),
                "bytes": b["bytes"],
                "packets": b["packets"],
                "bits_per_second": b["bytes"] * 8 / self.bucket_seconds,
            })
        return timeline

    def get_summary(self):
        timeline = self.get_timeline()
        if not timeline:
            return {"peak_bps": 0, "avg_bps": 0, "total_bytes": 0, "total_packets": 0}
        total_bytes = sum(t["bytes"] for t in timeline)
        total_packets = sum(t["packets"] for t in timeline)
        bps_values = [t["bits_per_second"] for t in timeline]
        return {
            "peak_bps": max(bps_values),
            "avg_bps": round(sum(bps_values) / len(bps_values), 2),
            "total_bytes": total_bytes,
            "total_packets": total_packets,
            "time_span_seconds": round(timeline[-1]["timestamp"] - timeline[0]["timestamp"], 3) if len(timeline) > 1 else 0,
            "num_buckets": len(timeline),
        }


class TrafficAnalyzer:
    def __init__(self):
        self.pcap_parser = PcapParser()
        self.flow_reconstructor = FlowReconstructor()
        self.protocol_analyzer = ProtocolAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.bandwidth_analyzer = BandwidthAnalyzer()
        self.results = {}

    def analyze_bytes(self, pcap_bytes):
        packets = self.pcap_parser.parse_bytes(pcap_bytes)
        return self._process_packets(packets)

    def analyze_pcap(self, filepath):
        packets = self.pcap_parser.parse_file(filepath)
        return self._process_packets(packets)

    def _process_packets(self, packets):
        for packet in packets:
            data = packet["data"]
            eth = EthernetParser.parse(data)
            if eth is None:
                continue
            ip_info = None
            transport_info = None
            if eth["ethertype"] == 0x0800:
                ip_info = IPParser.parse(eth["payload"])
                if ip_info:
                    if ip_info["protocol_name"] == "TCP":
                        transport_info = TCPParser.parse(ip_info["payload"])
                    elif ip_info["protocol_name"] == "UDP":
                        transport_info = UDPParser.parse(ip_info["payload"])
            if ip_info:
                self.flow_reconstructor.add_packet(packet, ip_info, transport_info)
                self.protocol_analyzer.analyze_packet(packet, ip_info, transport_info)
                self.anomaly_detector.analyze_packet(packet, ip_info, transport_info)
                self.bandwidth_analyzer.add_packet(packet, ip_info)
        return self.generate_report()

    def generate_report(self):
        self.results = {
            "analysis_time": datetime.now().isoformat(),
            "protocol_stats": self.protocol_analyzer.get_stats(),
            "flow_stats": self.flow_reconstructor.get_flow_stats(),
            "anomalies": self.anomaly_detector.detect_anomalies(),
            "bandwidth": self.bandwidth_analyzer.get_summary(),
            "bandwidth_timeline": self.bandwidth_analyzer.get_timeline(),
        }
        return self.results

    def to_json(self):
        return json.dumps(self.results, indent=2, default=lambda o: repr(o))

    def to_markdown(self):
        ps = self.results["protocol_stats"]
        lines = ["# R1 Traffic Analyzer Report", ""]
        lines.append(f"- Analysis time: {self.results['analysis_time']}")
        lines.append(f"- Total packets: {ps['total_packets']}")
        lines.append(f"- Total bytes: {ps['total_bytes']}")
        lines.append("")
        lines.append("## Protocol Distribution")
        lines.append("| Protocol | Count | % |")
        lines.append("|----------|-------|---|")
        for proto, info in ps["protocol_distribution"].items():
            lines.append(f"| {proto} | {info['count']} | {info['percentage']}% |")
        lines.append("")
        lines.append("## Flows")
        lines.append(f"Total flows: {len(self.results['flow_stats'])}")
        lines.append("")
        lines.append("## Anomalies")
        if self.results["anomalies"]:
            for a in self.results["anomalies"]:
                lines.append(f"- [{a['severity']}] {a['type']}: {a['description']}")
        else:
            lines.append("None")
        lines.append("")
        lines.append("## Bandwidth")
        b = self.results["bandwidth"]
        lines.append(f"- Peak: {b['peak_bps']} bps, Avg: {b['avg_bps']} bps")
        return "\n".join(lines)


def write_report(report_dir, results_json, markdown):
    os.makedirs(report_dir, exist_ok=True)
    json_path = os.path.join(report_dir, "r1_report.json")
    md_path = os.path.join(report_dir, "r1_report.md")
    with open(json_path, "w") as f:
        f.write(results_json)
    with open(md_path, "w") as f:
        f.write(markdown)
    return json_path, md_path


def make_fixture_pcap():
    """Create a deterministic pcap fixture with a realistic mix of packets."""
    buf = bytearray()
    magic = 0xA1B2C3D4
    hdr_fmt = "=IHHiIII"
    buf += struct.pack(hdr_fmt, magic, 2, 4, 0, 0, 65535, 1)
    pkt_hdr_fmt = "=IIII"

    def build_packet(src_ip, dst_ip, proto, sport, dport, flags=0x18, payload=b""):
        ip_header = bytearray(20)
        ip_header[0] = 0x45
        ip_header[2:4] = struct.pack("!H", 20 + 20 + len(payload))
        ip_header[8] = 64
        ip_header[9] = proto
        ip_header[12:16] = bytes([int(x) for x in src_ip.split(".")])
        ip_header[16:20] = bytes([int(x) for x in dst_ip.split(".")])
        tcp_header = bytearray(20)
        tcp_header[0:2] = struct.pack("!H", sport)
        tcp_header[2:4] = struct.pack("!H", dport)
        tcp_header[12] = 0x50
        tcp_header[13] = flags
        if proto == 17:
            udp_header = bytearray(8)
            udp_header[0:2] = struct.pack("!H", sport)
            udp_header[2:4] = struct.pack("!H", dport)
            udp_header[4:6] = struct.pack("!H", 8 + len(payload))
            transport = bytes(udp_header) + payload
            ip_header[2:4] = struct.pack("!H", 20 + len(transport))
        else:
            transport = bytes(tcp_header) + payload
        eth_header = bytearray(14)
        eth_header[12:14] = struct.pack("!H", 0x0800)
        pkt_data = bytes(eth_header) + bytes(ip_header) + transport
        return pkt_data

    packets_data = []
    # TCP traffic
    for i in range(10):
        packets_data.append(build_packet("192.168.1.10", "192.168.1.1", 6, 12345, 80, 0x18, b"GET / HTTP/1.1\r\n\r\n"))
    # TCP SYN to many ports (port scan)
    for port in range(1, 30):
        packets_data.append(build_packet("10.0.0.5", "10.0.0.1", 6, 40000 + port, port, 0x02))
    # UDP DNS
    for i in range(5):
        packets_data.append(build_packet("192.168.1.10", "8.8.8.8", 17, 5353, 53))
    # ICMP-ish (use UDP as proxy not needed; keep protocol 6/17 only for parser)
    # High-bandwidth burst
    for i in range(20):
        packets_data.append(build_packet("192.168.1.20", "192.168.1.1", 6, 50000 + i, 443, 0x18, b"A" * 1400))

    ts_sec = 1700000000
    ts_usec = 0
    for i, pkt in enumerate(packets_data):
        ts_sec_i = ts_sec + i // 100
        ts_usec_i = (i % 100) * 10000
        buf += struct.pack(pkt_hdr_fmt, ts_sec_i, ts_usec_i, len(pkt), len(pkt))
        buf += pkt
    return bytes(buf)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="traffic_analyzer",
        description="R1 — Network Traffic Analyzer v2: pcap parsing, flows, anomalies, bandwidth.",
    )
    parser.add_argument("pcap", nargs="?", help="Path to a pcap file. If omitted, uses the built-in fixture.")
    parser.add_argument("-o", "--report-dir", default="reports",
                        help="Directory to write reports to (default: reports)")
    parser.add_argument("--json-only", action="store_true", help="Only print JSON report")
    args = parser.parse_args(argv)

    analyzer = TrafficAnalyzer()
    if args.pcap:
        results = analyzer.analyze_pcap(args.pcap)
        src_label = f"pcap: {args.pcap}"
    else:
        fixture = make_fixture_pcap()
        results = analyzer.analyze_bytes(fixture)
        src_label = "built-in fixture"

    print("=" * 60)
    print("  R1 — Network Traffic Analyzer v2")
    print("=" * 60)
    print(f"  Source      : {src_label}")
    print(f"  Total packets: {results['protocol_stats']['total_packets']}")
    print(f"  Total bytes : {results['protocol_stats']['total_bytes']}")
    print(f"  Flows       : {len(results['flow_stats'])}")
    print(f"  Anomalies   : {len(results['anomalies'])}")
    print(f"  Peak BW     : {results['bandwidth']['peak_bps']} bps")
    print()
    print("  Protocol Distribution:")
    for proto, info in results["protocol_stats"]["protocol_distribution"].items():
        print(f"    {proto}: {info['count']} ({info['percentage']}%)")
    print()
    print("  Anomalies:")
    for a in results["anomalies"]:
        print(f"    [{a['severity']}] {a['type']}: {a['description']}")

    json_str = analyzer.to_json()
    md_str = analyzer.to_markdown()
    json_path, md_path = write_report(args.report_dir, json_str, md_str)
    print()
    print(f"  Reports written to:")
    print(f"    {json_path}")
    print(f"    {md_path}")

    if args.json_only:
        print(json_str)

    print("\n  Analysis complete — exit 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
