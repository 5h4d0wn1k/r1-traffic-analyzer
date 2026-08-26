#!/usr/bin/env python3
"""R1 — Network Traffic Analyzer: PCAP parsing, flow reconstruction, protocol stats, anomaly detection, bandwidth analysis."""

import struct
import collections
import json
import sys
from datetime import datetime


class PcapParser:
    """Parse pcap files and extract raw packet data."""

    MAGIC_NATIVE = 0xa1b2c3d4
    MAGIC_SWAPPED = 0xd4c3b2a1
    MAGIC_NANO_NATIVE = 0xa1b23c4d
    MAGIC_NANO_SWAPPED = 0x4d3cb2a1
    ETHERNET_HEADER_LEN = 14
    ETHERTYPE_IP = 0x0800
    ETHERTYPE_IPV6 = 0x86DD
    ETHERTYPE_ARP = 0x0806

    def __init__(self):
        self.global_header = {}
        self.packets = []
        self.byte_order = '>'
        self.nanosecond = False

    def parse_file(self, filepath):
        """Parse a pcap file and return list of packet dicts."""
        with open(filepath, 'rb') as f:
            magic = struct.unpack('I', f.read(4))[0]
            if magic == self.MAGIC_NATIVE:
                self.byte_order = '='
            elif magic == self.MAGIC_SWAPPED:
                self.byte_order = '>'
            elif magic == self.MAGIC_NANO_NATIVE:
                self.byte_order = '='
                self.nanosecond = True
            elif magic == self.MAGIC_NANO_SWAPPED:
                self.byte_order = '>'
                self.nanosecond = True
            else:
                raise ValueError(f"Not a valid pcap file (magic: 0x{magic:08x})")

            hdr_fmt = f'{self.byte_order}HHiIII'
            hdr_size = struct.calcsize(hdr_fmt)
            hdr_data = f.read(hdr_size)
            fields = struct.unpack(hdr_fmt, hdr_data)
            self.global_header = {
                'version_major': fields[0],
                'version_minor': fields[1],
                'thiszone': fields[2],
                'sigfigs': fields[3],
                'snaplen': fields[4],
                'network': fields[5],
            }

            pkt_hdr_fmt = f'{self.byte_order}IIII'
            pkt_hdr_size = struct.calcsize(pkt_hdr_fmt)
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
                    'number': packet_num,
                    'timestamp': ts_sec + ts_usec / 1_000_000.0,
                    'length': orig_len,
                    'captured_length': incl_len,
                    'data': data,
                })
                packet_num += 1
        return self.packets

    def parse_bytes(self, pcap_bytes):
        """Parse pcap data from bytes."""
        import io
        f = io.BytesIO(pcap_bytes)
        magic = struct.unpack('I', f.read(4))[0]
        if magic == self.MAGIC_NATIVE:
            self.byte_order = '='
        elif magic == self.MAGIC_SWAPPED:
            self.byte_order = '>'
        elif magic == self.MAGIC_NANO_NATIVE:
            self.byte_order = '='
            self.nanosecond = True
        elif magic == self.MAGIC_NANO_SWAPPED:
            self.byte_order = '>'
            self.nanosecond = True
        else:
            raise ValueError(f"Not a valid pcap file (magic: 0x{magic:08x})")

        hdr_fmt = f'{self.byte_order}HHiIII'
        hdr_size = struct.calcsize(hdr_fmt)
        hdr_data = f.read(hdr_size)
        fields = struct.unpack(hdr_fmt, hdr_data)
        self.global_header = {
            'version_major': fields[0],
            'version_minor': fields[1],
            'thiszone': fields[2],
            'sigfigs': fields[3],
            'snaplen': fields[4],
            'network': fields[5],
        }
        pkt_hdr_fmt = f'{self.byte_order}IIII'
        pkt_hdr_size = struct.calcsize(pkt_hdr_fmt)
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
                'number': packet_num,
                'timestamp': ts_sec + ts_usec / 1_000_000.0,
                'length': orig_len,
                'captured_length': incl_len,
                'data': data,
            })
            packet_num += 1
        return self.packets


class EthernetParser:
    """Parse Ethernet frames."""

    HEADER_LEN = 14

    @staticmethod
    def parse(data):
        """Parse ethernet header, return dict with dst_mac, src_mac, ethertype, payload."""
        if len(data) < 14:
            return None
        dst_mac = ':'.join(f'{b:02x}' for b in data[0:6])
        src_mac = ':'.join(f'{b:02x}' for b in data[6:12])
        ethertype = struct.unpack('!H', data[12:14])[0]
        return {
            'dst_mac': dst_mac,
            'src_mac': src_mac,
            'ethertype': ethertype,
            'payload': data[14:],
        }


class IPParser:
    """Parse IPv4 headers."""

    PROTOCOL_NAMES = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 51: 'AH'}

    @staticmethod
    def parse(data):
        """Parse IPv4 header, return dict with protocol fields."""
        if len(data) < 20:
            return None
        version_ihl = data[0]
        version = (version_ihl >> 4) & 0xF
        ihl = (version_ihl & 0xF) * 4
        if version != 4:
            return None
        if len(data) < ihl:
            return None
        total_length = struct.unpack('!H', data[2:4])[0]
        protocol_num = data[9]
        src_ip = '.'.join(str(b) for b in data[12:16])
        dst_ip = '.'.join(str(b) for b in data[16:20])
        protocol_name = IPParser.PROTOCOL_NAMES.get(protocol_num, f'PROTO_{protocol_num}')
        return {
            'version': version,
            'header_length': ihl,
            'total_length': total_length,
            'ttl': data[8],
            'protocol': protocol_num,
            'protocol_name': protocol_name,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'payload': data[ihl:],
        }


class TCPParser:
    """Parse TCP headers."""

    FLAGS = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']

    @staticmethod
    def parse(data):
        """Parse TCP header, return dict with port/flags."""
        if len(data) < 20:
            return None
        src_port = struct.unpack('!H', data[0:2])[0]
        dst_port = struct.unpack('!H', data[2:4])[0]
        seq_num = struct.unpack('!I', data[4:8])[0]
        ack_num = struct.unpack('!I', data[8:12])[0]
        data_offset = (data[12] >> 4) & 0xF
        header_len = data_offset * 4
        flags_raw = data[13]
        flags = []
        for i, name in enumerate(TCPParser.FLAGS):
            if flags_raw & (0x80 >> i):
                flags.append(name)
        window = struct.unpack('!H', data[14:16])[0]
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'header_length': header_len,
            'flags': flags,
            'flags_raw': flags_raw,
            'window': window,
            'payload': data[header_len:],
        }


class UDPParser:
    """Parse UDP headers."""

    @staticmethod
    def parse(data):
        """Parse UDP header, return dict with ports/length."""
        if len(data) < 8:
            return None
        src_port = struct.unpack('!H', data[0:2])[0]
        dst_port = struct.unpack('!H', data[2:4])[0]
        length = struct.unpack('!H', data[4:6])[0]
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length,
            'payload': data[8:],
        }


class FlowReconstructor:
    """Reconstruct network flows from parsed packets."""

    def __init__(self):
        self.flows = collections.defaultdict(lambda: {
            'packets': [],
            'bytes_sent': 0,
            'bytes_received': 0,
            'src_packets': 0,
            'dst_packets': 0,
            'start_time': None,
            'end_time': None,
            'flags': set(),
            'protocols': set(),
        })

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Create canonical flow key."""
        parts = sorted([(src_ip, src_port), (dst_ip, dst_port)])
        return (parts[0][0], parts[0][1], parts[1][0], parts[1][1], protocol)

    def add_packet(self, packet, ip_info, transport_info):
        """Add a parsed packet to the flow table."""
        src_ip = ip_info['src_ip']
        dst_ip = ip_info['dst_ip']
        src_port = transport_info.get('src_port', 0)
        dst_port = transport_info.get('dst_port', 0)
        protocol = ip_info['protocol_name']
        key = self._flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        flow = self.flows[key]
        flow['packets'].append(packet['number'])
        length = ip_info['total_length']
        if 'flags' in transport_info:
            flow['flags'].update(transport_info['flags'])
        flow['protocols'].add(protocol)

        if flow['start_time'] is None or packet['timestamp'] < flow['start_time']:
            flow['start_time'] = packet['timestamp']
        if flow['end_time'] is None or packet['timestamp'] > flow['end_time']:
            flow['end_time'] = packet['timestamp']

        return key

    def get_flow_stats(self):
        """Return statistics for all flows."""
        stats = {}
        for key, flow in self.flows.items():
            src_ip, src_port, dst_ip, dst_port, protocol = key
            duration = (flow['end_time'] - flow['start_time']) if flow['start_time'] and flow['end_time'] else 0
            stats[key] = {
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': protocol,
                'packet_count': len(flow['packets']),
                'duration': duration,
                'start_time': flow['start_time'],
                'end_time': flow['end_time'],
                'flags': list(flow['flags']),
            }
        return stats


class ProtocolAnalyzer:
    """Analyze protocol distribution and statistics."""

    def __init__(self):
        self.protocol_counts = collections.Counter()
        self.port_counts = collections.Counter()
        self.ip_src_counts = collections.Counter()
        self.ip_dst_counts = collections.Counter()
        self.packet_sizes = []
        self.timestamps = []

    def analyze_packet(self, packet, ip_info=None, transport_info=None):
        """Record statistics for a single packet."""
        self.packet_sizes.append(packet['length'])
        self.timestamps.append(packet['timestamp'])
        if ip_info:
            self.protocol_counts[ip_info['protocol_name']] += 1
            self.ip_src_counts[ip_info['src_ip']] += 1
            self.ip_dst_counts[ip_info['dst_ip']] += 1
        if transport_info:
            src_port = transport_info.get('src_port', 0)
            dst_port = transport_info.get('dst_port', 0)
            self.port_counts[src_port] += 1
            self.port_counts[dst_port] += 1

    def get_stats(self):
        """Return protocol analysis summary."""
        total = sum(self.protocol_counts.values()) if self.protocol_counts else 0
        protocol_pct = {}
        for proto, count in self.protocol_counts.most_common():
            protocol_pct[proto] = {
                'count': count,
                'percentage': round(count / total * 100, 2) if total > 0 else 0,
            }
        top_ports = self.port_counts.most_common(20)
        top_src = self.ip_src_counts.most_common(10)
        top_dst = self.ip_dst_counts.most_common(10)
        sizes = self.packet_sizes
        return {
            'total_packets': total,
            'total_bytes': sum(sizes),
            'avg_packet_size': round(sum(sizes) / len(sizes), 2) if sizes else 0,
            'min_packet_size': min(sizes) if sizes else 0,
            'max_packet_size': max(sizes) if sizes else 0,
            'protocol_distribution': protocol_pct,
            'top_source_ips': [{'ip': ip, 'count': c} for ip, c in top_src],
            'top_destination_ips': [{'ip': ip, 'count': c} for ip, c in top_dst],
            'top_ports': [{'port': p, 'count': c} for p, c in top_ports],
        }


class AnomalyDetector:
    """Detect anomalous network behavior."""

    def __init__(self):
        self.ip_packet_counts = collections.Counter()
        self.ip_byte_counts = collections.Counter()
        self.port_scan_suspects = collections.defaultdict(set)
        self.syn_flood_suspects = collections.Counter()
        self.anomalies = []

    def analyze_packet(self, packet, ip_info, transport_info):
        """Check a packet for anomalous indicators."""
        if not ip_info:
            return
        src_ip = ip_info['src_ip']
        self.ip_packet_counts[src_ip] += 1
        self.ip_byte_counts[src_ip] += ip_info['total_length']

        if transport_info and 'flags' in transport_info:
            flags = transport_info['flags']
            if 'SYN' in flags and 'ACK' not in flags:
                dst_port = transport_info.get('dst_port', 0)
                self.port_scan_suspects[src_ip].add(dst_port)
                self.syn_flood_suspects[src_ip] += 1

    def detect_anomalies(self, packet_threshold=1000, syn_threshold=100, scan_threshold=20):
        """Run anomaly detection on collected data. Returns list of anomalies."""
        self.anomalies = []

        for ip, count in self.ip_packet_counts.items():
            if count > packet_threshold:
                self.anomalies.append({
                    'type': 'HIGH_VOLUME',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'description': f'IP {ip} sent {count} packets (threshold: {packet_threshold})',
                })

        for ip, byte_count in self.ip_byte_counts.items():
            if byte_count > packet_threshold * 1400:
                self.anomalies.append({
                    'type': 'HIGH_BANDWIDTH',
                    'severity': 'MEDIUM',
                    'source_ip': ip,
                    'description': f'IP {ip} transferred {byte_count} bytes',
                })

        for ip, ports in self.port_scan_suspects.items():
            if len(ports) > scan_threshold:
                self.anomalies.append({
                    'type': 'PORT_SCAN',
                    'severity': 'HIGH',
                    'source_ip': ip,
                    'description': f'IP {ip} probed {len(ports)} unique ports',
                    'ports_sample': list(ports)[:50],
                })

        for ip, syn_count in self.syn_flood_suspects.items():
            if syn_count > syn_threshold:
                self.anomalies.append({
                    'type': 'SYN_FLOOD',
                    'severity': 'CRITICAL',
                    'source_ip': ip,
                    'description': f'IP {ip} sent {syn_count} SYN packets without ACK',
                })

        return self.anomalies


class BandwidthAnalyzer:
    """Analyze bandwidth usage over time."""

    def __init__(self, bucket_seconds=1.0):
        self.bucket_seconds = bucket_seconds
        self.buckets = collections.defaultdict(lambda: {'bytes': 0, 'packets': 0})

    def add_packet(self, packet, ip_info=None):
        """Add a packet to the bandwidth buckets."""
        bucket = int(packet['timestamp'] / self.bucket_seconds) * self.bucket_seconds
        self.buckets[bucket]['bytes'] += packet['length']
        self.buckets[bucket]['packets'] += 1

    def get_timeline(self):
        """Return bandwidth over time as sorted list."""
        timeline = []
        for ts in sorted(self.buckets.keys()):
            b = self.buckets[ts]
            timeline.append({
                'timestamp': ts,
                'bytes': b['bytes'],
                'packets': b['packets'],
                'bits_per_second': b['bytes'] * 8 / self.bucket_seconds,
            })
        return timeline

    def get_summary(self):
        """Return bandwidth summary statistics."""
        timeline = self.get_timeline()
        if not timeline:
            return {'peak_bps': 0, 'avg_bps': 0, 'total_bytes': 0, 'total_packets': 0}
        total_bytes = sum(t['bytes'] for t in timeline)
        total_packets = sum(t['packets'] for t in timeline)
        bps_values = [t['bits_per_second'] for t in timeline]
        return {
            'peak_bps': max(bps_values),
            'avg_bps': round(sum(bps_values) / len(bps_values), 2),
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'time_span_seconds': round(timeline[-1]['timestamp'] - timeline[0]['timestamp'], 3) if len(timeline) > 1 else 0,
            'num_buckets': len(timeline),
        }


class TrafficAnalyzer:
    """Main analyzer combining all components."""

    def __init__(self):
        self.pcap_parser = PcapParser()
        self.eth_parser = EthernetParser()
        self.ip_parser = IPParser()
        self.tcp_parser = TCPParser()
        self.udp_parser = UDPParser()
        self.flow_reconstructor = FlowReconstructor()
        self.protocol_analyzer = ProtocolAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        self.bandwidth_analyzer = BandwidthAnalyzer()
        self.results = {}

    def analyze_pcap(self, filepath):
        """Full analysis pipeline on a pcap file."""
        packets = self.pcap_parser.parse_file(filepath)
        self._process_packets(packets)
        return self.generate_report()

    def analyze_bytes(self, pcap_bytes):
        """Full analysis pipeline on pcap bytes."""
        packets = self.pcap_parser.parse_bytes(pcap_bytes)
        self._process_packets(packets)
        return self.generate_report()

    def _process_packets(self, packets):
        """Process all packets through the analysis pipeline."""
        for packet in packets:
            data = packet['data']
            eth = self.eth_parser.parse(data)
            if eth is None:
                continue

            ip_info = None
            transport_info = None

            if eth['ethertype'] == 0x0800:
                ip_info = self.ip_parser.parse(eth['payload'])
                if ip_info:
                    if ip_info['protocol_name'] == 'TCP':
                        transport_info = self.tcp_parser.parse(ip_info['payload'])
                    elif ip_info['protocol_name'] == 'UDP':
                        transport_info = self.udp_parser.parse(ip_info['payload'])

            if ip_info:
                self.flow_reconstructor.add_packet(packet, ip_info, transport_info or {'src_port': 0, 'dst_port': 0})
                self.protocol_analyzer.analyze_packet(packet, ip_info, transport_info)
                self.anomaly_detector.analyze_packet(packet, ip_info, transport_info)
                self.bandwidth_analyzer.add_packet(packet, ip_info)

    def generate_report(self):
        """Generate a complete analysis report."""
        self.results = {
            'analysis_time': datetime.now().isoformat(),
            'protocol_stats': self.protocol_analyzer.get_stats(),
            'flow_stats': self.flow_reconstructor.get_flow_stats(),
            'anomalies': self.anomaly_detector.detect_anomalies(),
            'bandwidth': self.bandwidth_analyzer.get_summary(),
            'bandwidth_timeline': self.bandwidth_analyzer.get_timeline(),
        }
        return self.results

    def export_json(self, filepath):
        """Export results to JSON."""
        def default_serializer(obj):
            if isinstance(obj, set):
                return list(obj)
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2, default=default_serializer)


def create_test_pcap():
    """Create a minimal test pcap in memory for unit testing."""
    import io
    buf = io.BytesIO()

    magic = 0xa1b2c3d4
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    network = 1  # LINKTYPE_ETHERNET

    hdr_fmt = '=IHHiIII'
    buf.write(struct.pack(hdr_fmt, magic, version_major, version_minor, thiszone, sigfigs, snaplen, network))

    pkt_hdr_fmt = '=IIII'

    for i in range(5):
        src_ip = [192, 168, 1, 10 + i]
        dst_ip = [192, 168, 1, 1]
        ip_header = bytearray(20)
        ip_header[0] = 0x45
        ip_header[2:4] = struct.pack('!H', 40)
        ip_header[8] = 64
        ip_header[9] = 6
        ip_header[12:16] = bytes(src_ip)
        ip_header[16:20] = bytes(dst_ip)

        tcp_header = bytearray(20)
        tcp_header[0:2] = struct.pack('!H', 12345)
        tcp_header[2:4] = struct.pack('!H', 80)
        tcp_header[12] = 0x50
        tcp_header[13] = 0x18

        payload = b'GET / HTTP/1.1\r\nHost: test\r\n\r\n'

        eth_header = bytearray(14)
        eth_header[12:14] = struct.pack('!H', 0x0800)

        pkt_data = bytes(eth_header) + bytes(ip_header) + bytes(tcp_header) + payload
        ts_sec = 1700000000 + i
        ts_usec = i * 100000
        incl_len = len(pkt_data)
        orig_len = incl_len
        buf.write(struct.pack(pkt_hdr_fmt, ts_sec, ts_usec, incl_len, orig_len))
        buf.write(pkt_data)

    return buf.getvalue()


if __name__ == '__main__':
    print("=== R1 — Network Traffic Analyzer ===")
    print("Creating test pcap data...")
    test_pcap = create_test_pcap()

    analyzer = TrafficAnalyzer()
    print("Analyzing packets...")
    results = analyzer.analyze_bytes(test_pcap)

    print(f"\nProtocol Distribution:")
    for proto, info in results['protocol_stats']['protocol_distribution'].items():
        print(f"  {proto}: {info['count']} packets ({info['percentage']}%)")

    print(f"\nTotal Packets: {results['protocol_stats']['total_packets']}")
    print(f"Total Bytes: {results['protocol_stats']['total_bytes']}")
    print(f"Flows Detected: {len(results['flow_stats'])}")
    print(f"Anomalies Found: {len(results['anomalies'])}")
    print(f"Peak Bandwidth: {results['bandwidth']['peak_bps']} bps")
    print("\nAnalysis complete.")
