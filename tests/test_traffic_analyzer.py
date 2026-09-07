#!/usr/bin/env python3
"""R1 — Traffic Analyzer v2: unit tests."""
import glob
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from traffic_analyzer import (
    AnomalyDetector,
    BandwidthAnalyzer,
    EthernetParser,
    FlowReconstructor,
    IPParser,
    PcapParser,
    ProtocolAnalyzer,
    TCPParser,
    TrafficAnalyzer,
    UDPParser,
    make_fixture_pcap,
    write_report,
)


class TestPcapParser(unittest.TestCase):
    def setUp(self):
        self.fixture = make_fixture_pcap()
        self.parser = PcapParser()

    def test_parse_fixture(self):
        packets = self.parser.parse_bytes(self.fixture)
        self.assertGreater(len(packets), 0)
        self.assertEqual(self.parser.global_header["network"], 1)

    def test_packet_fields(self):
        packets = self.parser.parse_bytes(self.fixture)
        p = packets[0]
        self.assertIn("data", p)
        self.assertIn("timestamp", p)
        self.assertIn("length", p)
        self.assertIn("captured_length", p)

    def test_invalid_magic(self):
        with self.assertRaises(ValueError):
            self.parser.parse_bytes(b"\x00\x00\x00\x00garbage")

    def test_write_and_reparse(self):
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "test.pcap")
            with open(path, "wb") as f:
                f.write(self.fixture)
            parser2 = PcapParser()
            packets = parser2.parse_file(path)
            self.assertEqual(len(packets), len(self.parser.parse_bytes(self.fixture)))


class TestEthernetParser(unittest.TestCase):
    def test_parse_ethernet(self):
        eth = EthernetParser.parse(b"\x00" * 14 + b"\x45" * 20)
        self.assertEqual(eth["ethertype"], 0x0000)

    def test_too_short(self):
        self.assertIsNone(EthernetParser.parse(b"\x00" * 10))


class TestIPParser(unittest.TestCase):
    def test_parse_ipv4(self):
        pkt = bytearray(20)
        pkt[0] = 0x45
        pkt[9] = 6
        pkt[12:16] = bytes([192, 168, 1, 10])
        pkt[16:20] = bytes([192, 168, 1, 1])
        ip = IPParser.parse(bytes(pkt))
        self.assertEqual(ip["protocol_name"], "TCP")
        self.assertEqual(ip["src_ip"], "192.168.1.10")

    def test_not_ipv4(self):
        self.assertIsNone(IPParser.parse(b"\x60" + b"\x00" * 19))


class TestTCPParser(unittest.TestCase):
    def test_parse_tcp(self):
        import struct
        data = bytearray(20)
        data[0:2] = struct.pack("!H", 12345)
        data[2:4] = struct.pack("!H", 80)
        data[13] = 0x12
        tcp = TCPParser.parse(bytes(data))
        self.assertIn("SYN", tcp["flags"])
        self.assertIn("ACK", tcp["flags"])

    def test_parse_tcp_flags_psh_ack(self):
        import struct
        data = bytearray(20)
        data[0:2] = struct.pack("!H", 12345)
        data[2:4] = struct.pack("!H", 80)
        data[13] = 0x18
        tcp = TCPParser.parse(bytes(data))
        self.assertIn("PSH", tcp["flags"])
        self.assertIn("ACK", tcp["flags"])


class TestUDPParser(unittest.TestCase):
    def test_parse_udp(self):
        import struct
        data = bytearray(8)
        data[0:2] = struct.pack("!H", 5353)
        data[2:4] = struct.pack("!H", 53)
        udp = UDPParser.parse(bytes(data))
        self.assertEqual(udp["src_port"], 5353)
        self.assertEqual(udp["dst_port"], 53)


class TestFlowReconstructor(unittest.TestCase):
    def test_flow_key_bidirectional(self):
        fr = FlowReconstructor()
        k1 = fr._flow_key("1.1.1.1", "2.2.2.2", 10, 20, "TCP")
        k2 = fr._flow_key("2.2.2.2", "1.1.1.1", 20, 10, "TCP")
        self.assertEqual(k1, k2)


class TestProtocolAnalyzer(unittest.TestCase):
    def test_get_stats_returns_keys(self):
        pa = ProtocolAnalyzer()
        stats = pa.get_stats()
        for k in ("total_packets", "total_bytes", "avg_packet_size", "protocol_distribution",
                  "top_source_ips", "top_destination_ips", "top_ports"):
            self.assertIn(k, stats)


class TestAnomalyDetector(unittest.TestCase):
    def test_port_scan_detection(self):
        ad = AnomalyDetector()
        for port in range(1, 30):
            ip = {"src_ip": "10.0.0.5", "protocol_name": "TCP", "total_length": 40}
            trans = {"flags": ["SYN"], "dst_port": port}
            pkt = {"number": port, "timestamp": float(port), "length": 40}
            ad.analyze_packet(pkt, ip, trans)
        anomalies = ad.detect_anomalies(scan_threshold=20)
        port_scans = [a for a in anomalies if a["type"] == "PORT_SCAN"]
        self.assertEqual(len(port_scans), 1)


class TestBandwidthAnalyzer(unittest.TestCase):
    def test_summary(self):
        ba = BandwidthAnalyzer()
        for i in range(10):
            ba.add_packet({"timestamp": float(i), "length": 100})
        s = ba.get_summary()
        self.assertEqual(s["total_packets"], 10)
        self.assertEqual(s["total_bytes"], 1000)


class TestTrafficAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = TrafficAnalyzer()

    def test_analyze_fixture(self):
        results = self.analyzer.analyze_bytes(make_fixture_pcap())
        self.assertIn("protocol_stats", results)
        self.assertIn("flow_stats", results)
        self.assertIn("anomalies", results)
        self.assertGreater(results["protocol_stats"]["total_packets"], 0)

    def test_tcp_and_udp_present(self):
        results = self.analyzer.analyze_bytes(make_fixture_pcap())
        dist = results["protocol_stats"]["protocol_distribution"]
        self.assertIn("TCP", dist)
        self.assertIn("UDP", dist)

    def test_anomaly_port_scan_present(self):
        results = self.analyzer.analyze_bytes(make_fixture_pcap())
        types = {a["type"] for a in results["anomalies"]}
        self.assertIn("PORT_SCAN", types)

    def test_to_json_valid(self):
        self.analyzer.analyze_bytes(make_fixture_pcap())
        text = self.analyzer.to_json()
        data = json.loads(text)
        self.assertIn("protocol_stats", data)

    def test_to_markdown(self):
        self.analyzer.analyze_bytes(make_fixture_pcap())
        md = self.analyzer.to_markdown()
        self.assertIn("R1 Traffic Analyzer Report", md)


class TestWriteReport(unittest.TestCase):
    def test_writes_files(self):
        with tempfile.TemporaryDirectory() as td:
            jp, mp = write_report(td, '{"a": 1}', "# Report")
            self.assertTrue(os.path.exists(jp))
            self.assertTrue(os.path.exists(mp))
            with open(jp) as f:
                self.assertIn("a", f.read())


class TestMainCLI(unittest.TestCase):
    def test_help(self):
        from traffic_analyzer import main
        with self.assertRaises(SystemExit) as ctx:
            main(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_demo_runs(self):
        from traffic_analyzer import main
        with tempfile.TemporaryDirectory() as td:
            ret = main(["-o", td])
            self.assertEqual(ret, 0)
            p = os.path.join(td, "r1_report.json")
            self.assertTrue(os.path.exists(p))


if __name__ == "__main__":
    unittest.main()
