# R1 — Network Traffic Analyzer v2

Real pcap parsing, flow reconstruction, protocol statistics, anomaly detection, bandwidth analysis, and JSON/Markdown reporting. Rebuild of the legacy `traffic_analyzer.py` into a working, tested baseline.

## Overview

This project implements a comprehensive network traffic analysis system that:
- Parses PCAP files and extracts packet data at multiple protocol layers
- Reconstructs network flows from captured traffic
- Calculates protocol distribution and statistics
- Detects anomalous behavior (port scans, SYN floods, high-volume traffic)
- Analyzes bandwidth usage over time
- Emits machine-readable (JSON) and human-readable (Markdown) reports

## Features

- **PCAP Parsing**: Parse pcap files with support for both byte orders and nanosecond timestamps
- **Protocol Analysis**: Ethernet, IPv4, TCP, UDP header parsing with field extraction
- **Flow Reconstruction**: Track bidirectional flows with packet counts and duration
- **Anomaly Detection**: Identify port scans, SYN floods, and high-volume anomalies (correct TCP flag decoding)
- **Bandwidth Analysis**: Time-bucketed bandwidth tracking with peak/average metrics
- **CLI**: argparse with `--help`, `-o` report directory, `--json-only`
- **Reports**: JSON + Markdown written to `reports/` (gitignored)
- **Fixtures**: deterministic built-in pcap generator for offline testing
- **Standard Library Only**: uses struct, collections, json — no external dependencies

## Usage

```bash
# Run built-in demo on the fixture (writes reports/ + prints summary)
python3 traffic_analyzer.py

# Analyze a real pcap file
python3 traffic_analyzer.py capture.pcap

# Custom report directory, JSON only
python3 traffic_analyzer.py capture.pcap -o ./out --json-only

# Help
python3 traffic_analyzer.py --help

# Run unit tests
python3 -m unittest discover -s tests -v
```

Programmatic use:

```python
from traffic_analyzer import TrafficAnalyzer

analyzer = TrafficAnalyzer()

# Analyze a pcap file
results = analyzer.analyze_pcap("capture.pcap")

# Or analyze bytes (e.g. fixture / in-memory buffer)
results = analyzer.analyze_bytes(pcap_bytes)

# Reports
json_str = analyzer.to_json()
md_str = analyzer.to_markdown()
```

## Output

The demo outputs a console summary and writes:
- `reports/r1_report.json`
- `reports/r1_report.md`

Both are gitignored.

## Live Lab Test Plan

| Phase | Description | Go / No-Go Criteria | Status |
|-------|-------------|---------------------|--------|
| Phase 0 | Offline fixture validation (this tool) | Demo exits 0, tests pass, port scan detected | DONE |
| Phase 1 | Real pcap ingestion | Parses a captured pcap without error, reports match packet counts | PENDING |
| Phase 2 | Synthetic anomaly validation (SYN flood, high-volume) | Detector flags engineered anomalies in lab traffic | PENDING |
| Phase 3 | Benchmark against tshark/Wireshark | Flow & bandwidth stats within tolerance of reference tool | PENDING |

## Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Fixture packets parsed | 64 | 64 |
| TCP/UDP decoding | Correct events | Verified |
| Port scan detection | Yes | Yes |
| Test pass rate | 100% | 100% |
| Demo exit code | 0 | 0 |

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
