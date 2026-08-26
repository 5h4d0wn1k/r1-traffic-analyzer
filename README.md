# R1 — Network Traffic Analyzer

PCAP parsing, flow reconstruction, protocol statistics, anomaly detection, and bandwidth analysis for security research.

## Overview

This project implements a comprehensive network traffic analysis system that:
- Parses PCAP files and extracts packet data at multiple protocol layers
- Reconstructs network flows from captured traffic
- Calculates protocol distribution and statistics
- Detects anomalous behavior (port scans, SYN floods, high-volume traffic)
- Analyzes bandwidth usage over time

## Features

- **PCAP Parsing**: Parse pcap files with support for both byte orders and nanosecond timestamps
- **Protocol Analysis**: Ethernet, IPv4, TCP, UDP header parsing with field extraction
- **Flow Reconstruction**: Track bidirectional flows with packet counts and duration
- **Anomaly Detection**: Identify port scans, SYN floods, and high-volume anomalies
- **Bandwidth Analysis**: Time-bucketed bandwidth tracking with peak/average metrics
- **Standard Library Only**: Uses struct, collections, json — no external dependencies

## Usage

```python
from traffic_analyzer import TrafficAnalyzer

# Analyze a pcap file
analyzer = TrafficAnalyzer()
results = analyzer.analyze_pcap("capture.pcap")

# Or analyze from bytes
results = analyzer.analyze_bytes(pcap_bytes)

# Export results
analyzer.export_json("report.json")
```

```bash
# Run built-in demo
python3 traffic_analyzer.py
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

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
