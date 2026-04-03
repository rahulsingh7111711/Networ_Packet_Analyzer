# 📡 NeatLabs™ Packet Capture Analyzer
### Deep Packet Inspection • Traffic Forensics • Network Threat Detection

**NeatLabs™ — Bringing Context to Chaos**

---

## Overview

**NeatLabs™ Packet Capture Analyzer** is an enterprise-grade network forensics and traffic analysis platform designed for cybersecurity professionals, incident responders, threat hunters, and digital forensics teams.

The system performs deep packet inspection, protocol dissection, session reconstruction, anomaly detection, and threat scoring from PCAP and PCAPNG capture files.

Built in pure Python with zero external dependencies for core analysis, the platform provides full traffic intelligence, IOC extraction, and professional forensic reporting.

---

## 🚀 Core Capabilities

### 📦 Native Capture Analysis
- PCAP and PCAPNG parsing
- Gzip-compressed capture support
- Pure Python parser (no Scapy or dpkt required)
- High-performance packet processing

---

### 🌐 Protocol Dissection
- Ethernet
- IPv4 / IPv6
- TCP / UDP
- ICMP
- ARP
- DNS
- HTTP
- TLS
- VLAN handling
- Application-layer identification

---

### 🔁 Flow & Session Reconstruction
- TCP session tracking
- UDP flow analysis
- Traffic timeline reconstruction
- Source/destination mapping
- Bandwidth analysis
- Top talker identification

---

### 🔍 Threat Detection Engine

#### Network Attack Detection
- Port scan detection
- Command-and-control beaconing detection
- Data exfiltration detection
- DNS tunneling detection
- ARP spoofing / cache poisoning detection
- Suspicious port usage detection
- Cleartext credential transmission detection

#### Encryption Analysis
- TLS handshake inspection
- Deprecated SSL/TLS detection
- Cipher suite analysis
- SNI extraction

---

### 🧠 Traffic Intelligence
- IOC extraction (IPs, domains, URLs)
- DNS query analysis
- HTTP request analysis
- User-agent profiling
- External vs internal IP classification
- Protocol distribution metrics
- TTL distribution analysis

---

### 🎯 Risk Assessment
- Comprehensive threat scoring engine (0–100)
- Severity-based anomaly classification
- Risk level assessment
- Evidence-based findings

---

### 📊 Reporting & Export
- Standalone HTML forensic reports
- JSON export
- Investigation summary dashboard
- Traffic statistics
- IOC listings
- Timeline visualizations

---

## 🖥 Interface Options

### Graphical Interface
- Interactive analysis dashboard
- Real-time packet inspection
- Threat visualization
- Investigation workflow UI

### Command Line Interface
- Automated analysis pipeline
- Batch processing
- Report generation
- Scriptable workflows

---

## 📦 Installation

### Requirements

- Python 3.9+
- No external dependencies required for core functionality

Clone repository:

```bash
git clone https://github.com/neatlabs-ai/packet-capture-analyzer
cd packet-capture-analyzer
```

---

## ⚡ Usage

### Launch GUI

```bash
python packet_capture_analyzer.py
```

---

### Analyze PCAP File

```bash
python packet_capture_analyzer.py capture.pcap
```

---

### Analyze PCAPNG File

```bash
python packet_capture_analyzer.py capture.pcapng
```

---

### Generate HTML Report

```bash
python packet_capture_analyzer.py capture.pcap -r report.html
```

---

### JSON Output

```bash
python packet_capture_analyzer.py capture.pcap --json
```

---

### Generate Demo Capture Dataset

Creates a realistic sample capture with:

- HTTPS traffic
- DNS queries
- HTTP requests
- C2 beaconing behavior
- DNS tunneling patterns
- ARP spoofing attempt
- Suspicious traffic patterns

```bash
python packet_capture_analyzer.py --demo
```

---

## 🧠 Architecture

```
Capture Parser
    ↓
Protocol Dissector
    ↓
Flow Reconstruction Engine
    ↓
Traffic Analyzer
    ↓
Threat Detection Engine
    ↓
Risk Scoring Engine
    ↓
Report Generator
```

---

## 🎯 Use Cases

- Incident response investigations
- Network forensics
- Malware traffic analysis
- Threat hunting
- SOC investigations
- Data exfiltration detection
- Intrusion detection validation
- DFIR workflows
- Security research

---

## 🔐 Security Notice

This tool performs automated analysis and should not replace expert validation.

Always:

- Validate findings independently
- Execute in controlled environments
- Treat capture data as sensitive

---

## 🗺 Roadmap

- PCAP live capture mode
- SIEM integration
- ML anomaly detection
- Distributed analysis engine
- Threat intelligence feed integration
- Interactive timeline visualization

---

## 👤 Author

NeatLabs™  
https://neatlabs.ai

Service-Disabled Veteran-Owned Small Business

---

## 📜 License

MIT

---

## ⭐ About NeatLabs™

NeatLabs develops advanced cybersecurity, AI, and information integrity platforms that provide deep technical insight, automated analysis, and actionable intelligence across complex digital environments.
