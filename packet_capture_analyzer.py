#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                      PACKET CAPTURE ANALYZER v1.0                              ║
║                              NEATLABS ™                                        ║
║       Deep Packet Inspection • Traffic Forensics • Threat Detection            ║
╚══════════════════════════════════════════════════════════════════════════════════╝

Enterprise-grade PCAP forensic analysis tool for cybersecurity professionals.
Pure Python — zero external dependencies for core analysis.

CAPABILITIES:
  • Native PCAP & PCAPNG parsing (no scapy/dpkt required)
  • Full protocol dissection: Ethernet, IPv4/v6, TCP, UDP, ICMP, ARP, DNS, HTTP, TLS
  • TCP/UDP flow reconstruction and session tracking
  • DNS query extraction with tunneling detection
  • HTTP request/response analysis with user-agent profiling
  • TLS handshake inspection (SNI, cipher suites, certificate metadata)
  • ARP spoofing / cache poisoning detection
  • Anomaly engine: port scans, beaconing, data exfiltration, DNS tunneling,
    cleartext credentials, suspicious ports, GeoIP-free reputation heuristics
  • Comprehensive threat scoring with risk assessment
  • IOC extraction (IPs, domains, URLs, user agents)
  • Traffic timeline and bandwidth analysis
  • Professional HTML report generation
  • Full GUI + CLI interface

USAGE:
  python3 packet_capture_analyzer.py                       # Launch GUI
  python3 packet_capture_analyzer.py capture.pcap          # Analyze PCAP (CLI)
  python3 packet_capture_analyzer.py capture.pcapng        # Analyze PCAPNG
  python3 packet_capture_analyzer.py cap.pcap -r report.html  # Custom report path
  python3 packet_capture_analyzer.py cap.pcap --json       # JSON output
  python3 packet_capture_analyzer.py --demo                # Generate sample PCAP + analyze

Author: NEATLABS
License: Proprietary — All Rights Reserved
"""

import sys, os, re, json, hashlib, math, time, struct, socket, argparse
import io, gzip, threading, ipaddress, collections
from datetime import datetime, timezone, timedelta
from pathlib import Path
from collections import Counter, defaultdict, OrderedDict
from typing import Optional, Dict, List, Tuple, Any, Set

VERSION = "1.0.0"
TOOL_NAME = "Packet Capture Analyzer"
BRAND = "NEATLABS"

# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1
PCAP_MAGIC_NS_LE = 0xa1b23c4d  # nanosecond resolution
PCAP_MAGIC_NS_BE = 0x4d3cb2a1
PCAPNG_MAGIC = 0x0a0d0d0a

ETHERTYPES = {0x0800: 'IPv4', 0x0806: 'ARP', 0x86DD: 'IPv6', 0x8100: 'VLAN', 0x88CC: 'LLDP'}

IP_PROTOCOLS = {
    1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6-encap',
    47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 132: 'SCTP',
}

WELL_KNOWN_PORTS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-S', 68: 'DHCP-C', 69: 'TFTP', 80: 'HTTP',
    110: 'POP3', 119: 'NNTP', 123: 'NTP', 135: 'RPC', 137: 'NetBIOS-NS',
    138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN', 143: 'IMAP', 161: 'SNMP',
    162: 'SNMP-Trap', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    500: 'IKE', 514: 'Syslog', 515: 'LPD', 520: 'RIP', 587: 'SMTP-Sub',
    636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S', 1080: 'SOCKS', 1433: 'MSSQL',
    1434: 'MSSQL-Mon', 1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS',
    3306: 'MySQL', 3389: 'RDP', 3478: 'STUN', 4443: 'Pharos',
    5060: 'SIP', 5061: 'SIPS', 5222: 'XMPP', 5432: 'PostgreSQL',
    5900: 'VNC', 5901: 'VNC-1', 6379: 'Redis', 6667: 'IRC',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt2',
    9200: 'Elasticsearch', 9300: 'ES-Transport', 27017: 'MongoDB',
}

SUSPICIOUS_PORTS = {
    4444: 'Metasploit default', 5555: 'Android ADB', 1337: 'Leet/backdoor',
    31337: 'Back Orifice', 12345: 'NetBus', 54321: 'Back Orifice 2K',
    6666: 'IRC/backdoor', 6667: 'IRC', 6697: 'IRC-SSL',
    9001: 'Tor', 9050: 'Tor SOCKS', 9150: 'Tor Browser',
    4445: 'Upnotifyp', 8291: 'Mikrotik Winbox', 2323: 'Telnet-alt',
    1234: 'Hotline', 65535: 'Max port/suspicious',
}

DNS_TYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
    16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 43: 'DS',
    46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 65: 'HTTPS', 255: 'ANY',
}

TLS_VERSIONS = {
    0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
    0x0300: 'SSL 3.0', 0x0200: 'SSL 2.0',
}

DEPRECATED_TLS = {0x0300, 0x0301, 0x0302, 0x0200}

HTTP_METHODS = {b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH', b'CONNECT', b'TRACE'}

PRIVATE_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'), ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'), ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('255.255.255.255/32'),
]

COLORS = {
    'bg_dark': '#0a0e1a', 'bg_mid': '#111827', 'bg_card': '#1a2332',
    'bg_input': '#0f1629', 'border': '#2a3a4a', 'accent': '#3b82f6',
    'accent_hover': '#2563eb', 'text': '#e2e8f0', 'text_secondary': '#94a3b8',
    'text_muted': '#64748b', 'green': '#22c55e', 'yellow': '#f59e0b',
    'orange': '#f97316', 'red': '#ef4444', 'critical': '#dc2626',
    'purple': '#a855f7', 'cyan': '#06b6d4', 'white': '#ffffff',
}


def _is_private(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_RANGES)
    except:
        return False


def _esc(t):
    return str(t).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')


def _human_bytes(b):
    for u in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024: return f'{b:.1f} {u}'
        b /= 1024
    return f'{b:.1f} PB'


# ═══════════════════════════════════════════════════════════════════════════════
# PCAP / PCAPNG PARSER
# ═══════════════════════════════════════════════════════════════════════════════

class PcapParser:
    """Pure-Python PCAP and PCAPNG file parser."""

    @staticmethod
    def parse(filepath: str) -> Dict[str, Any]:
        with open(filepath, 'rb') as f:
            header = f.read(16)
            if len(header) < 4:
                raise ValueError("File is too small to be a valid capture file")
            magic = struct.unpack('<I', header[:4])[0]

            # ── Standard PCAP ─────────────────────────────────────────────
            if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
                f.seek(0)
                return PcapParser._parse_pcap(f, magic)

            # ── PCAPNG ────────────────────────────────────────────────────
            elif magic == PCAPNG_MAGIC:
                f.seek(0)
                return PcapParser._parse_pcapng(f)

            # ── Gzip-compressed capture (.pcap.gz / .pcapng.gz) ───────────
            elif header[:2] == b'\x1f\x8b':
                f.seek(0)
                try:
                    gz = gzip.GzipFile(fileobj=f)
                    inner_magic = struct.unpack('<I', gz.read(4))[0]
                    gz.seek(0)
                    if inner_magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE):
                        return PcapParser._parse_pcap(gz, inner_magic)
                    elif inner_magic == PCAPNG_MAGIC:
                        return PcapParser._parse_pcapng(gz)
                    else:
                        raise ValueError(
                            f"Gzip-compressed file does not contain a valid PCAP/PCAPNG "
                            f"(inner magic: 0x{inner_magic:08x})")
                except (OSError, struct.error) as e:
                    raise ValueError(f"File appears gzip-compressed but cannot be read: {e}")

            # ── Helpful diagnostics for common non-pcap formats ───────────
            else:
                # Detect text-based exports (Wireshark plain-text, NetMon CSV, etc.)
                try:
                    sample = header + f.read(256)
                    text_sample = sample.decode('utf-8', errors='ignore')
                except Exception:
                    text_sample = ""

                hint = ""
                if all(b in (0x0a, 0x0d, 0x20, 0x09) or 0x20 <= b < 0x7f for b in header[:8]):
                    hint = (
                        " The file appears to be a TEXT export (e.g. Wireshark plain-text "
                        "or CSV), not a binary capture. Re-export from Wireshark using "
                        "'File → Save As' with format 'Wireshark/pcapng' or 'Wireshark/pcap'."
                    )
                elif magic == 0x7b0a2020 or header[:1] == b'{':
                    hint = " The file appears to be JSON, not a binary capture."
                elif header[:5] == b'<?xml' or header[:5] == b'<pdml':
                    hint = " The file appears to be XML/PDML, not a binary capture."

                raise ValueError(
                    f"Unknown file format (magic: 0x{magic:08x}).{hint}"
                )

    @staticmethod
    def _parse_pcap(f, magic):
        is_be = magic in (PCAP_MAGIC_BE, PCAP_MAGIC_NS_BE)
        is_ns = magic in (PCAP_MAGIC_NS_LE, PCAP_MAGIC_NS_BE)
        endian = '>' if is_be else '<'

        hdr = f.read(24)
        _, ver_maj, ver_min, tz, sigfigs, snaplen, linktype = struct.unpack(f'{endian}IHHiIII', hdr)

        packets = []
        pkt_idx = 0
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, cap_len, orig_len = struct.unpack(f'{endian}IIII', pkt_hdr)
            if is_ns:
                timestamp = ts_sec + ts_usec / 1e9
            else:
                timestamp = ts_sec + ts_usec / 1e6

            data = f.read(cap_len)
            if len(data) < cap_len:
                break

            packets.append({
                'index': pkt_idx,
                'timestamp': timestamp,
                'cap_len': cap_len,
                'orig_len': orig_len,
                'data': data,
                'linktype': linktype,
            })
            pkt_idx += 1

        return {
            'format': 'pcap',
            'version': f'{ver_maj}.{ver_min}',
            'snaplen': snaplen,
            'linktype': linktype,
            'packets': packets,
            'nanosecond': is_ns,
        }

    @staticmethod
    def _parse_pcapng(f):
        packets = []
        linktype = 1  # default Ethernet
        if_tsresol = 6  # default microsecond

        pkt_idx = 0
        while True:
            block_hdr = f.read(8)
            if len(block_hdr) < 8:
                break
            block_type, block_len = struct.unpack('<II', block_hdr)

            if block_len < 12:
                break

            body = f.read(block_len - 12)
            trail = f.read(4)  # trailing block length

            if block_type == 0x0A0D0D0A:  # Section Header Block
                pass
            elif block_type == 0x00000001:  # Interface Description Block
                if len(body) >= 4:
                    linktype = struct.unpack('<HH', body[:4])[0]
            elif block_type == 0x00000006:  # Enhanced Packet Block
                if len(body) >= 20:
                    iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack('<IIIII', body[:20])
                    timestamp = ((ts_high << 32) | ts_low) / (10 ** if_tsresol)
                    data = body[20:20 + cap_len]
                    packets.append({
                        'index': pkt_idx,
                        'timestamp': timestamp,
                        'cap_len': cap_len,
                        'orig_len': orig_len,
                        'data': data,
                        'linktype': linktype,
                    })
                    pkt_idx += 1
            elif block_type == 0x00000003:  # Simple Packet Block
                if len(body) >= 4:
                    orig_len = struct.unpack('<I', body[:4])[0]
                    data = body[4:]
                    packets.append({
                        'index': pkt_idx,
                        'timestamp': 0,
                        'cap_len': len(data),
                        'orig_len': orig_len,
                        'data': data,
                        'linktype': linktype,
                    })
                    pkt_idx += 1

        return {
            'format': 'pcapng',
            'version': '1.0',
            'snaplen': 0,
            'linktype': linktype,
            'packets': packets,
            'nanosecond': False,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# PROTOCOL DISSECTOR
# ═══════════════════════════════════════════════════════════════════════════════

class ProtocolDissector:
    """Dissects packets into protocol layers."""

    @staticmethod
    def dissect(pkt: Dict) -> Dict:
        """Dissect a raw packet into protocol layers."""
        result = {
            'index': pkt['index'], 'timestamp': pkt['timestamp'],
            'cap_len': pkt['cap_len'], 'orig_len': pkt['orig_len'],
            'layers': [], 'ethernet': None, 'ip': None, 'transport': None,
            'app': None, 'summary': '',
        }

        data = pkt['data']
        linktype = pkt.get('linktype', 1)

        # Layer 2: Ethernet (linktype 1)
        if linktype == 1 and len(data) >= 14:
            eth = ProtocolDissector._parse_ethernet(data)
            result['ethernet'] = eth
            result['layers'].append('Ethernet')
            data = data[14:]

            # Handle VLAN tagging
            if eth['ethertype'] == 0x8100 and len(data) >= 4:
                vlan_id = struct.unpack('!H', data[:2])[0] & 0x0FFF
                eth['vlan_id'] = vlan_id
                eth['ethertype'] = struct.unpack('!H', data[2:4])[0]
                data = data[4:]

            # Layer 3
            if eth['ethertype'] == 0x0800:  # IPv4
                ip = ProtocolDissector._parse_ipv4(data)
                if ip:
                    result['ip'] = ip
                    result['layers'].append('IPv4')
                    ip_hdr_len = ip['ihl'] * 4
                    payload = data[ip_hdr_len:]

                    # Layer 4
                    if ip['protocol'] == 6:  # TCP
                        tcp = ProtocolDissector._parse_tcp(payload)
                        if tcp:
                            result['transport'] = tcp
                            result['layers'].append('TCP')
                            tcp_payload = payload[tcp['data_offset'] * 4:]
                            result['app'] = ProtocolDissector._identify_app(tcp['src_port'], tcp['dst_port'], tcp_payload, 'tcp')

                    elif ip['protocol'] == 17:  # UDP
                        udp = ProtocolDissector._parse_udp(payload)
                        if udp:
                            result['transport'] = udp
                            result['layers'].append('UDP')
                            udp_payload = payload[8:]
                            result['app'] = ProtocolDissector._identify_app(udp['src_port'], udp['dst_port'], udp_payload, 'udp')

                    elif ip['protocol'] == 1:  # ICMP
                        icmp = ProtocolDissector._parse_icmp(payload)
                        if icmp:
                            result['transport'] = icmp
                            result['layers'].append('ICMP')

            elif eth['ethertype'] == 0x0806:  # ARP
                arp = ProtocolDissector._parse_arp(data)
                if arp:
                    result['ip'] = arp
                    result['layers'].append('ARP')

            elif eth['ethertype'] == 0x86DD:  # IPv6
                ip6 = ProtocolDissector._parse_ipv6(data)
                if ip6:
                    result['ip'] = ip6
                    result['layers'].append('IPv6')
                    payload = data[40:]
                    if ip6['next_header'] == 6:
                        tcp = ProtocolDissector._parse_tcp(payload)
                        if tcp:
                            result['transport'] = tcp; result['layers'].append('TCP')
                            tcp_payload = payload[tcp['data_offset'] * 4:]
                            result['app'] = ProtocolDissector._identify_app(tcp['src_port'], tcp['dst_port'], tcp_payload, 'tcp')
                    elif ip6['next_header'] == 17:
                        udp = ProtocolDissector._parse_udp(payload)
                        if udp:
                            result['transport'] = udp; result['layers'].append('UDP')
                            result['app'] = ProtocolDissector._identify_app(udp['src_port'], udp['dst_port'], payload[8:], 'udp')

        # Raw IP (linktype 101)
        elif linktype == 101 and len(data) >= 20:
            version = (data[0] >> 4) & 0xF
            if version == 4:
                ip = ProtocolDissector._parse_ipv4(data)
                if ip:
                    result['ip'] = ip; result['layers'].append('IPv4')
                    payload = data[ip['ihl'] * 4:]
                    if ip['protocol'] == 6:
                        tcp = ProtocolDissector._parse_tcp(payload)
                        if tcp:
                            result['transport'] = tcp; result['layers'].append('TCP')
                            result['app'] = ProtocolDissector._identify_app(tcp['src_port'], tcp['dst_port'], payload[tcp['data_offset']*4:], 'tcp')
                    elif ip['protocol'] == 17:
                        udp = ProtocolDissector._parse_udp(payload)
                        if udp:
                            result['transport'] = udp; result['layers'].append('UDP')
                            result['app'] = ProtocolDissector._identify_app(udp['src_port'], udp['dst_port'], payload[8:], 'udp')

        # Build summary
        result['summary'] = ProtocolDissector._build_summary(result)
        return result

    @staticmethod
    def _parse_ethernet(data):
        dst = data[:6]; src = data[6:12]
        ethertype = struct.unpack('!H', data[12:14])[0]
        return {
            'dst_mac': ':'.join(f'{b:02x}' for b in dst),
            'src_mac': ':'.join(f'{b:02x}' for b in src),
            'ethertype': ethertype,
            'ethertype_name': ETHERTYPES.get(ethertype, f'0x{ethertype:04x}'),
            'type': 'ethernet',
        }

    @staticmethod
    def _parse_ipv4(data):
        if len(data) < 20: return None
        b0 = data[0]
        version = (b0 >> 4) & 0xF
        ihl = b0 & 0xF
        if version != 4 or ihl < 5: return None
        tos, total_len, ident, flags_frag, ttl, proto, checksum = struct.unpack('!xBHHHBBH', data[0:12])
        # Re-parse properly
        ihl = data[0] & 0xF
        tos = data[1]
        total_len = struct.unpack('!H', data[2:4])[0]
        ident = struct.unpack('!H', data[4:6])[0]
        flags_frag = struct.unpack('!H', data[6:8])[0]
        ttl = data[8]
        proto = data[9]
        checksum = struct.unpack('!H', data[10:12])[0]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        flags = (flags_frag >> 13) & 0x7
        frag_offset = flags_frag & 0x1FFF

        return {
            'type': 'ipv4', 'version': 4, 'ihl': ihl, 'tos': tos,
            'total_length': total_len, 'identification': ident,
            'flags': flags, 'fragment_offset': frag_offset,
            'ttl': ttl, 'protocol': proto,
            'protocol_name': IP_PROTOCOLS.get(proto, f'Proto-{proto}'),
            'checksum': checksum, 'src_ip': src_ip, 'dst_ip': dst_ip,
            'df': bool(flags & 0x2), 'mf': bool(flags & 0x1),
        }

    @staticmethod
    def _parse_ipv6(data):
        if len(data) < 40: return None
        vtcfl = struct.unpack('!I', data[:4])[0]
        version = (vtcfl >> 28) & 0xF
        if version != 6: return None
        payload_len = struct.unpack('!H', data[4:6])[0]
        next_header = data[6]
        hop_limit = data[7]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
        return {
            'type': 'ipv6', 'version': 6, 'payload_length': payload_len,
            'next_header': next_header, 'hop_limit': hop_limit,
            'protocol': next_header,
            'protocol_name': IP_PROTOCOLS.get(next_header, f'Proto-{next_header}'),
            'src_ip': src_ip, 'dst_ip': dst_ip, 'ttl': hop_limit,
        }

    @staticmethod
    def _parse_tcp(data):
        if len(data) < 20: return None
        src_port, dst_port, seq, ack, offset_flags = struct.unpack('!HHIIH', data[:14])
        data_offset = (offset_flags >> 12) & 0xF
        flags = offset_flags & 0x3F
        window = struct.unpack('!H', data[14:16])[0]
        checksum = struct.unpack('!H', data[16:18])[0]
        urgent = struct.unpack('!H', data[18:20])[0]

        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')

        return {
            'type': 'tcp', 'src_port': src_port, 'dst_port': dst_port,
            'seq': seq, 'ack': ack, 'data_offset': data_offset,
            'flags': flags, 'flag_names': flag_names, 'flags_str': ','.join(flag_names),
            'window': window, 'checksum': checksum, 'urgent': urgent,
            'payload_len': max(0, len(data) - data_offset * 4),
            'src_port_name': WELL_KNOWN_PORTS.get(src_port, ''),
            'dst_port_name': WELL_KNOWN_PORTS.get(dst_port, ''),
        }

    @staticmethod
    def _parse_udp(data):
        if len(data) < 8: return None
        src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])
        return {
            'type': 'udp', 'src_port': src_port, 'dst_port': dst_port,
            'length': length, 'checksum': checksum,
            'payload_len': max(0, length - 8),
            'src_port_name': WELL_KNOWN_PORTS.get(src_port, ''),
            'dst_port_name': WELL_KNOWN_PORTS.get(dst_port, ''),
        }

    @staticmethod
    def _parse_icmp(data):
        if len(data) < 8: return None
        icmp_type, code, checksum, rest = struct.unpack('!BBHI', data[:8])
        type_names = {0: 'Echo Reply', 3: 'Dest Unreachable', 5: 'Redirect',
                      8: 'Echo Request', 11: 'Time Exceeded', 13: 'Timestamp', 14: 'Timestamp Reply'}
        return {
            'type': 'icmp', 'icmp_type': icmp_type, 'code': code,
            'checksum': checksum, 'type_name': type_names.get(icmp_type, f'Type-{icmp_type}'),
            'payload_len': len(data) - 8,
        }

    @staticmethod
    def _parse_arp(data):
        if len(data) < 28: return None
        hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack('!HHBBH', data[:8])
        sender_mac = ':'.join(f'{b:02x}' for b in data[8:14])
        sender_ip = socket.inet_ntoa(data[14:18])
        target_mac = ':'.join(f'{b:02x}' for b in data[18:24])
        target_ip = socket.inet_ntoa(data[24:28])
        op_names = {1: 'Request', 2: 'Reply'}
        return {
            'type': 'arp', 'opcode': opcode, 'opcode_name': op_names.get(opcode, f'Op-{opcode}'),
            'sender_mac': sender_mac, 'sender_ip': sender_ip,
            'target_mac': target_mac, 'target_ip': target_ip,
            'src_ip': sender_ip, 'dst_ip': target_ip,
        }

    @staticmethod
    def _identify_app(src_port, dst_port, payload, transport):
        """Identify application-layer protocol from ports and payload."""
        app = {'protocol': 'unknown', 'details': {}}
        ports = {src_port, dst_port}
        min_port = min(src_port, dst_port)

        # DNS
        if 53 in ports and transport == 'udp' and len(payload) >= 12:
            dns = ProtocolDissector._parse_dns(payload)
            if dns: return dns

        # HTTP
        if payload and len(payload) > 4:
            first_word = payload.split(b' ', 1)[0] if b' ' in payload[:12] else b''
            if first_word in HTTP_METHODS:
                return ProtocolDissector._parse_http_request(payload)
            if payload[:5] == b'HTTP/':
                return ProtocolDissector._parse_http_response(payload)

        # TLS
        if len(payload) >= 5 and payload[0] == 0x16:
            tls = ProtocolDissector._parse_tls(payload)
            if tls: return tls

        # Port-based identification
        if 443 in ports or 8443 in ports:
            app['protocol'] = 'TLS/HTTPS'
        elif 80 in ports or 8080 in ports:
            app['protocol'] = 'HTTP'
        elif 22 in ports:
            app['protocol'] = 'SSH'
        elif 21 in ports:
            app['protocol'] = 'FTP'
        elif 25 in ports or 587 in ports or 465 in ports:
            app['protocol'] = 'SMTP'
        elif 53 in ports:
            app['protocol'] = 'DNS'
        elif 3389 in ports:
            app['protocol'] = 'RDP'
        elif 445 in ports or 139 in ports:
            app['protocol'] = 'SMB'
        elif min_port in WELL_KNOWN_PORTS:
            app['protocol'] = WELL_KNOWN_PORTS[min_port]

        return app

    @staticmethod
    def _parse_dns(data):
        if len(data) < 12: return None
        try:
            txn_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
            qr = (flags >> 15) & 1
            opcode = (flags >> 11) & 0xF
            rcode = flags & 0xF

            queries = []
            offset = 12
            for _ in range(min(qdcount, 10)):
                name, offset = ProtocolDissector._parse_dns_name(data, offset)
                if offset + 4 <= len(data):
                    qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
                    offset += 4
                    queries.append({
                        'name': name,
                        'type': DNS_TYPES.get(qtype, f'TYPE-{qtype}'),
                        'type_num': qtype,
                        'class': qclass,
                    })

            answers = []
            for _ in range(min(ancount, 20)):
                if offset >= len(data): break
                name, offset = ProtocolDissector._parse_dns_name(data, offset)
                if offset + 10 > len(data): break
                rtype, rclass, ttl, rdlen = struct.unpack('!HHIH', data[offset:offset + 10])
                offset += 10
                rdata = data[offset:offset + rdlen]
                offset += rdlen

                answer = {'name': name, 'type': DNS_TYPES.get(rtype, f'TYPE-{rtype}'),
                          'type_num': rtype, 'ttl': ttl, 'data': ''}
                if rtype == 1 and len(rdata) == 4:
                    answer['data'] = socket.inet_ntoa(rdata)
                elif rtype == 28 and len(rdata) == 16:
                    answer['data'] = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype == 5:
                    answer['data'], _ = ProtocolDissector._parse_dns_name(data, offset - rdlen)
                elif rtype == 16:
                    answer['data'] = rdata[1:].decode('utf-8', errors='replace') if rdata else ''
                answers.append(answer)

            return {
                'protocol': 'DNS',
                'details': {
                    'transaction_id': txn_id,
                    'is_response': bool(qr),
                    'opcode': opcode,
                    'rcode': rcode,
                    'queries': queries,
                    'answers': answers,
                    'query_count': qdcount,
                    'answer_count': ancount,
                },
            }
        except:
            return None

    @staticmethod
    def _parse_dns_name(data, offset):
        labels = []
        seen = set()
        while offset < len(data):
            if offset in seen: break
            seen.add(offset)
            length = data[offset]
            if length == 0:
                offset += 1; break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data): break
                ptr = struct.unpack('!H', data[offset:offset + 2])[0] & 0x3FFF
                name_part, _ = ProtocolDissector._parse_dns_name(data, ptr)
                labels.append(name_part)
                offset += 2; break
            else:
                offset += 1
                if offset + length > len(data): break
                labels.append(data[offset:offset + length].decode('utf-8', errors='replace'))
                offset += length
        return '.'.join(labels), offset

    @staticmethod
    def _parse_http_request(data):
        try:
            lines = data.split(b'\r\n')
            request_line = lines[0].decode('utf-8', errors='replace')
            parts = request_line.split(' ', 2)
            headers = {}
            for line in lines[1:]:
                if not line or line == b'': break
                decoded = line.decode('utf-8', errors='replace')
                if ':' in decoded:
                    k, _, v = decoded.partition(':')
                    headers[k.strip().lower()] = v.strip()

            return {
                'protocol': 'HTTP',
                'details': {
                    'method': parts[0] if parts else '',
                    'uri': parts[1] if len(parts) > 1 else '',
                    'version': parts[2] if len(parts) > 2 else '',
                    'host': headers.get('host', ''),
                    'user_agent': headers.get('user-agent', ''),
                    'content_type': headers.get('content-type', ''),
                    'content_length': headers.get('content-length', ''),
                    'referer': headers.get('referer', ''),
                    'cookie': '[present]' if 'cookie' in headers else '',
                    'authorization': '[present]' if 'authorization' in headers else '',
                    'headers': headers,
                    'is_request': True,
                },
            }
        except:
            return {'protocol': 'HTTP', 'details': {'is_request': True}}

    @staticmethod
    def _parse_http_response(data):
        try:
            lines = data.split(b'\r\n')
            status_line = lines[0].decode('utf-8', errors='replace')
            parts = status_line.split(' ', 2)
            headers = {}
            for line in lines[1:]:
                if not line: break
                decoded = line.decode('utf-8', errors='replace')
                if ':' in decoded:
                    k, _, v = decoded.partition(':')
                    headers[k.strip().lower()] = v.strip()
            return {
                'protocol': 'HTTP',
                'details': {
                    'version': parts[0] if parts else '',
                    'status_code': parts[1] if len(parts) > 1 else '',
                    'reason': parts[2] if len(parts) > 2 else '',
                    'server': headers.get('server', ''),
                    'content_type': headers.get('content-type', ''),
                    'headers': headers,
                    'is_request': False,
                },
            }
        except:
            return {'protocol': 'HTTP', 'details': {'is_request': False}}

    @staticmethod
    def _parse_tls(data):
        try:
            if len(data) < 5: return None
            content_type = data[0]
            if content_type != 0x16: return None  # Handshake
            version = struct.unpack('!H', data[1:3])[0]
            length = struct.unpack('!H', data[3:5])[0]

            result = {
                'protocol': 'TLS',
                'details': {
                    'record_version': TLS_VERSIONS.get(version, f'0x{version:04x}'),
                    'version': TLS_VERSIONS.get(version, f'0x{version:04x}'),
                    'version_num': version,
                    'content_type': 'Handshake',
                    'deprecated': version in DEPRECATED_TLS,
                    'sni': '',
                    'cipher_suites': [],
                },
            }

            if len(data) < 6: return result
            hs_type = data[5]

            # Client Hello
            if hs_type == 1 and len(data) > 43:
                # Read actual ClientHello version (bytes 9-10: after record hdr + hs type + length)
                if len(data) >= 11:
                    ch_version = struct.unpack('!H', data[9:11])[0]
                    result['details']['version'] = TLS_VERSIONS.get(ch_version, f'0x{ch_version:04x}')
                    result['details']['version_num'] = ch_version
                    result['details']['deprecated'] = ch_version in DEPRECATED_TLS

                # Skip to session ID
                off = 43
                if off < len(data):
                    sess_len = data[off]; off += 1 + sess_len
                if off + 2 <= len(data):
                    cs_len = struct.unpack('!H', data[off:off + 2])[0]; off += 2
                    cs_data = data[off:off + cs_len]
                    suites = []
                    for i in range(0, len(cs_data) - 1, 2):
                        suites.append(struct.unpack('!H', cs_data[i:i + 2])[0])
                    result['details']['cipher_suites'] = suites[:20]
                    off += cs_len

                # Skip compression
                if off < len(data):
                    comp_len = data[off]; off += 1 + comp_len

                # Extensions
                if off + 2 <= len(data):
                    ext_len = struct.unpack('!H', data[off:off + 2])[0]; off += 2
                    ext_end = off + ext_len
                    while off + 4 <= ext_end and off + 4 <= len(data):
                        ext_type = struct.unpack('!H', data[off:off + 2])[0]
                        ext_data_len = struct.unpack('!H', data[off + 2:off + 4])[0]
                        off += 4
                        if ext_type == 0 and ext_data_len > 5:  # SNI
                            sni_data = data[off:off + ext_data_len]
                            if len(sni_data) > 5:
                                name_len = struct.unpack('!H', sni_data[3:5])[0]
                                if len(sni_data) >= 5 + name_len:
                                    result['details']['sni'] = sni_data[5:5 + name_len].decode('utf-8', errors='replace')
                        off += ext_data_len

                result['details']['handshake'] = 'ClientHello'

            elif hs_type == 2:
                result['details']['handshake'] = 'ServerHello'

            return result
        except:
            return None

    @staticmethod
    def _build_summary(result):
        parts = []
        ip = result.get('ip')
        tr = result.get('transport')
        app = result.get('app')

        if ip:
            if ip.get('type') == 'arp':
                return f"ARP {ip.get('opcode_name','')} {ip.get('sender_ip','')} -> {ip.get('target_ip','')}"
            src = ip.get('src_ip', '?')
            dst = ip.get('dst_ip', '?')
            proto = ip.get('protocol_name', '')

            if tr:
                if tr.get('type') in ('tcp', 'udp'):
                    sp = tr.get('src_port', 0)
                    dp = tr.get('dst_port', 0)
                    flags = f" [{tr.get('flags_str', '')}]" if tr.get('type') == 'tcp' else ''
                    app_name = app.get('protocol', '') if app else ''
                    return f"{src}:{sp} -> {dst}:{dp} {proto}{flags} {app_name}".strip()
                elif tr.get('type') == 'icmp':
                    return f"{src} -> {dst} ICMP {tr.get('type_name', '')}"

            return f"{src} -> {dst} {proto}"

        return f"{'->'.join(result.get('layers', ['Unknown']))}"


# ═══════════════════════════════════════════════════════════════════════════════
# TRAFFIC ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

class TrafficAnalyzer:
    """Analyzes dissected packets for flows, statistics, and anomalies."""

    def __init__(self):
        self.flows = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'start': float('inf'),
                                            'end': 0, 'flags_seen': set(), 'payload_bytes': 0})
        self.dns_queries = []
        self.dns_answers = []
        self.http_requests = []
        self.tls_handshakes = []
        self.arp_table = defaultdict(set)
        self.ip_counter = Counter()
        self.port_counter = Counter()
        self.protocol_counter = Counter()
        self.src_dst_pairs = Counter()
        self.packets_per_second = Counter()
        self.total_bytes = 0
        self.total_packets = 0
        self.unique_ips = set()
        self.unique_macs = set()
        self.external_ips = set()
        self.internal_ips = set()
        self.timestamps = []
        self.ttl_values = Counter()
        self.user_agents = Counter()
        self.anomalies = []
        self.iocs = []

    def process(self, dissected_packets: List[Dict]) -> Dict:
        """Process all dissected packets and produce analysis."""
        for pkt in dissected_packets:
            self._process_packet(pkt)

        # Post-processing anomaly detection
        self._detect_port_scan()
        self._detect_beaconing()
        self._detect_dns_tunneling()
        self._detect_arp_spoofing()
        self._detect_data_exfil()
        self._detect_suspicious_ports()
        self._detect_cleartext()
        self._detect_tls_issues()

        return self._compile_results()

    def _process_packet(self, pkt):
        self.total_packets += 1
        self.total_bytes += pkt.get('cap_len', 0)
        ts = pkt.get('timestamp', 0)
        if ts > 0:
            self.timestamps.append(ts)
            self.packets_per_second[int(ts)] += 1

        ip = pkt.get('ip')
        tr = pkt.get('transport')
        app = pkt.get('app')
        eth = pkt.get('ethernet')

        if eth:
            self.unique_macs.add(eth.get('src_mac', ''))
            self.unique_macs.add(eth.get('dst_mac', ''))

        if ip:
            if ip.get('type') == 'arp':
                self.protocol_counter['ARP'] += 1
                self.arp_table[ip.get('sender_ip', '')].add(ip.get('sender_mac', ''))
                return

            src_ip = ip.get('src_ip', '')
            dst_ip = ip.get('dst_ip', '')
            self.ip_counter[src_ip] += 1
            self.ip_counter[dst_ip] += 1
            self.unique_ips.add(src_ip)
            self.unique_ips.add(dst_ip)
            self.src_dst_pairs[(src_ip, dst_ip)] += 1

            for addr in [src_ip, dst_ip]:
                if _is_private(addr):
                    self.internal_ips.add(addr)
                else:
                    self.external_ips.add(addr)

            if ip.get('ttl'):
                self.ttl_values[ip['ttl']] += 1

            proto_name = ip.get('protocol_name', 'Other')
            self.protocol_counter[proto_name] += 1

        if tr:
            if tr.get('type') in ('tcp', 'udp'):
                sp = tr.get('src_port', 0)
                dp = tr.get('dst_port', 0)
                self.port_counter[sp] += 1
                self.port_counter[dp] += 1

                # Flow tracking
                flow_key = self._flow_key(ip, tr)
                flow = self.flows[flow_key]
                flow['packets'] += 1
                flow['bytes'] += pkt.get('cap_len', 0)
                flow['payload_bytes'] += tr.get('payload_len', 0)
                if ts > 0:
                    flow['start'] = min(flow['start'], ts)
                    flow['end'] = max(flow['end'], ts)
                if tr.get('type') == 'tcp':
                    flow['flags_seen'].update(tr.get('flag_names', []))

        if app:
            proto = app.get('protocol', '')
            details = app.get('details', {})

            if proto == 'DNS':
                for q in details.get('queries', []):
                    self.dns_queries.append({
                        'name': q['name'], 'type': q['type'],
                        'timestamp': ts, 'src_ip': ip.get('src_ip', '') if ip else '',
                    })
                for a in details.get('answers', []):
                    self.dns_answers.append(a)

            elif proto == 'HTTP':
                if details.get('is_request'):
                    req = {
                        'method': details.get('method', ''),
                        'uri': details.get('uri', ''),
                        'host': details.get('host', ''),
                        'user_agent': details.get('user_agent', ''),
                        'timestamp': ts,
                        'src_ip': ip.get('src_ip', '') if ip else '',
                        'dst_ip': ip.get('dst_ip', '') if ip else '',
                    }
                    self.http_requests.append(req)
                    if details.get('user_agent'):
                        self.user_agents[details['user_agent']] += 1

            elif proto == 'TLS':
                self.tls_handshakes.append({
                    'sni': details.get('sni', ''),
                    'version': details.get('version', ''),
                    'version_num': details.get('version_num', 0),
                    'deprecated': details.get('deprecated', False),
                    'handshake': details.get('handshake', ''),
                    'timestamp': ts,
                    'src_ip': ip.get('src_ip', '') if ip else '',
                    'dst_ip': ip.get('dst_ip', '') if ip else '',
                })

    def _flow_key(self, ip, tr):
        if not ip or not tr: return ('unknown', 'unknown', 0, 0, '')
        src = ip.get('src_ip', ''); dst = ip.get('dst_ip', '')
        sp = tr.get('src_port', 0); dp = tr.get('dst_port', 0)
        proto = tr.get('type', '')
        if (src, sp) > (dst, dp):
            return (dst, src, dp, sp, proto)
        return (src, dst, sp, dp, proto)

    def _detect_port_scan(self):
        """Detect potential port scans."""
        src_dst_ports = defaultdict(set)
        for (src, dst), count in self.src_dst_pairs.items():
            for flow_key, flow in self.flows.items():
                if len(flow_key) == 5:
                    if flow_key[0] == src or flow_key[1] == src:
                        src_dst_ports[src].add(flow_key[2])
                        src_dst_ports[src].add(flow_key[3])

        for src, ports in src_dst_ports.items():
            if len(ports) > 20:
                self.anomalies.append({
                    'severity': 'high', 'category': 'reconnaissance',
                    'description': f'Possible port scan from {src} — {len(ports)} unique ports contacted',
                    'source': src,
                })
                self.iocs.append({'type': 'scanner_ip', 'value': src})

    def _detect_beaconing(self):
        """Detect periodic communication patterns (C2 beaconing)."""
        for (src, dst), count in self.src_dst_pairs.items():
            if count < 5: continue
            # Get timestamps for this pair
            pair_times = []
            for flow_key, flow in self.flows.items():
                if len(flow_key) == 5:
                    if (flow_key[0] == src and flow_key[1] == dst) or (flow_key[0] == dst and flow_key[1] == src):
                        if flow['start'] < float('inf'):
                            pair_times.append(flow['start'])

            if len(pair_times) < 4: continue
            pair_times.sort()
            intervals = [pair_times[i+1] - pair_times[i] for i in range(len(pair_times)-1)]
            if not intervals: continue
            mean_int = sum(intervals) / len(intervals)
            if mean_int < 1: continue
            variance = sum((i - mean_int)**2 for i in intervals) / len(intervals)
            std_dev = math.sqrt(variance) if variance > 0 else 0
            cv = std_dev / mean_int if mean_int > 0 else float('inf')

            if cv < 0.15 and mean_int > 5:
                self.anomalies.append({
                    'severity': 'critical', 'category': 'c2',
                    'description': f'Beaconing detected: {src} -> {dst} every ~{mean_int:.0f}s (CV={cv:.3f}, {count} connections)',
                    'source': src, 'destination': dst,
                })
                self.iocs.append({'type': 'c2_candidate', 'value': f'{src} -> {dst}'})

    def _detect_dns_tunneling(self):
        """Detect potential DNS tunneling."""
        domain_lengths = defaultdict(list)
        for q in self.dns_queries:
            name = q.get('name', '')
            parts = name.split('.')
            if len(parts) > 2:
                subdomain = '.'.join(parts[:-2])
                base_domain = '.'.join(parts[-2:])
                domain_lengths[base_domain].append(len(subdomain))

        for domain, lengths in domain_lengths.items():
            if len(lengths) < 5: continue
            avg_len = sum(lengths) / len(lengths)
            if avg_len > 30 and len(lengths) > 10:
                self.anomalies.append({
                    'severity': 'critical', 'category': 'exfiltration',
                    'description': f'DNS tunneling suspected: {domain} — {len(lengths)} queries, avg subdomain length {avg_len:.0f} chars',
                    'domain': domain,
                })
                self.iocs.append({'type': 'dns_tunnel_domain', 'value': domain})

        # High volume to single domain
        domain_counts = Counter(q.get('name', '').split('.')[-2] + '.' + q.get('name', '').split('.')[-1]
                                 for q in self.dns_queries if len(q.get('name', '').split('.')) >= 2)
        for domain, count in domain_counts.most_common(5):
            if count > 50:
                self.anomalies.append({
                    'severity': 'medium', 'category': 'dns',
                    'description': f'High DNS query volume to {domain}: {count} queries',
                })

    def _detect_arp_spoofing(self):
        """Detect ARP spoofing / cache poisoning."""
        for ip_addr, macs in self.arp_table.items():
            macs_clean = {m for m in macs if m != '00:00:00:00:00:00'}
            if len(macs_clean) > 1:
                self.anomalies.append({
                    'severity': 'critical', 'category': 'mitm',
                    'description': f'ARP spoofing detected: IP {ip_addr} has {len(macs_clean)} different MAC addresses: {", ".join(macs_clean)}',
                    'ip': ip_addr,
                })
                self.iocs.append({'type': 'arp_spoof_ip', 'value': ip_addr})

    def _detect_data_exfil(self):
        """Detect potential data exfiltration."""
        for flow_key, flow in self.flows.items():
            if len(flow_key) != 5: continue
            if flow['payload_bytes'] > 10 * 1024 * 1024:  # > 10MB
                src, dst = flow_key[0], flow_key[1]
                if not _is_private(dst):
                    self.anomalies.append({
                        'severity': 'high', 'category': 'exfiltration',
                        'description': f'Large outbound transfer: {src} -> {dst} ({_human_bytes(flow["payload_bytes"])})',
                        'source': src, 'destination': dst,
                    })
            duration = flow['end'] - flow['start']
            if duration > 0 and flow['payload_bytes'] > 0:
                rate = flow['payload_bytes'] / duration
                if rate > 5 * 1024 * 1024:  # > 5 MB/s sustained
                    src, dst = flow_key[0], flow_key[1]
                    if not _is_private(dst):
                        self.anomalies.append({
                            'severity': 'medium', 'category': 'exfiltration',
                            'description': f'High-rate transfer: {src} -> {dst} at {_human_bytes(rate)}/s',
                        })

    def _detect_suspicious_ports(self):
        """Flag traffic on known suspicious/malware ports."""
        for flow_key, flow in self.flows.items():
            if len(flow_key) != 5: continue
            for port in [flow_key[2], flow_key[3]]:
                if port in SUSPICIOUS_PORTS:
                    desc = SUSPICIOUS_PORTS[port]
                    self.anomalies.append({
                        'severity': 'high', 'category': 'suspicious_port',
                        'description': f'Traffic on suspicious port {port} ({desc}): {flow_key[0]} <-> {flow_key[1]}',
                    })
                    self.iocs.append({'type': 'suspicious_port', 'value': f'{port} ({desc})'})

    def _detect_cleartext(self):
        """Flag cleartext protocols carrying sensitive data."""
        cleartext_protos = {'FTP', 'Telnet', 'HTTP', 'POP3', 'IMAP'}
        for req in self.http_requests:
            if req.get('method') == 'POST':
                self.anomalies.append({
                    'severity': 'medium', 'category': 'cleartext',
                    'description': f'HTTP POST (cleartext) to {req.get("host", "unknown")}{req.get("uri", "")} from {req.get("src_ip", "")}',
                })

        # Check for FTP/Telnet usage
        ftp_flows = sum(1 for k in self.flows if len(k) == 5 and (k[2] in (20, 21) or k[3] in (20, 21)))
        telnet_flows = sum(1 for k in self.flows if len(k) == 5 and (k[2] == 23 or k[3] == 23))
        if ftp_flows:
            self.anomalies.append({'severity': 'high', 'category': 'cleartext',
                                   'description': f'FTP traffic detected ({ftp_flows} flows) — credentials transmitted in cleartext'})
        if telnet_flows:
            self.anomalies.append({'severity': 'high', 'category': 'cleartext',
                                   'description': f'Telnet traffic detected ({telnet_flows} flows) — all data in cleartext'})

    def _detect_tls_issues(self):
        """Flag deprecated TLS versions."""
        for hs in self.tls_handshakes:
            if hs.get('deprecated'):
                self.anomalies.append({
                    'severity': 'high', 'category': 'encryption',
                    'description': f'Deprecated {hs["version"]} in use: {hs.get("src_ip","")} -> {hs.get("dst_ip","")} (SNI: {hs.get("sni","N/A")})',
                })

    def _compile_results(self):
        """Compile all analysis into final results dict."""
        duration = (max(self.timestamps) - min(self.timestamps)) if len(self.timestamps) >= 2 else 0
        pps = self.total_packets / duration if duration > 0 else 0
        bps = self.total_bytes / duration if duration > 0 else 0

        # Top talkers
        top_src = Counter()
        top_dst = Counter()
        for (src, dst), count in self.src_dst_pairs.items():
            top_src[src] += count
            top_dst[dst] += count

        # Top flows by bytes
        top_flows = sorted(self.flows.items(), key=lambda x: x[1]['bytes'], reverse=True)[:20]

        # Threat scoring
        score = 0
        for a in self.anomalies:
            if a['severity'] == 'critical': score += 25
            elif a['severity'] == 'high': score += 15
            elif a['severity'] == 'medium': score += 8
            elif a['severity'] == 'low': score += 3
        score = min(score, 100)

        if score >= 50: risk_level = 'CRITICAL'
        elif score >= 30: risk_level = 'HIGH'
        elif score >= 15: risk_level = 'MEDIUM'
        elif score > 0: risk_level = 'LOW'
        else: risk_level = 'CLEAN'

        # Extract IOCs
        for ip in self.external_ips:
            self.iocs.append({'type': 'external_ip', 'value': ip})
        for q in self.dns_queries:
            name = q.get('name', '')
            if name and not name.endswith('.local') and not name.endswith('.arpa'):
                self.iocs.append({'type': 'domain', 'value': name})
        for req in self.http_requests:
            host = req.get('host', '')
            uri = req.get('uri', '')
            if host: self.iocs.append({'type': 'url', 'value': f'http://{host}{uri}'})
        for hs in self.tls_handshakes:
            if hs.get('sni'): self.iocs.append({'type': 'tls_sni', 'value': hs['sni']})

        # Deduplicate IOCs
        seen = set()
        unique_iocs = []
        for ioc in self.iocs:
            k = f"{ioc['type']}:{ioc['value']}"
            if k not in seen:
                seen.add(k); unique_iocs.append(ioc)

        # Unique DNS domains
        unique_domains = sorted(set(q.get('name', '') for q in self.dns_queries if q.get('name')))

        return {
            'summary': {
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'total_bytes_human': _human_bytes(self.total_bytes),
                'duration_seconds': round(duration, 2),
                'duration_human': str(timedelta(seconds=int(duration))) if duration else '0:00:00',
                'packets_per_second': round(pps, 1),
                'bytes_per_second': round(bps, 1),
                'bandwidth_human': f'{_human_bytes(bps)}/s',
                'unique_ips': len(self.unique_ips),
                'unique_macs': len(self.unique_macs),
                'external_ips': len(self.external_ips),
                'internal_ips': len(self.internal_ips),
                'total_flows': len(self.flows),
                'first_timestamp': min(self.timestamps) if self.timestamps else 0,
                'last_timestamp': max(self.timestamps) if self.timestamps else 0,
            },
            'protocols': dict(self.protocol_counter.most_common()),
            'top_talkers_src': dict(top_src.most_common(15)),
            'top_talkers_dst': dict(top_dst.most_common(15)),
            'top_ports': dict(self.port_counter.most_common(20)),
            'top_flows': [{
                'key': f'{k[0]}:{k[2]} <-> {k[1]}:{k[3]} ({k[4]})' if len(k) == 5 else str(k),
                'packets': v['packets'], 'bytes': v['bytes'],
                'bytes_human': _human_bytes(v['bytes']),
                'duration': round(v['end'] - v['start'], 2) if v['end'] > v['start'] else 0,
            } for k, v in top_flows],
            'dns': {
                'total_queries': len(self.dns_queries),
                'unique_domains': len(unique_domains),
                'top_domains': dict(Counter(q.get('name','') for q in self.dns_queries).most_common(20)),
                'query_types': dict(Counter(q.get('type','') for q in self.dns_queries).most_common()),
                'domains': unique_domains[:100],
            },
            'http': {
                'total_requests': len(self.http_requests),
                'methods': dict(Counter(r.get('method','') for r in self.http_requests).most_common()),
                'hosts': dict(Counter(r.get('host','') for r in self.http_requests).most_common(20)),
                'user_agents': dict(self.user_agents.most_common(10)),
                'requests': self.http_requests[:50],
            },
            'tls': {
                'total_handshakes': len(self.tls_handshakes),
                'versions': dict(Counter(h.get('version','') for h in self.tls_handshakes).most_common()),
                'sni_list': sorted(set(h.get('sni','') for h in self.tls_handshakes if h.get('sni'))),
                'deprecated_count': sum(1 for h in self.tls_handshakes if h.get('deprecated')),
            },
            'anomalies': self.anomalies,
            'threat_score': score,
            'risk_level': risk_level,
            'iocs': unique_iocs,
            'ttl_distribution': dict(self.ttl_values.most_common(10)),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# DEMO PCAP GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class DemoGenerator:
    """Generates a sample PCAP file with various traffic patterns for testing."""

    @staticmethod
    def generate(output_path: str):
        """Generate a realistic demo PCAP file."""
        packets = []
        base_time = int(time.time()) - 300  # 5 minutes ago

        def make_eth(src_mac, dst_mac, ethertype=0x0800):
            return (bytes.fromhex(dst_mac.replace(':','')) +
                    bytes.fromhex(src_mac.replace(':','')) +
                    struct.pack('!H', ethertype))

        def make_ipv4(src, dst, proto, payload_len, ttl=64, ident=0):
            total_len = 20 + payload_len
            header = struct.pack('!BBHHHBBH4s4s',
                0x45, 0, total_len, ident, 0x4000, ttl, proto, 0,
                socket.inet_aton(src), socket.inet_aton(dst))
            return header

        def make_tcp(sp, dp, seq=1000, ack=0, flags=0x02, payload=b''):
            offset = 5
            off_flags = (offset << 12) | flags
            header = struct.pack('!HHIIHHHH', sp, dp, seq, ack, off_flags, 65535, 0, 0)
            return header + payload

        def make_udp(sp, dp, payload=b''):
            length = 8 + len(payload)
            return struct.pack('!HHHH', sp, dp, length, 0) + payload

        def make_dns_query(domain, txn_id=0x1234, qtype=1):
            header = struct.pack('!HHHHHH', txn_id, 0x0100, 1, 0, 0, 0)
            qname = b''
            for label in domain.split('.'):
                qname += struct.pack('B', len(label)) + label.encode()
            qname += b'\x00'
            question = qname + struct.pack('!HH', qtype, 1)
            return header + question

        def add_packet(data, ts_offset):
            packets.append((base_time + ts_offset, data))

        local_mac = 'aa:bb:cc:dd:ee:01'
        gw_mac = 'aa:bb:cc:dd:ee:ff'
        local_ip = '192.168.1.100'
        gw_ip = '192.168.1.1'

        # Normal DNS queries
        for i, domain in enumerate(['google.com', 'github.com', 'example.com', 'api.stripe.com',
                                      'cdn.cloudflare.com', 'fonts.googleapis.com']):
            dns = make_dns_query(domain, txn_id=0x1000 + i)
            udp = make_udp(50000 + i, 53, dns)
            ip = make_ipv4(local_ip, '8.8.8.8', 17, len(udp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip + udp, i * 2)

        # Normal HTTPS (TLS ClientHello with SNI)
        for i, (sni, dst_ip) in enumerate([
            ('www.google.com', '142.250.80.100'), ('github.com', '20.27.177.113'),
            ('api.stripe.com', '104.18.10.39'),
        ]):
            sni_ext = struct.pack('!HH', 0, len(sni) + 5) + struct.pack('!HBH', len(sni) + 3, 0, len(sni)) + sni.encode()
            extensions = sni_ext
            ext_block = struct.pack('!H', len(extensions)) + extensions
            cipher_suites = struct.pack('!H', 4) + struct.pack('!HH', 0x1301, 0x1302)
            session_id = b'\x00'
            client_hello = struct.pack('!HH32s', 0x0303, 0, b'\x00'*32) + session_id + cipher_suites + b'\x01\x00' + ext_block
            hs_header = struct.pack('!B', 1) + struct.pack('!I', len(client_hello))[1:]
            tls_record = struct.pack('!BHH', 0x16, 0x0301, len(hs_header + client_hello)) + hs_header + client_hello
            tcp = make_tcp(50100 + i, 443, flags=0x18, payload=tls_record)
            ip_pkt = make_ipv4(local_ip, dst_ip, 6, len(tcp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip_pkt + tcp, 15 + i * 3)

        # HTTP requests (cleartext)
        for i, (host, uri) in enumerate([
            ('example.com', '/api/data'), ('internal-app.local', '/login'),
            ('tracking.ads.net', '/pixel?uid=12345'),
        ]):
            http_payload = f'GET {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nAccept: */*\r\n\r\n'.encode()
            tcp = make_tcp(50200 + i, 80, flags=0x18, payload=http_payload)
            ip_pkt = make_ipv4(local_ip, '93.184.216.34', 6, len(tcp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip_pkt + tcp, 30 + i * 5)

        # Suspicious: beaconing pattern (every ~60s to same IP)
        c2_ip = '185.220.101.42'
        for i in range(5):
            tcp = make_tcp(49000, 4444, seq=1000 + i * 100, flags=0x18, payload=b'\x00' * 64)
            ip_pkt = make_ipv4(local_ip, c2_ip, 6, len(tcp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip_pkt + tcp, 60 + i * 60)

        # DNS tunneling pattern
        for i in range(15):
            long_sub = hashlib.md5(f'exfil-data-chunk-{i}'.encode()).hexdigest()
            tunnel_domain = f'{long_sub}.tunnel.evil-domain.com'
            dns = make_dns_query(tunnel_domain, txn_id=0x2000 + i, qtype=16)
            udp = make_udp(51000 + i, 53, dns)
            ip_pkt = make_ipv4(local_ip, '8.8.8.8', 17, len(udp))
            eth = make_eth(local_mac, gw_mac)
            add_packet(eth + ip_pkt + udp, 50 + i * 3)

        # ARP requests/replies (normal)
        arp_req = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
        arp_req += bytes.fromhex(local_mac.replace(':','')) + socket.inet_aton(local_ip)
        arp_req += b'\x00' * 6 + socket.inet_aton(gw_ip)
        eth = make_eth(local_mac, 'ff:ff:ff:ff:ff:ff', 0x0806)
        add_packet(eth + arp_req, 1)

        # ARP spoofing attempt (different MAC for same IP)
        spoof_mac = 'de:ad:be:ef:00:01'
        arp_spoof = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2)
        arp_spoof += bytes.fromhex(spoof_mac.replace(':','')) + socket.inet_aton(gw_ip)
        arp_spoof += bytes.fromhex(local_mac.replace(':','')) + socket.inet_aton(local_ip)
        eth = make_eth(spoof_mac, local_mac, 0x0806)
        add_packet(eth + arp_spoof, 100)

        # ICMP ping
        icmp = struct.pack('!BBHI', 8, 0, 0, 0x0001_0001) + b'ABCDEFGH'
        ip_pkt = make_ipv4(local_ip, '8.8.8.8', 1, len(icmp))
        eth = make_eth(local_mac, gw_mac)
        add_packet(eth + ip_pkt + icmp, 5)

        # Deprecated TLS (SSL 3.0)
        old_tls = struct.pack('!BHH', 0x16, 0x0300, 5) + struct.pack('!B', 1) + b'\x00\x00\x01\x00'
        tcp = make_tcp(50300, 443, flags=0x18, payload=old_tls)
        ip_pkt = make_ipv4(local_ip, '10.0.0.50', 6, len(tcp))
        eth = make_eth(local_mac, gw_mac)
        add_packet(eth + ip_pkt + tcp, 200)

        # Write PCAP
        packets.sort(key=lambda x: x[0])
        with open(output_path, 'wb') as f:
            # Global header
            f.write(struct.pack('<IHHiIII', PCAP_MAGIC_LE, 2, 4, 0, 0, 65535, 1))
            for ts, data in packets:
                ts_sec = int(ts)
                ts_usec = int((ts - ts_sec) * 1e6)
                f.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
                f.write(data)

        return output_path


# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    @staticmethod
    def generate(analysis, file_info, output_path):
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        rid = hashlib.sha256(f'{ts}{id(analysis)}'.encode()).hexdigest()[:12].upper()
        s = analysis.get('summary', {})
        risk = analysis.get('risk_level', 'CLEAN')
        score = analysis.get('threat_score', 0)
        sc = '#22c55e' if score<15 else '#f59e0b' if score<30 else '#f97316' if score<50 else '#ef4444'

        css = """<style>
:root{--bg:#0a0e1a;--bg2:#1a2332;--bdr:#2a3a4a;--txt:#e2e8f0;--txt2:#94a3b8;--mut:#64748b;--acc:#3b82f6;--grn:#22c55e;--ylw:#f59e0b;--org:#f97316;--red:#ef4444;--cri:#dc2626;--pur:#a855f7;--cyn:#06b6d4;--mono:'Consolas',monospace;--sans:-apple-system,'Segoe UI',sans-serif}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:var(--sans);background:var(--bg);color:var(--txt);line-height:1.6}.ctr{max-width:1200px;margin:0 auto;padding:2rem}
.hdr{background:linear-gradient(135deg,#0f172a,#1e293b,#0f172a);border:1px solid var(--bdr);border-radius:16px;padding:2.5rem;margin-bottom:2rem;position:relative;overflow:hidden}
.hdr::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--acc),var(--pur),var(--cyn))}
.brand{font-size:.85rem;font-weight:700;letter-spacing:3px;color:var(--acc);text-transform:uppercase}
h1{font-size:1.75rem;font-weight:700;margin:.5rem 0}.sub{color:var(--txt2);font-size:.95rem}.meta{text-align:right;font-size:.85rem;color:var(--mut);font-family:var(--mono)}.meta span{display:block;margin-bottom:.25rem}
.sb{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}.sc{background:var(--bg2);border:1px solid var(--bdr);border-radius:12px;padding:1.25rem;text-align:center}
.sv{font-size:1.8rem;font-weight:700;font-family:var(--mono);color:var(--acc)}.sl{font-size:.75rem;color:var(--mut);text-transform:uppercase;letter-spacing:1px;margin-top:.25rem}
.sec{background:var(--bg2);border:1px solid var(--bdr);border-radius:12px;margin-bottom:1.5rem;overflow:hidden}.sh{padding:1.25rem 1.5rem;border-bottom:1px solid var(--bdr);font-weight:600;font-size:1.1rem}.sbd{padding:1.5rem}
table{width:100%;border-collapse:collapse}th{text-align:left;padding:.65rem 1rem;background:rgba(59,130,246,.05);color:var(--txt2);font-size:.8rem;text-transform:uppercase;border-bottom:1px solid var(--bdr)}
td{padding:.65rem 1rem;border-bottom:1px solid rgba(42,58,74,.5);font-size:.9rem;vertical-align:top}tr:last-child td{border-bottom:none}
.mono{font-family:var(--mono);font-size:.85rem}.sm{display:flex;align-items:center;gap:1rem;padding:1rem}.st{flex:1;height:12px;background:var(--bg);border-radius:6px;overflow:hidden;border:1px solid var(--bdr)}
.sf{height:100%;border-radius:6px}.sn{font-family:var(--mono);font-size:1.5rem;font-weight:700;min-width:60px;text-align:right}
.rb{display:inline-flex;padding:.35rem .85rem;border-radius:20px;font-size:.8rem;font-weight:700;text-transform:uppercase;font-family:var(--mono)}
.r-clean{background:rgba(34,197,94,.1);color:var(--grn);border:1px solid rgba(34,197,94,.3)}.r-low{background:rgba(245,158,11,.1);color:var(--ylw);border:1px solid rgba(245,158,11,.3)}
.r-medium{background:rgba(249,115,22,.1);color:var(--org);border:1px solid rgba(249,115,22,.3)}.r-high{background:rgba(239,68,68,.1);color:var(--red);border:1px solid rgba(239,68,68,.3)}
.r-critical{background:rgba(220,38,38,.15);color:var(--cri);border:1px solid rgba(220,38,38,.3)}
.ti{display:flex;gap:.75rem;padding:.75rem 0;border-bottom:1px solid rgba(42,58,74,.3)}.ti:last-child{border-bottom:none}
.ts{flex-shrink:0;width:70px;text-align:center;padding:.2rem .5rem;border-radius:4px;font-size:.7rem;font-weight:700;text-transform:uppercase;font-family:var(--mono)}
.s-cri{background:rgba(220,38,38,.15);color:var(--cri)}.s-hi{background:rgba(239,68,68,.1);color:var(--red)}.s-me{background:rgba(249,115,22,.1);color:var(--org)}.s-lo{background:rgba(245,158,11,.1);color:var(--ylw)}.s-in{background:rgba(6,182,212,.1);color:var(--cyn)}
.ftr{text-align:center;padding:2rem;color:var(--mut);font-size:.8rem;border-top:1px solid var(--bdr);margin-top:2rem}
.cb{text-align:center;padding:.5rem;font-size:.75rem;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:var(--mut);border-bottom:1px solid var(--bdr)}
</style>"""

        h = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Packet Capture Analysis — {BRAND}</title>{css}</head><body>
<div class="cb">UNCLASSIFIED // FOR OFFICIAL USE ONLY // {BRAND} PROPRIETARY</div><div class="ctr">
<div class="hdr"><div style="display:flex;justify-content:space-between;align-items:flex-start"><div><div class="brand">{BRAND}</div>
<h1>Packet Capture Analysis Report</h1><div class="sub">Deep packet inspection, traffic forensics, and threat detection</div></div>
<div class="meta"><span>Report ID: {rid}</span><span>Generated: {ts}</span><span>Engine: {TOOL_NAME} v{VERSION}</span><span>File: {_esc(file_info.get('filename',''))}</span></div></div></div>

<div class="sb">
<div class="sc"><div class="sv">{s.get('total_packets',0):,}</div><div class="sl">Packets</div></div>
<div class="sc"><div class="sv">{s.get('total_bytes_human','0 B')}</div><div class="sl">Total Data</div></div>
<div class="sc"><div class="sv">{s.get('duration_human','0:00')}</div><div class="sl">Duration</div></div>
<div class="sc"><div class="sv">{s.get('unique_ips',0)}</div><div class="sl">Unique IPs</div></div>
<div class="sc"><div class="sv">{s.get('total_flows',0)}</div><div class="sl">Flows</div></div>
<div class="sc"><div class="sv">{len(analysis.get('anomalies',[]))}</div><div class="sl">Anomalies</div></div>
<div class="sc"><div class="sv" style="color:{sc}">{score}/100</div><div class="sl">Threat Score</div></div>
</div>

<div class="sec"><div class="sh">Threat Score &nbsp;<span class="rb r-{risk.lower()}">{risk}</span></div><div class="sbd">
<div class="sm"><div class="st"><div class="sf" style="width:{score}%;background:{sc}"></div></div><div class="sn" style="color:{sc}">{score}/100</div></div></div></div>"""

        # Anomalies
        anomalies = analysis.get('anomalies', [])
        if anomalies:
            sev_cls = {'critical':'s-cri','high':'s-hi','medium':'s-me','low':'s-lo','info':'s-in'}
            h += f'<div class="sec"><div class="sh">Anomalies &amp; Threats ({len(anomalies)})</div><div class="sbd">'
            for a in anomalies:
                sv = a.get('severity','info')
                h += f'<div class="ti"><div class="ts {sev_cls.get(sv,"s-in")}">{sv}</div><div><div style="font-size:.75rem;color:var(--mut);text-transform:uppercase">{a.get("category","")}</div><div style="font-size:.9rem;margin-top:.15rem">{_esc(a.get("description",""))}</div></div></div>'
            h += '</div></div>'

        # Protocol breakdown
        protos = analysis.get('protocols', {})
        if protos:
            h += '<div class="sec"><div class="sh">Protocol Distribution</div><div class="sbd"><table><thead><tr><th>Protocol</th><th>Packets</th><th>%</th></tr></thead><tbody>'
            for p, c in sorted(protos.items(), key=lambda x: -x[1]):
                pct = (c / max(s.get('total_packets',1),1)) * 100
                h += f'<tr><td class="mono">{_esc(p)}</td><td>{c:,}</td><td>{pct:.1f}%</td></tr>'
            h += '</tbody></table></div></div>'

        # Top talkers
        talkers = analysis.get('top_talkers_src', {})
        if talkers:
            h += '<div class="sec"><div class="sh">Top Talkers (Source)</div><div class="sbd"><table><thead><tr><th>IP Address</th><th>Packets</th><th>Type</th></tr></thead><tbody>'
            for ip, c in list(talkers.items())[:10]:
                t = 'Internal' if _is_private(ip) else '<span style="color:var(--org)">External</span>'
                h += f'<tr><td class="mono">{_esc(ip)}</td><td>{c:,}</td><td>{t}</td></tr>'
            h += '</tbody></table></div></div>'

        # Top flows
        flows = analysis.get('top_flows', [])
        if flows:
            h += '<div class="sec"><div class="sh">Top Flows by Volume</div><div class="sbd"><table><thead><tr><th>Flow</th><th>Packets</th><th>Data</th><th>Duration</th></tr></thead><tbody>'
            for f in flows[:10]:
                h += f'<tr><td class="mono" style="font-size:.8rem">{_esc(f["key"])}</td><td>{f["packets"]:,}</td><td>{f["bytes_human"]}</td><td>{f["duration"]}s</td></tr>'
            h += '</tbody></table></div></div>'

        # DNS
        dns = analysis.get('dns', {})
        if dns.get('total_queries', 0):
            h += f'<div class="sec"><div class="sh">DNS Analysis ({dns["total_queries"]} queries, {dns["unique_domains"]} domains)</div><div class="sbd"><table><thead><tr><th>Domain</th><th>Queries</th></tr></thead><tbody>'
            for d, c in list(dns.get('top_domains', {}).items())[:15]:
                h += f'<tr><td class="mono">{_esc(d)}</td><td>{c}</td></tr>'
            h += '</tbody></table></div></div>'

        # HTTP
        http = analysis.get('http', {})
        if http.get('total_requests', 0):
            h += f'<div class="sec"><div class="sh">HTTP Analysis ({http["total_requests"]} requests)</div><div class="sbd"><table><thead><tr><th>Method</th><th>Host</th><th>URI</th><th>Source</th></tr></thead><tbody>'
            for r in http.get('requests', [])[:15]:
                h += f'<tr><td class="mono">{_esc(r.get("method",""))}</td><td class="mono">{_esc(r.get("host",""))}</td><td style="font-size:.8rem;word-break:break-all">{_esc(r.get("uri","")[:80])}</td><td class="mono">{_esc(r.get("src_ip",""))}</td></tr>'
            h += '</tbody></table></div></div>'

        # TLS
        tls = analysis.get('tls', {})
        if tls.get('total_handshakes', 0):
            h += f'<div class="sec"><div class="sh">TLS Analysis ({tls["total_handshakes"]} handshakes)</div><div class="sbd"><table><thead><tr><th>Version</th><th>Count</th></tr></thead><tbody>'
            for v, c in tls.get('versions', {}).items():
                dep = ' <span style="color:var(--red)">(DEPRECATED)</span>' if 'SSL' in v or v in ('TLS 1.0','TLS 1.1') else ''
                h += f'<tr><td class="mono">{_esc(v)}{dep}</td><td>{c}</td></tr>'
            h += '</tbody></table>'
            snis = tls.get('sni_list', [])
            if snis:
                h += '<p style="margin-top:1rem;color:var(--txt2);font-size:.85rem"><strong>SNI Hostnames:</strong> ' + ', '.join(f'<span class="mono">{_esc(s)}</span>' for s in snis[:20]) + '</p>'
            h += '</div></div>'

        # IOCs
        iocs = analysis.get('iocs', [])
        if iocs:
            h += f'<div class="sec"><div class="sh">IOC Summary ({len(iocs)})</div><div class="sbd"><table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>'
            for ioc in iocs[:50]:
                h += f'<tr><td class="mono">{_esc(ioc["type"])}</td><td class="mono" style="color:var(--cyn);word-break:break-all">{_esc(ioc["value"])}</td></tr>'
            h += '</tbody></table></div></div>'

        h += f'<div class="ftr"><strong>{BRAND}</strong> — {TOOL_NAME} v{VERSION}<br>Report generated {ts} | ID: {rid}<br>&copy; {datetime.now().year} {BRAND} — All Rights Reserved</div></div></body></html>'

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(h)
        return output_path


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN SCANNER ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class PacketCaptureAnalyzer:
    def __init__(self):
        pass

    def analyze_file(self, filepath, log_cb=None):
        def log(m):
            if log_cb: log_cb(m)
            print(m)

        log(f"[*] Analyzing: {os.path.basename(filepath)}")
        file_info = {
            'filename': os.path.basename(filepath),
            'size': os.path.getsize(filepath),
            'size_human': _human_bytes(os.path.getsize(filepath)),
        }
        with open(filepath, 'rb') as f:
            file_info['sha256'] = hashlib.sha256(f.read()).hexdigest()

        log(f"  File: {file_info['size_human']} | SHA-256: {file_info['sha256'][:16]}...")

        # Parse PCAP
        log("  [1/3] Parsing packet capture...")
        pcap_data = PcapParser.parse(filepath)
        raw_packets = pcap_data.get('packets', [])
        log(f"  [+] Format: {pcap_data['format']} | {len(raw_packets)} packets | Linktype: {pcap_data['linktype']}")

        # Dissect packets
        log("  [2/3] Dissecting protocols...")
        dissected = []
        for pkt in raw_packets:
            try:
                d = ProtocolDissector.dissect(pkt)
                dissected.append(d)
            except Exception:
                pass
        log(f"  [+] Dissected {len(dissected)} packets")

        # Analyze
        log("  [3/3] Analyzing traffic patterns & detecting anomalies...")
        analyzer = TrafficAnalyzer()
        results = analyzer.process(dissected)
        results['file_info'] = file_info
        results['pcap_info'] = {k: v for k, v in pcap_data.items() if k != 'packets'}

        s = results.get('summary', {})
        log(f"\n  RESULTS:")
        log(f"    Packets:    {s.get('total_packets',0):,}")
        log(f"    Data:       {s.get('total_bytes_human','0 B')}")
        log(f"    Duration:   {s.get('duration_human','0:00')}")
        log(f"    Unique IPs: {s.get('unique_ips',0)} ({s.get('external_ips',0)} external)")
        log(f"    Flows:      {s.get('total_flows',0)}")
        log(f"    DNS:        {results.get('dns',{}).get('total_queries',0)} queries")
        log(f"    HTTP:       {results.get('http',{}).get('total_requests',0)} requests")
        log(f"    TLS:        {results.get('tls',{}).get('total_handshakes',0)} handshakes")
        log(f"    Anomalies:  {len(results.get('anomalies',[]))}")
        log(f"    Risk:       {results.get('risk_level','CLEAN')} ({results.get('threat_score',0)}/100)")
        log(f"    IOCs:       {len(results.get('iocs',[]))}")

        for a in results.get('anomalies', [])[:10]:
            log(f"    [{a['severity'].upper():8s}] {a['description']}")

        log("")
        return results


# ═══════════════════════════════════════════════════════════════════════════════
# TKINTER GUI
# ═══════════════════════════════════════════════════════════════════════════════

def launch_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    from PIL import ImageTk

    class App:
        def __init__(self, root):
            self.root = root
            self.root.title(f"{TOOL_NAME} v{VERSION} — {BRAND}")
            self.root.geometry("1300x920")
            self.root.minsize(1000, 700)
            self.root.configure(bg=COLORS['bg_dark'])
            self.analyzer = PacketCaptureAnalyzer()
            self.results = None
            self._setup_styles()
            self._build()

        def _setup_styles(self):
            s = ttk.Style(); s.theme_use('clam')
            s.configure('Dark.TFrame', background=COLORS['bg_dark'])
            s.configure('Card.TFrame', background=COLORS['bg_card'])
            s.configure('Mid.TFrame', background=COLORS['bg_mid'])
            for name, bg, fg, font in [
                ('Title.TLabel', COLORS['bg_dark'], COLORS['accent'], ('Helvetica',22,'bold')),
                ('Subtitle.TLabel', COLORS['bg_dark'], COLORS['text_secondary'], ('Helvetica',11)),
                ('Brand.TLabel', COLORS['bg_dark'], COLORS['accent'], ('Helvetica',10,'bold')),
                ('Dark.TLabel', COLORS['bg_dark'], COLORS['text'], ('Helvetica',10)),
                ('Card.TLabel', COLORS['bg_card'], COLORS['text'], ('Helvetica',10)),
                ('CardMuted.TLabel', COLORS['bg_card'], COLORS['text_muted'], ('Helvetica',9)),
                ('Score.TLabel', COLORS['bg_card'], COLORS['accent'], ('Consolas',28,'bold')),
                ('StatVal.TLabel', COLORS['bg_card'], COLORS['cyan'], ('Consolas',16,'bold')),
                ('StatLbl.TLabel', COLORS['bg_card'], COLORS['text_muted'], ('Helvetica',8)),
            ]:
                s.configure(name, background=bg, foreground=fg, font=font)
            s.configure('Accent.TButton', background=COLORS['accent'], foreground=COLORS['white'], font=('Helvetica',11,'bold'), padding=(20,12))
            s.map('Accent.TButton', background=[('active',COLORS['accent_hover'])])
            s.configure('Secondary.TButton', background=COLORS['bg_card'], foreground=COLORS['text'], font=('Helvetica',10), padding=(15,10))
            s.map('Secondary.TButton', background=[('active',COLORS['border'])])
            s.configure('Small.TButton', background=COLORS['bg_card'], foreground=COLORS['text_secondary'], font=('Helvetica',9), padding=(10,6))
            s.configure('dark.Horizontal.TProgressbar', background=COLORS['accent'], troughcolor=COLORS['bg_input'])

        def _build(self):
            main = ttk.Frame(self.root, style='Dark.TFrame'); main.pack(fill=tk.BOTH, expand=True)

            # Header
            hdr = ttk.Frame(main, style='Dark.TFrame'); hdr.pack(fill=tk.X, padx=30, pady=(20,10))
            accent = tk.Canvas(hdr, height=3, bg=COLORS['bg_dark'], highlightthickness=0)
            accent.pack(fill=tk.X, pady=(0,12)); accent.update_idletasks()
            w = max(accent.winfo_width(), 800)
            accent.create_rectangle(0,0,w//3,3,fill=COLORS['accent'],outline='')
            accent.create_rectangle(w//3,0,2*w//3,3,fill=COLORS['purple'],outline='')
            accent.create_rectangle(2*w//3,0,w,3,fill=COLORS['cyan'],outline='')
            ht = ttk.Frame(hdr, style='Dark.TFrame'); ht.pack(fill=tk.X)
            lh = ttk.Frame(ht, style='Dark.TFrame'); lh.pack(side=tk.LEFT)
            ttk.Label(lh, text=BRAND, style='Brand.TLabel').pack(anchor='w')
            ttk.Label(lh, text="Packet Capture Analyzer", style='Title.TLabel').pack(anchor='w')
            ttk.Label(lh, text="Deep Packet Inspection  •  Traffic Forensics  •  Threat Detection", style='Subtitle.TLabel').pack(anchor='w', pady=(2,0))
            ttk.Label(ttk.Frame(ht, style='Dark.TFrame'), text=f"v{VERSION}", style='Dark.TLabel').pack(anchor='e')

            # Toolbar
            tb = ttk.Frame(main, style='Dark.TFrame'); tb.pack(fill=tk.X, padx=30, pady=(10,5))
            ttk.Button(tb, text="  Open PCAP  ", style='Accent.TButton', command=self._open_pcap).pack(side=tk.LEFT, padx=(0,8))
            ttk.Button(tb, text="  Generate Demo  ", style='Secondary.TButton', command=self._gen_demo).pack(side=tk.LEFT, padx=(0,8))
            ttk.Button(tb, text="  Export Report  ", style='Secondary.TButton', command=self._export_html).pack(side=tk.RIGHT, padx=(8,0))
            ttk.Button(tb, text="  Export JSON  ", style='Small.TButton', command=self._export_json).pack(side=tk.RIGHT, padx=(8,0))
            ttk.Button(tb, text="  Clear  ", style='Small.TButton', command=self._clear).pack(side=tk.RIGHT, padx=(8,0))

            # Content
            content = ttk.Frame(main, style='Dark.TFrame'); content.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10,20))

            # Left panel — stats
            left = ttk.Frame(content, style='Dark.TFrame', width=340); left.pack(side=tk.LEFT, fill=tk.Y, padx=(0,15)); left.pack_propagate(False)

            # Risk card
            rc = ttk.Frame(left, style='Card.TFrame'); rc.pack(fill=tk.X, pady=(0,10))
            ttk.Label(rc, text="THREAT ASSESSMENT", style='CardMuted.TLabel').pack(anchor='w', padx=15, pady=(12,5))
            self.risk_lbl = ttk.Label(rc, text="—", style='Score.TLabel'); self.risk_lbl.pack(padx=15, pady=(5,2))
            self.risk_desc = ttk.Label(rc, text="Awaiting analysis...", style='CardMuted.TLabel'); self.risk_desc.pack(padx=15)
            sf = ttk.Frame(rc, style='Card.TFrame'); sf.pack(fill=tk.X, padx=15, pady=(5,15))
            self.score_bar = ttk.Progressbar(sf, style='dark.Horizontal.TProgressbar', length=300, maximum=100, value=0)
            self.score_bar.pack(fill=tk.X, pady=(3,2))
            self.score_lbl = ttk.Label(sf, text="0 / 100", style='CardMuted.TLabel'); self.score_lbl.pack(anchor='e')

            # Stats card
            sc = ttk.Frame(left, style='Card.TFrame'); sc.pack(fill=tk.X, pady=(0,10))
            ttk.Label(sc, text="CAPTURE STATISTICS", style='CardMuted.TLabel').pack(anchor='w', padx=15, pady=(12,5))
            stats_grid = ttk.Frame(sc, style='Card.TFrame'); stats_grid.pack(fill=tk.X, padx=15, pady=(0,15))
            self.stat_labels = {}
            for i, (key, label) in enumerate([
                ('packets', 'Packets'), ('bytes', 'Data'), ('duration', 'Duration'),
                ('ips', 'Unique IPs'), ('flows', 'Flows'), ('anomalies', 'Anomalies'),
                ('dns', 'DNS Queries'), ('http', 'HTTP Reqs'), ('tls', 'TLS Handshakes'),
            ]):
                r, c = divmod(i, 3)
                f = ttk.Frame(stats_grid, style='Card.TFrame')
                f.grid(row=r, column=c, padx=5, pady=3, sticky='ew')
                stats_grid.columnconfigure(c, weight=1)
                val = ttk.Label(f, text="—", style='StatVal.TLabel'); val.pack()
                ttk.Label(f, text=label, style='StatLbl.TLabel').pack()
                self.stat_labels[key] = val

            # Right panel — tabs
            right = ttk.Frame(content, style='Dark.TFrame'); right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            s = ttk.Style()
            s.configure('TNotebook', background=COLORS['bg_dark'], borderwidth=0)
            s.configure('TNotebook.Tab', background=COLORS['bg_card'], foreground=COLORS['text_secondary'], padding=(12,8), font=('Helvetica',10))
            s.map('TNotebook.Tab', background=[('selected',COLORS['accent'])], foreground=[('selected',COLORS['white'])])

            self.nb = ttk.Notebook(right); self.nb.pack(fill=tk.BOTH, expand=True)
            txt_opts = dict(wrap=tk.WORD, bg=COLORS['bg_input'], fg=COLORS['text'], font=('Consolas',10), relief='flat', borderwidth=0, padx=12, pady=12)
            self.tabs = {}
            for name, fg in [("Log", COLORS['text']), ("Protocols", COLORS['cyan']), ("Flows", COLORS['text']),
                               ("DNS", COLORS['cyan']), ("HTTP", COLORS['text']), ("TLS", COLORS['purple']),
                               ("Threats", COLORS['red']), ("IOCs", COLORS['cyan'])]:
                f = ttk.Frame(self.nb, style='Card.TFrame'); self.nb.add(f, text=f" {name} ")
                t = scrolledtext.ScrolledText(f, **{**txt_opts, 'fg': fg}); t.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
                self.tabs[name] = t

            self.tabs["Log"].insert(tk.END, f"  {BRAND} — {TOOL_NAME} v{VERSION}\n  Ready. Open a PCAP file to analyze.\n\n")
            self.tabs["Log"].config(state=tk.DISABLED)

            # Status
            sb = ttk.Frame(main, style='Mid.TFrame'); sb.pack(fill=tk.X, side=tk.BOTTOM)
            self.status = ttk.Label(sb, text=f"  {BRAND} — {TOOL_NAME} v{VERSION}  |  Ready",
                                     background=COLORS['bg_mid'], foreground=COLORS['text_muted'], font=('Helvetica',9))
            self.status.pack(side=tk.LEFT, padx=10, pady=5)

        def _log(self, m):
            def _a():
                self.tabs["Log"].config(state=tk.NORMAL); self.tabs["Log"].insert(tk.END, m+"\n")
                self.tabs["Log"].see(tk.END); self.tabs["Log"].config(state=tk.DISABLED)
            self.root.after(0, _a)

        def _set_status(self, t):
            self.root.after(0, lambda: self.status.configure(text=f"  {BRAND} — {TOOL_NAME} v{VERSION}  |  {t}"))

        def _update(self, r):
            risk = r.get('risk_level','CLEAN'); score = r.get('threat_score',0)
            rc = {'CLEAN':COLORS['green'],'LOW':COLORS['yellow'],'MEDIUM':COLORS['orange'],'HIGH':COLORS['red'],'CRITICAL':COLORS['critical']}
            self.risk_lbl.configure(text=risk, foreground=rc.get(risk, COLORS['text_muted']))
            self.risk_desc.configure(text=f"Threat Score: {score}/100")
            self.score_bar['value'] = score; self.score_lbl.configure(text=f"{score} / 100")

            s = r.get('summary',{})
            self.stat_labels['packets'].configure(text=f"{s.get('total_packets',0):,}")
            self.stat_labels['bytes'].configure(text=s.get('total_bytes_human','0 B'))
            self.stat_labels['duration'].configure(text=s.get('duration_human','0:00'))
            self.stat_labels['ips'].configure(text=str(s.get('unique_ips',0)))
            self.stat_labels['flows'].configure(text=str(s.get('total_flows',0)))
            self.stat_labels['anomalies'].configure(text=str(len(r.get('anomalies',[]))))
            self.stat_labels['dns'].configure(text=str(r.get('dns',{}).get('total_queries',0)))
            self.stat_labels['http'].configure(text=str(r.get('http',{}).get('total_requests',0)))
            self.stat_labels['tls'].configure(text=str(r.get('tls',{}).get('total_handshakes',0)))

            # Protocols tab
            t = self.tabs["Protocols"]; t.delete('1.0', tk.END)
            t.insert(tk.END, f"PROTOCOL DISTRIBUTION\n{'='*60}\n\n")
            for p, c in sorted(r.get('protocols',{}).items(), key=lambda x:-x[1]):
                pct = (c/max(s.get('total_packets',1),1))*100
                bar = '#' * int(pct/2)
                t.insert(tk.END, f"  {p:12s} {c:>8,}  ({pct:5.1f}%)  {bar}\n")

            # Flows tab
            t = self.tabs["Flows"]; t.delete('1.0', tk.END)
            t.insert(tk.END, f"TOP FLOWS BY VOLUME\n{'='*60}\n\n")
            for f in r.get('top_flows',[])[:20]:
                t.insert(tk.END, f"  {f['key']}\n    Packets: {f['packets']:,}  Data: {f['bytes_human']}  Duration: {f['duration']}s\n\n")

            # DNS tab
            t = self.tabs["DNS"]; t.delete('1.0', tk.END)
            dns = r.get('dns',{})
            t.insert(tk.END, f"DNS ANALYSIS\n{'='*60}\n  Queries: {dns.get('total_queries',0)}  Unique domains: {dns.get('unique_domains',0)}\n\n")
            t.insert(tk.END, f"TOP QUERIED DOMAINS\n{'-'*40}\n")
            for d, c in list(dns.get('top_domains',{}).items())[:20]:
                t.insert(tk.END, f"  {c:>5}  {d}\n")

            # HTTP tab
            t = self.tabs["HTTP"]; t.delete('1.0', tk.END)
            http = r.get('http',{})
            t.insert(tk.END, f"HTTP ANALYSIS\n{'='*60}\n  Requests: {http.get('total_requests',0)}\n\n")
            for req in http.get('requests',[])[:30]:
                t.insert(tk.END, f"  {req.get('method',''):6s} {req.get('host','')}{req.get('uri','')}\n    From: {req.get('src_ip','')}  UA: {req.get('user_agent','')[:60]}\n\n")

            # TLS tab
            t = self.tabs["TLS"]; t.delete('1.0', tk.END)
            tls = r.get('tls',{})
            t.insert(tk.END, f"TLS ANALYSIS\n{'='*60}\n  Handshakes: {tls.get('total_handshakes',0)}  Deprecated: {tls.get('deprecated_count',0)}\n\n")
            t.insert(tk.END, f"VERSIONS\n{'-'*40}\n")
            for v, c in tls.get('versions',{}).items():
                t.insert(tk.END, f"  {v:12s}  {c}\n")
            snis = tls.get('sni_list',[])
            if snis:
                t.insert(tk.END, f"\nSNI HOSTNAMES\n{'-'*40}\n")
                for sni in snis[:30]: t.insert(tk.END, f"  {sni}\n")

            # Threats tab
            t = self.tabs["Threats"]; t.delete('1.0', tk.END)
            anomalies = r.get('anomalies',[])
            t.insert(tk.END, f"ANOMALIES & THREATS ({len(anomalies)})\n{'='*60}\n\n")
            if anomalies:
                for a in anomalies:
                    t.insert(tk.END, f"  [{a['severity'].upper():8s}] [{a.get('category','')}]\n  {a['description']}\n\n")
            else:
                t.insert(tk.END, "  No anomalies detected — traffic appears clean.\n")

            # IOCs tab
            t = self.tabs["IOCs"]; t.delete('1.0', tk.END)
            iocs = r.get('iocs',[])
            t.insert(tk.END, f"INDICATORS OF COMPROMISE ({len(iocs)})\n{'='*60}\n\n")
            for ioc in iocs[:100]:
                t.insert(tk.END, f"  [{ioc['type']:20s}]  {ioc['value']}\n")

        def _open_pcap(self):
            p = filedialog.askopenfilename(title="Open PCAP File",
                filetypes=[("PCAP files","*.pcap *.pcapng *.cap"),("All","*.*")])
            if not p: return
            self._set_status("Analyzing..."); self.nb.select(0)
            def _go():
                try:
                    r = self.analyzer.analyze_file(p, log_cb=self._log)
                    self.results = r
                    self.root.after(0, lambda: self._update(r))
                    self._set_status(f"Done — {r.get('risk_level','?')} ({r.get('threat_score',0)}/100)")
                except Exception as e:
                    self._log(f"[!] ERROR: {e}")
                    self._set_status("Error — analysis failed")
                    self.root.after(0, lambda msg=str(e): messagebox.showerror("Analysis Failed", msg))
            threading.Thread(target=_go, daemon=True).start()

        def _gen_demo(self):
            p = filedialog.asksaveasfilename(title="Save Demo PCAP", defaultextension=".pcap",
                filetypes=[("PCAP","*.pcap")], initialfile="demo_capture.pcap")
            if not p: return
            self._log("[*] Generating demo PCAP...")
            DemoGenerator.generate(p)
            self._log(f"[+] Demo saved: {p}\n[*] Analyzing...")
            self._set_status("Analyzing demo...")
            def _go():
                try:
                    r = self.analyzer.analyze_file(p, log_cb=self._log)
                    self.results = r
                    self.root.after(0, lambda: self._update(r))
                    self._set_status(f"Demo analyzed — {r.get('risk_level','?')}")
                except Exception as e:
                    self._log(f"[!] ERROR: {e}")
                    self._set_status("Error — analysis failed")
                    self.root.after(0, lambda msg=str(e): messagebox.showerror("Analysis Failed", msg))
            threading.Thread(target=_go, daemon=True).start()

        def _export_html(self):
            if not self.results:
                messagebox.showwarning("No Results","Analyze a PCAP first."); return
            p = filedialog.asksaveasfilename(title="Save Report", defaultextension=".html",
                filetypes=[("HTML","*.html")], initialfile=f"pcap_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            if not p: return
            ReportGenerator.generate(self.results, self.results.get('file_info',{}), p)
            self._log(f"[+] Report: {p}"); messagebox.showinfo("Exported", f"Report saved:\n{p}")

        def _export_json(self):
            if not self.results:
                messagebox.showwarning("No Results","Analyze a PCAP first."); return
            p = filedialog.asksaveasfilename(title="Save JSON", defaultextension=".json",
                filetypes=[("JSON","*.json")], initialfile=f"pcap_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            if not p: return
            with open(p,'w') as f: json.dump(self.results, f, indent=2, default=str)
            self._log(f"[+] JSON: {p}")

        def _clear(self):
            self.results = None
            self.risk_lbl.configure(text="—", foreground=COLORS['accent'])
            self.risk_desc.configure(text="Awaiting analysis...")
            self.score_bar['value'] = 0; self.score_lbl.configure(text="0 / 100")
            for k in self.stat_labels: self.stat_labels[k].configure(text="—")
            for name, t in self.tabs.items():
                if name == "Log": continue
                t.delete('1.0', tk.END)
            self.tabs["Log"].config(state=tk.NORMAL); self.tabs["Log"].delete('1.0', tk.END)
            self.tabs["Log"].insert(tk.END, f"  {BRAND} — {TOOL_NAME} v{VERSION}\n  Cleared.\n\n")
            self.tabs["Log"].config(state=tk.DISABLED)
            self._set_status("Ready")

    root = tk.Tk(); App(root); root.mainloop()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      PACKET CAPTURE ANALYZER v{VERSION}                         ║
║                              {BRAND} ™                                       ║
║       Deep Packet Inspection • Traffic Forensics • Threat Detection        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    if len(sys.argv) == 1:
        print(banner); print("[*] Launching GUI...\n"); launch_gui(); return

    print(banner)
    parser = argparse.ArgumentParser(description=f'{TOOL_NAME} — {BRAND}',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"  Run with no args to launch GUI.\n\n  {BRAND} — All Rights Reserved")
    parser.add_argument('target', nargs='?', help='PCAP/PCAPNG file to analyze')
    parser.add_argument('--report', '-r', help='HTML report output path')
    parser.add_argument('--json', '-j', action='store_true', help='JSON output')
    parser.add_argument('--demo', '-d', action='store_true', help='Generate & analyze demo PCAP')
    parser.add_argument('--no-report', action='store_true', help='Skip HTML report')
    parser.add_argument('--output-dir', '-o', default='.', help='Output directory')
    parser.add_argument('--gui', '-g', action='store_true', help='Force GUI')
    args = parser.parse_args()

    if args.gui: launch_gui(); return

    analyzer = PacketCaptureAnalyzer()

    if args.demo:
        demo_path = os.path.join(args.output_dir, 'demo_capture.pcap')
        print("[*] Generating demo PCAP...")
        DemoGenerator.generate(demo_path)
        print(f"[+] Demo: {demo_path}\n")
        results = analyzer.analyze_file(demo_path)
    elif args.target:
        if not os.path.isfile(args.target):
            print(f"[!] Not found: {args.target}"); sys.exit(1)
        results = analyzer.analyze_file(args.target)
    else:
        parser.print_help(); sys.exit(0)

    if args.json:
        print("\n" + json.dumps(results, indent=2, default=str))

    if not args.no_report:
        rp = args.report or os.path.join(args.output_dir, f'pcap_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
        ReportGenerator.generate(results, results.get('file_info', {}), rp)
        print(f"\n[+] Report: {rp}")

    s = results.get('summary', {})
    print(f"\n{'='*70}")
    print(f"  ANALYSIS COMPLETE")
    print(f"  {s.get('total_packets',0):,} packets | {s.get('total_bytes_human','0 B')} | {s.get('duration_human','0:00')}")
    print(f"  Risk: {results.get('risk_level','CLEAN')} ({results.get('threat_score',0)}/100)")
    print(f"  Anomalies: {len(results.get('anomalies',[]))} | IOCs: {len(results.get('iocs',[]))}")
    print(f"{'='*70}\n")


if __name__ == '__main__':
    main()
