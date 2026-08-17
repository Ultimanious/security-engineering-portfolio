#!/usr/bin/env python3
"""
Generate test .pcap files containing realistic suspicious traffic patterns.
Run this once to create the test data used by traffic_analyzer.py.

    python generate_test_pcap.py
"""

from scapy.all import (
    IP, TCP, UDP, DNS, DNSQR, Raw,
    wrpcap, RandShort
)
import random
import time

INTERNAL_HOST  = "192.168.1.50"
ATTACKER_IP    = "10.0.0.99"
EXTERNAL_C2    = "203.0.113.42"   # TEST-NET — safe to use in examples
EXTERNAL_LEGIT = "8.8.8.8"
WEB_SERVER     = "192.168.1.10"
DNS_SERVER     = "192.168.1.1"

packets = []
base_time = 1700000000.0  # fixed timestamp so pcap is deterministic
t = base_time


def pkt_at(offset, pkt):
    pkt.time = base_time + offset
    return pkt


# ── 1. Port scan: attacker SYNs 200 ports on the web server ──────────────────
print("Generating port scan traffic...")
for port in range(1, 201):
    p = IP(src=ATTACKER_IP, dst=WEB_SERVER) / TCP(sport=RandShort(), dport=port, flags="S")
    p.time = base_time + (port * 0.01)
    packets.append(p)


# ── 2. Cleartext HTTP Basic Auth ─────────────────────────────────────────────
print("Generating cleartext credential traffic...")
http_payload = (
    b"GET /admin HTTP/1.1\r\n"
    b"Host: 192.168.1.10\r\n"
    b"Authorization: Basic YWRtaW46cGFzc3dvcmQxMjM=\r\n"   # admin:password123
    b"User-Agent: Mozilla/5.0\r\n"
    b"\r\n"
)
p = IP(src=INTERNAL_HOST, dst=WEB_SERVER) / TCP(sport=54321, dport=80, flags="PA") / Raw(load=http_payload)
p.time = base_time + 5.0
packets.append(p)

# FTP credentials
ftp_payload = b"USER ftpuser\r\nPASS s3cr3tpassword\r\n"
p = IP(src=INTERNAL_HOST, dst=WEB_SERVER) / TCP(sport=54322, dport=21, flags="PA") / Raw(load=ftp_payload)
p.time = base_time + 6.0
packets.append(p)


# ── 3. DNS tunnelling — very long query names ─────────────────────────────────
print("Generating DNS anomaly traffic...")
long_subdomain = "a" * 30 + ".exfil." + "b" * 25 + ".evil-c2-server.com"
for i in range(60):   # high-volume queries too
    qname = f"data{i}.{long_subdomain}"
    p = (IP(src=INTERNAL_HOST, dst=DNS_SERVER) /
         UDP(sport=RandShort(), dport=53) /
         DNS(rd=1, qd=DNSQR(qname=qname)))
    p.time = base_time + 10.0 + (i * 0.5)
    packets.append(p)


# ── 4. Beaconing — very regular connections to external C2 ────────────────────
print("Generating beaconing traffic...")
BEACON_INTERVAL = 30.0   # every 30 seconds, low jitter
for i in range(10):
    jitter = random.uniform(-0.5, 0.5)   # tiny jitter, CV will still be low
    p = IP(src=INTERNAL_HOST, dst=EXTERNAL_C2) / TCP(
        sport=RandShort(), dport=443, flags="S"
    )
    p.time = base_time + 100.0 + (i * BEACON_INTERVAL) + jitter
    packets.append(p)


# ── 5. Large outbound transfer ────────────────────────────────────────────────
print("Generating large transfer traffic...")
chunk = b"X" * 1400   # ~MTU-sized payload chunks
for i in range(800):  # 800 * 1400 = ~1.1 MB
    p = (IP(src=INTERNAL_HOST, dst=EXTERNAL_C2) /
         TCP(sport=54400, dport=443, flags="PA") /
         Raw(load=chunk))
    p.time = base_time + 400.0 + (i * 0.001)
    packets.append(p)


# ── Write pcap ────────────────────────────────────────────────────────────────
out = "tests/suspicious_traffic.pcap"
wrpcap(out, packets)
print(f"\n✔  Written {len(packets)} packets → {out}")
print("   Run:  python traffic_analyzer.py --file tests/suspicious_traffic.pcap")
