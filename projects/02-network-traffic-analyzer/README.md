# Day 02 — Network Traffic Analyzer

**Domain:** Network Security  
**Type:** Security Tool  
**Difficulty:** Beginner → Intermediate  
**Language:** Python 3.10+ · Scapy

---

## What This Is

A `.pcap` file analyzer that parses captured network traffic and automatically flags suspicious behaviour — port scans, cleartext credentials, DNS tunnelling, C2 beaconing, and large data exfiltration transfers.

This is the kind of tool a security operations (SOC) analyst or network defender runs when investigating an incident or reviewing captured traffic. Real equivalents include Zeek (formerly Bro) and Suricata, but building your own teaches you exactly what those tools are doing under the hood.

---

## Why Network Traffic Analysis Matters

Attackers leave traces in network traffic. Even if an attacker encrypts their C2 channel, the *pattern* of connections (timing, frequency, destination) can reveal malware. Cleartext protocols like FTP, Telnet, and HTTP Basic Auth are still common in real networks and trivially sniffable. DNS is almost always allowed through firewalls — making it a favourite exfiltration channel.

Security engineers need to understand what "normal" traffic looks like so they can spot "abnormal".

---

## Detections Implemented

| Rule ID | Severity | Detection |
|---------|----------|-----------|
| NET-001 | CRITICAL/HIGH | Port scan — single IP probing many ports via SYN packets |
| NET-002 | HIGH | Cleartext credentials — HTTP Basic Auth, FTP USER/PASS, password in body |
| NET-003 | HIGH | DNS tunnelling — unusually long query names, high query volume |
| NET-004 | HIGH | Beaconing — highly regular repeated connections to external IP |
| NET-005 | MEDIUM | Large outbound data transfer — potential exfiltration |

---

## Usage

```bash
# Install dependency
pip install scapy

# Generate the test pcap (only needed once)
python tests/generate_test_pcap.py

# Analyze a capture file
python traffic_analyzer.py --file tests/suspicious_traffic.pcap

# Only show HIGH and above
python traffic_analyzer.py --file capture.pcap --min-severity HIGH

# Save JSON report
python traffic_analyzer.py --file capture.pcap --output report.json
```

To capture your own traffic for testing (requires admin/root):
```bash
# On Linux/Mac — capture 60 seconds of traffic on interface eth0
sudo tcpdump -i eth0 -w my_capture.pcap -G 60 -W 1
```

---

## Example Output

```
[CRITICAL] NET-001: Port scan detected: 10.0.0.99 → 192.168.1.10
  Source : 10.0.0.99
  Detail : 200 unique ports probed | Sample ports: [1, 2, 3, 4, 5, ...]

[HIGH] NET-002: Cleartext credentials: FTP USER/PASS sequence
  Source : 192.168.1.50 → 192.168.1.10:21
  Detail : Match preview: 'USER ftpuser\r\nPASS s3cr3tpassword'

[HIGH] NET-003: DNS tunnelling indicator: 192.168.1.50 (60 long queries)
  Detail : 60 queries with names >50 chars | Example: data0.aaaa...exfil...evil-c2-server.com

[HIGH] NET-004: Beaconing behaviour: 192.168.1.50 → 203.0.113.42:443
  Detail : 10 connections | Mean interval: 30.0s | CV: 0.013 (very regular)

SUMMARY  (6 finding(s))
  CRITICAL   1  █
  HIGH       3  ███
  MEDIUM     2  ██
```

---

## Concepts Learned

**TCP SYN scanning** — a port scan works by sending a TCP SYN packet to a port. If the port is open, the target replies with SYN-ACK. A scanner never completes the handshake (sends RST instead), making it fast and leaving fewer logs. The flag pattern `SYN=1, ACK=0` on many ports from one source is the detection signature.

**Protocol hierarchy** — network traffic is layered: Ethernet → IP → TCP/UDP → Application (HTTP, DNS, FTP). Scapy lets you peel each layer like an onion using `pkt[TCP]`, `pkt[DNS]`, etc.

**DNS tunnelling** — DNS is typically allowed through firewalls because everything needs name resolution. Attackers encode data in subdomain labels (e.g. `aGVsbG8=.exfil.evil.com`) — the data goes out in the query name, answers come back in TXT records. Detection: long names + high query volume to unusual domains.

**Beaconing and Coefficient of Variation (CV)** — malware phones home on a timer. Human network traffic is irregular; malware traffic is extremely regular. The coefficient of variation (standard deviation / mean) of inter-connection intervals gives a dimensionless measure of regularity. A CV below ~0.3 is suspiciously regular.

**Private vs public IP space (RFC 1918)** — `10.x.x.x`, `172.16–31.x.x`, and `192.168.x.x` are private (internal) addresses. Connections *from* private IPs *to* public IPs are outbound — the direction most relevant for exfiltration and C2 detection.

---

## How to Extend This

- Add **TLS certificate inspection** — parse the TLS ClientHello to extract SNI (server name) even from encrypted traffic
- Add **HTTP User-Agent anomaly detection** — unusual or empty user agents often indicate automated tools or malware
- Add **GeoIP lookup** — flag connections to unusual countries using the MaxMind GeoLite2 database
- Add **Shannon entropy scoring** on DNS query labels — high entropy subdomains (base64/hex encoded) are a stronger tunnelling signal than length alone
- Build a **live capture mode** using `scapy.sniff()` instead of reading a file — real-time detection

---

## References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [MITRE ATT&CK — Network Sniffing T1040](https://attack.mitre.org/techniques/T1040/)
- [MITRE ATT&CK — DNS Tunnelling T1071.004](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE ATT&CK — Port Scanning T1046](https://attack.mitre.org/techniques/T1046/)
- [SANS — Detecting DNS Tunnelling](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
- [Beaconing Detection — Mandiant](https://www.mandiant.com/resources/blog/beacon-detection)
