#!/usr/bin/env python3
"""
Network Traffic Analyzer
========================
Parses .pcap files and flags suspicious network behaviour:
  - Port scans (SYN scan, connect scan)
  - Cleartext credential patterns (HTTP Basic Auth, FTP, Telnet)
  - DNS anomalies (unusually long names, high query volume — DNS tunnelling indicators)
  - Beaconing (hosts making repeated connections at regular intervals)
  - Large data transfers to external IPs

Usage:
    python traffic_analyzer.py --file capture.pcap
    python traffic_analyzer.py --file capture.pcap --output report.json
    python traffic_analyzer.py --file capture.pcap --no-colour

Author: Security Engineering Portfolio
"""

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

# ── Try importing scapy ──────────────────────────────────────────────────────

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, rdpcap
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("ERROR: scapy is required.  Run:  pip install scapy", file=sys.stderr)
    sys.exit(1)

# ── Severity & colours ───────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

COLOURS = {
    CRITICAL: "\033[91m",
    HIGH:     "\033[31m",
    MEDIUM:   "\033[33m",
    LOW:      "\033[36m",
    INFO:     "\033[37m",
    "RESET":  "\033[0m",
    "BOLD":   "\033[1m",
    "GREEN":  "\033[92m",
    "HEADER": "\033[95m",
}

# ── Private IP ranges (RFC 1918 + loopback) ──────────────────────────────────

PRIVATE_RANGES = [
    ("10.0.0.0",     0xFF000000, 0x0A000000),
    ("172.16.0.0",   0xFFF00000, 0xAC100000),
    ("192.168.0.0",  0xFFFF0000, 0xC0A80000),
    ("127.0.0.0",    0xFF000000, 0x7F000000),
]


def is_private(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
        n = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        return any((n & mask) == base for _, mask, base in PRIVATE_RANGES)
    except Exception:
        return False


# ── Finding dataclass ────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id:     str
    severity:    str
    title:       str
    description: str
    src:         str
    detail:      str
    remediation: str
    references:  list[str] = field(default_factory=list)


# ── Detection logic ──────────────────────────────────────────────────────────

def detect_port_scan(packets: list) -> list[Finding]:
    """
    NET-001: Port scan detection.
    A single source IP sending SYN packets to many distinct destination ports
    on the same host within the capture window is a classic port scan signature.
    """
    findings = []

    # { src_ip -> { dst_ip -> set of dst_ports } }
    syn_map: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            tcp = pkt[TCP]
            # SYN flag set, ACK flag not set → SYN packet (not part of established conn)
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                syn_map[pkt[IP].src][pkt[IP].dst].add(tcp.dport)

    SCAN_THRESHOLD = 15  # ports

    for src, targets in syn_map.items():
        for dst, ports in targets.items():
            if len(ports) >= SCAN_THRESHOLD:
                severity = CRITICAL if len(ports) > 100 else HIGH
                findings.append(Finding(
                    rule_id="NET-001",
                    severity=severity,
                    title=f"Port scan detected: {src} → {dst}",
                    description=(
                        "A single source IP sent SYN packets to a large number of distinct "
                        "ports on the same destination. This is the hallmark of an automated "
                        "port scan (e.g. nmap -sS), used by attackers to discover open services."
                    ),
                    src=src,
                    detail=(
                        f"{src} → {dst} | {len(ports)} unique ports probed | "
                        f"Sample ports: {sorted(ports)[:10]}"
                    ),
                    remediation=(
                        "Investigate the source IP. Block at firewall if not an authorised "
                        "scanner. Enable IDS/IPS rules for SYN flood and port scan signatures."
                    ),
                    references=[
                        "https://nmap.org/book/man-port-scanning-basics.html",
                        "https://attack.mitre.org/techniques/T1046/",
                    ],
                ))

    return findings


def detect_cleartext_credentials(packets: list) -> list[Finding]:
    """
    NET-002: Cleartext credential transmission.
    Scans HTTP, FTP, and Telnet traffic for credential patterns.
    """
    findings = []

    # Patterns that suggest credentials in cleartext
    CRED_PATTERNS = [
        (re.compile(rb"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+", re.I),
         "HTTP Basic Auth header (base64-encoded credentials)"),
        (re.compile(rb"(password|passwd|pwd)\s*[:=]\s*\S+", re.I),
         "Password field in HTTP body"),
        (re.compile(rb"USER\s+\S+\r\nPASS\s+\S+", re.I),
         "FTP USER/PASS sequence"),
        (re.compile(rb"(login|username|user)\s*[:=]\s*\S+", re.I),
         "Login/username field in cleartext"),
    ]

    seen: set[str] = set()  # deduplicate by src:dst:pattern

    for pkt in packets:
        if not (IP in pkt and TCP in pkt and Raw in pkt):
            continue

        payload = pkt[Raw].load
        src = pkt[IP].src
        dst = pkt[IP].dst
        dport = pkt[TCP].dport

        # Only look at plaintext protocol ports
        if dport not in (80, 8080, 8000, 21, 23, 25, 110, 143):
            continue

        for pattern, label in CRED_PATTERNS:
            match = pattern.search(payload)
            if match:
                key = f"{src}:{dst}:{label}"
                if key in seen:
                    continue
                seen.add(key)

                # Truncate matched value for display — don't log actual passwords
                matched_bytes = match.group(0)[:60].decode("utf-8", errors="replace")

                findings.append(Finding(
                    rule_id="NET-002",
                    severity=HIGH,
                    title=f"Cleartext credentials: {label}",
                    description=(
                        "Credentials or authentication material were transmitted in cleartext "
                        "over the network. Any observer with packet capture capability on the "
                        "same network segment can read these credentials."
                    ),
                    src=f"{src} → {dst}:{dport}",
                    detail=f"Pattern: {label} | Match preview: {matched_bytes!r}",
                    remediation=(
                        "Migrate to encrypted protocols: HTTPS instead of HTTP, "
                        "SFTP/SCP instead of FTP, SSH instead of Telnet. "
                        "Enforce TLS 1.2+ and disable plaintext protocol listeners."
                    ),
                    references=[
                        "https://attack.mitre.org/techniques/T1040/",
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                    ],
                ))

    return findings


def detect_dns_anomalies(packets: list) -> list[Finding]:
    """
    NET-003: DNS anomaly detection.
    - Unusually long DNS query names (DNS tunnelling indicator)
    - Single host making an unusually high volume of DNS queries
    """
    findings = []

    query_counts: Counter = Counter()
    # { src -> list of long query names }
    long_queries: dict[str, list[str]] = defaultdict(list)

    LONG_NAME_THRESHOLD = 50    # characters in the query name
    HIGH_VOLUME_THRESHOLD = 50  # DNS queries from a single IP

    for pkt in packets:
        if DNS in pkt and pkt[DNS].qr == 0:  # qr=0 means query (not response)
            src = pkt[IP].src if IP in pkt else "unknown"
            query_counts[src] += 1

            if DNSQR in pkt:
                name = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                if len(name) > LONG_NAME_THRESHOLD:
                    long_queries[src].append(name)

    # Long query names — group by source IP, one finding per host
    for src, names in long_queries.items():
        max_len = max(len(n) for n in names)
        example = names[0]
        findings.append(Finding(
            rule_id="NET-003",
            severity=HIGH,
            title=f"DNS tunnelling indicator: {src} ({len(names)} long queries)",
            description=(
                "DNS tunnelling encodes data inside DNS query names to exfiltrate data "
                "or establish C2 channels through firewalls that allow DNS. "
                "Legitimate DNS names are rarely this long."
            ),
            src=src,
            detail=(
                f"{len(names)} queries with names >{LONG_NAME_THRESHOLD} chars | "
                f"Max length: {max_len} | Example: {example[:80]}{'...' if len(example) > 80 else ''}"
            ),
            remediation=(
                "Inspect DNS traffic for high-entropy subdomains. Deploy DNS security "
                "solutions (e.g. Cisco Umbrella, Cloudflare Gateway) that detect tunnelling. "
                "Consider blocking uncommon TLDs and restricting DNS to known resolvers."
            ),
            references=[
                "https://attack.mitre.org/techniques/T1071/004/",
                "https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152",
            ],
        ))

    # High-volume DNS queries
    for src, count in query_counts.items():
        if count >= HIGH_VOLUME_THRESHOLD:
            findings.append(Finding(
                rule_id="NET-003",
                severity=MEDIUM,
                title=f"High DNS query volume from {src}",
                description=(
                    "A single host is generating an unusually high number of DNS queries. "
                    "This can indicate malware performing domain generation algorithm (DGA) "
                    "lookups, DNS tunnelling, or a misconfigured application."
                ),
                src=src,
                detail=f"{count} DNS queries from {src} in this capture",
                remediation=(
                    "Investigate the host for malware. Review which domains are being "
                    "queried. Enable DNS logging and alerting on anomalous query rates."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1568/002/",
                ],
            ))

    return findings


def detect_beaconing(packets: list) -> list[Finding]:
    """
    NET-004: Beaconing detection.
    Malware C2 channels often 'beacon' — making connections to the same external
    host at regular intervals. We detect this by looking for repeated connections
    from a single internal IP to the same external IP with low inter-arrival variance.
    """
    findings = []

    # { (src, dst, dport) -> [timestamps] }
    connection_times: dict[tuple, list[float]] = defaultdict(list)

    for pkt in packets:
        if IP in pkt and TCP in pkt:
            tcp = pkt[TCP]
            # Only track SYN packets (new connections)
            if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                src = pkt[IP].src
                dst = pkt[IP].dst
                if is_private(src) and not is_private(dst):
                    connection_times[(src, dst, tcp.dport)].append(float(pkt.time))

    MIN_CONNECTIONS = 5  # need at least this many to call it beaconing

    for (src, dst, dport), times in connection_times.items():
        if len(times) < MIN_CONNECTIONS:
            continue

        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        mean_interval = sum(intervals) / len(intervals)

        # Coefficient of variation: low value = very regular intervals = beaconing
        if mean_interval == 0:
            continue
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_interval  # coefficient of variation

        BEACON_CV_THRESHOLD = 0.3  # very regular if CV < 0.3

        if cv < BEACON_CV_THRESHOLD:
            findings.append(Finding(
                rule_id="NET-004",
                severity=HIGH,
                title=f"Beaconing behaviour: {src} → {dst}:{dport}",
                description=(
                    "An internal host is making repeated, highly regular connections to an "
                    "external IP. This pattern is characteristic of malware C2 (command and "
                    "control) beaconing — the implant checks in with its controller on a timer."
                ),
                src=src,
                detail=(
                    f"{len(times)} connections | Mean interval: {mean_interval:.1f}s | "
                    f"CV: {cv:.3f} (lower = more regular) | Destination: {dst}:{dport}"
                ),
                remediation=(
                    "Isolate the source host immediately. Capture memory for forensic analysis. "
                    "Block the destination IP at the perimeter firewall. "
                    "Investigate with EDR tooling for malware persistence mechanisms."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1071/",
                    "https://www.mandiant.com/resources/blog/beacon-detection",
                ],
            ))

    return findings


def detect_large_external_transfers(packets: list) -> list[Finding]:
    """
    NET-005: Large outbound data transfers to external IPs.
    Potential data exfiltration indicator.
    """
    findings = []

    # { (src, dst) -> byte count }
    transfer_bytes: dict[tuple, int] = defaultdict(int)

    for pkt in packets:
        if IP in pkt and Raw in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            if is_private(src) and not is_private(dst):
                transfer_bytes[(src, dst)] += len(pkt[Raw].load)

    EXFIL_THRESHOLD_MB = 1  # flag transfers over 1 MB in a single capture

    for (src, dst), byte_count in transfer_bytes.items():
        mb = byte_count / (1024 * 1024)
        if mb >= EXFIL_THRESHOLD_MB:
            findings.append(Finding(
                rule_id="NET-005",
                severity=MEDIUM,
                title=f"Large outbound transfer: {src} → {dst}",
                description=(
                    "A significant volume of data was transferred from an internal host "
                    "to an external destination. This may indicate data exfiltration, "
                    "a misconfigured backup, or a cloud sync tool."
                ),
                src=src,
                detail=f"{mb:.2f} MB transferred from {src} to {dst}",
                remediation=(
                    "Verify the destination is an authorised service. Review DLP (Data Loss "
                    "Prevention) policies. Correlate with endpoint activity to determine "
                    "what data was sent."
                ),
                references=[
                    "https://attack.mitre.org/techniques/T1041/",
                ],
            ))

    return findings


# ── Orchestrator ─────────────────────────────────────────────────────────────

DETECTORS = [
    detect_port_scan,
    detect_cleartext_credentials,
    detect_dns_anomalies,
    detect_beaconing,
    detect_large_external_transfers,
]


def analyze(pcap_path: str) -> list[Finding]:
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        print(f"  ERROR reading {pcap_path}: {e}", file=sys.stderr)
        return []

    findings: list[Finding] = []
    for detector in DETECTORS:
        findings.extend(detector(packets))

    return findings


# ── Output helpers ────────────────────────────────────────────────────────────

def print_banner():
    c = COLOURS
    print(f"""
{c['BOLD']}{c['HEADER']}╔══════════════════════════════════════════════════════╗
║       Network Traffic Analyzer  — v1.0               ║
║       Cloud Security Engineering Portfolio           ║
╚══════════════════════════════════════════════════════╝{c['RESET']}
""")


def print_findings(findings: list[Finding]):
    if not findings:
        print(f"  {COLOURS['GREEN']}✔  No suspicious traffic detected.{COLOURS['RESET']}\n")
        return

    for f in sorted(findings, key=lambda x: SEVERITY_ORDER[x.severity]):
        col = COLOURS.get(f.severity, "")
        rst = COLOURS["RESET"]
        bld = COLOURS["BOLD"]
        print(f"  {col}{bld}[{f.severity}]{rst} {bld}{f.rule_id}: {f.title}{rst}")
        print(f"    Source     : {f.src}")
        print(f"    Detail     : {f.detail}")
        print(f"    Remediation: {f.remediation}")
        if f.references:
            print(f"    MITRE/Ref  : {f.references[0]}")
        print()


def print_summary(findings: list[Finding]):
    counts = {s: 0 for s in [CRITICAL, HIGH, MEDIUM, LOW, INFO]}
    for f in findings:
        counts[f.severity] += 1

    c = COLOURS
    print(f"\n{c['BOLD']}{'─'*54}")
    print(f"  SUMMARY  ({len(findings)} finding(s))")
    print(f"{'─'*54}{c['RESET']}")
    for sev, count in counts.items():
        col = c.get(sev, "")
        bar = "█" * count if count else "·"
        print(f"  {col}{sev:<10}{c['RESET']}  {count:>3}  {col}{bar}{c['RESET']}")
    print()

    if counts[CRITICAL] + counts[HIGH] > 0:
        print(f"  {c['CRITICAL']}{c['BOLD']}⚠  HIGH/CRITICAL findings — investigate immediately!{c['RESET']}\n")


def save_json_report(findings: list[Finding], out_path: str):
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"  {COLOURS['GREEN']}✔  JSON report saved → {out_path}{COLOURS['RESET']}\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analyze .pcap network captures for suspicious behaviour.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python traffic_analyzer.py --file capture.pcap
  python traffic_analyzer.py --file capture.pcap --output report.json
  python traffic_analyzer.py --file capture.pcap --min-severity HIGH --no-colour
        """,
    )
    parser.add_argument("--file",         required=True, metavar="FILE", help=".pcap file to analyze")
    parser.add_argument("--output",       metavar="FILE", help="Save findings as JSON")
    parser.add_argument("--no-colour",    action="store_true")
    parser.add_argument("--min-severity", choices=[CRITICAL, HIGH, MEDIUM, LOW, INFO],
                        default=INFO, help="Only show findings at or above this severity")
    args = parser.parse_args()

    if args.no_colour:
        for k in COLOURS:
            COLOURS[k] = ""

    print_banner()
    print(f"{COLOURS['BOLD']}Analyzing: {args.file}{COLOURS['RESET']}\n")

    findings = analyze(args.file)
    threshold = SEVERITY_ORDER[args.min_severity]
    visible = [f for f in findings if SEVERITY_ORDER[f.severity] <= threshold]
    print_findings(visible)
    print_summary(findings)

    if args.output:
        save_json_report(findings, args.output)

    has_blocking = any(SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[HIGH] for f in findings)
    sys.exit(1 if has_blocking else 0)


if __name__ == "__main__":
    main()
