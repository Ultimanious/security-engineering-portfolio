# Security Engineering Portfolio

A self-directed, project-driven curriculum in security engineering — built one day at a time. Each entry is a working tool or documented writeup, created to develop real skills and demonstrate them to potential employers.

**Focus areas:** Cloud Security · Security Engineering · Network Security  
**Level:** Beginner → Intermediate → Advanced

---

## Projects

| # | Project | Domain | Type | Skills Demonstrated |
|---|---------|--------|------|---------------------|
| 01 | [IAM Policy Auditor](projects/01-iam-policy-auditor/) | ☁️ Cloud | Tool | Least privilege, privilege escalation, static analysis |
| 02 | Network Traffic Analyzer | 🌐 Network | Tool | Packet parsing, protocol analysis, anomaly detection |
| 03 | Secrets Scanner | 🔐 SecEng | Tool | Regex, entropy analysis, CI/CD integration |
| 04 | Cloud Logging Monitor | ☁️ Cloud | Tool | CloudTrail, SIEM concepts, detection engineering |
| 05 | JWT Security Toolkit | 🔐 SecEng | Tool | Auth flows, algorithm confusion attacks, token forgery |
| 06 | TLS Certificate Auditor | 🌐 Network | Tool | PKI, cipher suites, certificate chain validation |

*New projects added regularly. Greyed-out rows are upcoming.*

---

## Curriculum Roadmap

### Phase 1 — Cloud Security Foundations (Projects 01–04)
The cloud is where most modern infrastructure lives, and IAM misconfigurations are the #1 cause of cloud breaches. This phase builds a solid foundation in AWS security primitives.

- **IAM & Access Control** — least privilege, privilege escalation, resource policies
- **Secrets Management** — detecting hardcoded credentials, secrets sprawl
- **Logging & Detection** — CloudTrail, GuardDuty concepts, detection engineering
- **Data Exposure** — S3 public access, encryption at rest vs in transit

### Phase 2 — Security Engineering (Projects 05–08)
Security engineering means building security *into* systems — secure authentication, safe cryptography, and hardened APIs.

- **Authentication & Authorization** — JWT, OAuth 2.0, session management
- **Cryptography in Practice** — TLS, hashing, common implementation mistakes
- **Secure SDLC** — SAST, dependency scanning, threat modeling
- **API Security** — OWASP API Top 10, rate limiting, input validation

### Phase 3 — Network Security (Projects 09–12)
Network-level visibility is fundamental. This phase covers traffic analysis, protocol-level attacks, and detection.

- **Packet Analysis** — TCP/IP, protocol dissection with Scapy/dpkt
- **Network Scanning** — building a port scanner, service fingerprinting
- **Intrusion Detection** — signature-based and anomaly-based detection
- **Firewall & VPC Security** — security group analysis, network ACLs

### Phase 4 — CTF Writeups
Alongside tooling, applying skills to Capture the Flag challenges. Each writeup documents methodology, not just the answer.

---

## How This Repo Is Structured

```
security-portfolio/
├── projects/
│   └── XX-project-name/
│       ├── README.md        ← writeup: what, why, concepts, how to run
│       ├── *.py / *.go      ← the actual tool
│       └── tests/           ← sample data for testing
├── writeups/
│   └── ctf-name/
│       └── README.md        ← CTF challenge writeup
└── notes/
    └── topic.md             ← running notes on concepts
```

Each project README covers: what the tool does, what security concept it addresses, how to run it, what I learned, and how it could be extended.

---

## Skills Index

| Skill | Projects |
|-------|----------|
| Python | 01, 02, 03, 04 |
| AWS / Cloud Security | 01, 04 |
| Static Analysis | 01, 03 |
| Network Protocols | 02, 06 |
| Cryptography | 05, 06 |
| CI/CD Integration | 01, 03 |
| Detection Engineering | 04 |

---

## Running the Tools

All tools are standalone Python scripts unless otherwise noted. No special setup required beyond:

```bash
pip install -r requirements.txt   # if a project has one
python <tool>.py --help
```

---

*Built with daily sessions alongside Claude (Anthropic). Each project is independently functional and documented.*
