# Day 01 — IAM Policy Auditor

**Domain:** Cloud Security  
**Type:** Security Tool  
**Difficulty:** Beginner → Intermediate  
**Language:** Python 3.10+

---

## What This Is

A static analysis tool that parses AWS IAM policy JSON files and flags security misconfigurations before they ever reach production. Think of it as a linter for your IAM policies; it can run locally, in CI/CD pipelines, or as part of a pre-commit hook.

No AWS credentials required. It works entirely on policy JSON files.

---

## Why IAM Security Matters

IAM (Identity and Access Management) is the access control layer for everything in AWS. A misconfigured IAM policy is one of the most common root causes of cloud security incidents: overly permissive roles, public S3 buckets, and privilege escalation paths have all led to major real-world breaches (Capital One 2019, Twitch 2021, and many others).

Security engineers need to understand:
- The principle of least privilege
- How privilege escalation works in AWS
- What makes a policy "public" via resource-based policies
- How to detect and remediate these issues at scale

---

## Rules Implemented

| Rule ID | Severity | What It Detects |
|---------|----------|-----------------|
| IAM-001 | CRITICAL | `Action: "*"` — unrestricted all-service access |
| IAM-002 | HIGH | Sensitive service actions on `Resource: "*"` |
| IAM-003 | CRITICAL | Known privilege escalation vectors (Lambda, PassRole, CreatePolicyVersion, etc.) |
| IAM-004 | MEDIUM | Destructive actions without MFA enforcement condition |
| IAM-005 | HIGH | `NotAction` + `Allow` — typically a misconfiguration granting near-unlimited access |
| IAM-006 | CRITICAL | `Principal: "*"` with no `Condition` — publicly accessible resource |
| IAM-007 | HIGH | S3 read actions on public principal — data exposure risk |

---

## Usage

```bash
# Audit a single policy file
python iam_auditor.py --file my_policy.json

# Audit all policy files in a directory
python iam_auditor.py --dir ./policies/

# Save a machine-readable JSON report
python iam_auditor.py --dir ./policies/ --output report.json

# Only show HIGH and above (useful for CI)
python iam_auditor.py --file policy.json --min-severity HIGH

# Disable colour (for log files)
python iam_auditor.py --file policy.json --no-colour
```

**Exit codes:**
- `0` — No HIGH or CRITICAL findings (safe to pass CI gate)
- `1` — At least one HIGH or CRITICAL finding (blocks deployment)

---

## Example Output (usability and visuals improved by Claude)

Running against the intentionally bad policy in `tests/bad_policy.json`:

```
[CRITICAL] IAM-001: Wildcard action '*' grants all AWS permissions
  Resource : tests/bad_policy.json → AdminWildcard
  Detail   : Statement Sid: AdminWildcard | Action: *
  Fix      : Replace '*' with only the specific actions the principal requires.

[CRITICAL] IAM-003: Privilege escalation vector: Lambda CreateFunction + InvokeFunction + PassRole
  Resource : tests/bad_policy.json → LambdaEscalation
  Detail   : Classic serverless privilege escalation path.

SUMMARY  (3 file(s) scanned, 15 finding(s))
  CRITICAL      8  ████████
  HIGH          6  ██████
  MEDIUM        1  █
```

---

## Concepts Learned

**Principle of Least Privilege** — a principal should have only the permissions it needs to do its job, nothing more. `Action: "*"` is the antithesis of this.

**Privilege Escalation in AWS** — a user with limited permissions can sometimes combine those permissions to grant themselves (or others) elevated access. Classic vectors include:
- `lambda:CreateFunction` + `lambda:InvokeFunction` + `iam:PassRole` → deploy code running as a high-privilege role
- `iam:CreatePolicyVersion` → overwrite an existing policy with an admin-granting one
- `iam:AttachUserPolicy` on `Resource: "*"` → attach `AdministratorAccess` to yourself

**Resource-based policies vs Identity-based policies** — S3 bucket policies are *resource-based*: they include a `Principal` field and can grant access to anonymous internet users. Identity-based policies (attached to roles/users) do not have a `Principal`.

**The NotAction trap** — `Effect: Allow` + `NotAction: [x, y]` means "allow everything EXCEPT x and y". Most policy authors intend this the other way around and should use `Action` instead.

**MFA conditions** — Adding `"Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}` forces the caller to have authenticated with MFA for that specific API call. Essential for destructive operations.

---

## How to Extend This

- Add more IAM-003 privilege escalation vectors (there are ~20+ documented by Rhino Security)
- Add a check for missing `aws:RequestedRegion` condition (prevents actions outside your expected regions)
- Add support for Terraform `.tf` files — parse `aws_iam_policy_document` resources
- Integrate with `pre-commit` hooks so it runs on every `git commit`
- Add a `--fix` mode that suggests corrected JSON

---

## References

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Rhino Security Labs — AWS Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [AWS IAM Access Analyzer](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_GeneratePolicy.html)
- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Capital One Breach Analysis](https://krebsonsecurity.com/2019/07/capital-one-data-theft-impacts-106m-people/)
