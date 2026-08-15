#!/usr/bin/env python3
"""
IAM Policy Auditor
==================
A cloud security tool that analyzes AWS IAM policies (in JSON format)
for common misconfigurations and privilege escalation risks.

Usage:
    python iam_auditor.py --file policy.json
    python iam_auditor.py --dir ./policies/
    python iam_auditor.py --file policy.json --output report.json

Author: Security Engineering Portfolio
"""

import json
import argparse
import sys
import os
from datetime import datetime
from typing import Any
from dataclasses import dataclass, field, asdict


# ── Severity levels ─────────────────────────────────────────────────────────

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

# ANSI colours for terminal output
COLOURS = {
    CRITICAL: "\033[91m",   # bright red
    HIGH:     "\033[31m",   # red
    MEDIUM:   "\033[33m",   # yellow
    LOW:      "\033[36m",   # cyan
    INFO:     "\033[37m",   # white
    "RESET":  "\033[0m",
    "BOLD":   "\033[1m",
    "GREEN":  "\033[92m",
    "HEADER": "\033[95m",
}


# ── Finding dataclass ────────────────────────────────────────────────────────

@dataclass
class Finding:
    rule_id:     str
    severity:    str
    title:       str
    description: str
    resource:    str
    detail:      str
    remediation: str
    references:  list[str] = field(default_factory=list)

    def colour(self) -> str:
        return COLOURS.get(self.severity, "")


# ── Individual check functions ───────────────────────────────────────────────

def check_wildcard_actions(statement: dict, resource_path: str) -> list[Finding]:
    """IAM-001: Detect Action: '*' (all actions allowed)."""
    findings = []
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    effect = statement.get("Effect", "")
    if effect != "Allow":
        return findings

    for action in actions:
        if action == "*":
            findings.append(Finding(
                rule_id="IAM-001",
                severity=CRITICAL,
                title="Wildcard action '*' grants all AWS permissions",
                description=(
                    "Allowing Action: '*' grants the principal unrestricted access to "
                    "every AWS service and operation. This violates the principle of "
                    "least privilege and is the most common path to full account compromise."
                ),
                resource=resource_path,
                detail=f"Statement Sid: {statement.get('Sid', '<no sid>')} | Action: *",
                remediation=(
                    "Replace '*' with only the specific actions the principal requires. "
                    "Use IAM Access Analyzer to generate a least-privilege policy from "
                    "actual access patterns."
                ),
                references=[
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
                    "https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_GeneratePolicy.html",
                ],
            ))
    return findings


def check_wildcard_resources(statement: dict, resource_path: str) -> list[Finding]:
    """IAM-002: Detect Resource: '*' on sensitive service actions."""
    findings = []
    effect = statement.get("Effect", "")
    if effect != "Allow":
        return findings

    resources = statement.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]

    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    SENSITIVE_PREFIXES = (
        "iam:", "sts:", "s3:", "ec2:", "lambda:", "rds:",
        "secretsmanager:", "kms:", "ssm:", "cloudtrail:",
    )

    sensitive_actions = [
        a for a in actions
        if any(a.lower().startswith(p) for p in SENSITIVE_PREFIXES) or a == "*"
    ]

    if "*" in resources and sensitive_actions:
        findings.append(Finding(
            rule_id="IAM-002",
            severity=HIGH,
            title="Sensitive actions allowed on all resources (Resource: '*')",
            description=(
                "Granting sensitive service actions on Resource: '*' means the principal "
                "can operate on every resource in those services, including ones created "
                "in the future. This significantly increases blast radius if credentials "
                "are compromised."
            ),
            resource=resource_path,
            detail=(
                f"Sid: {statement.get('Sid', '<no sid>')} | "
                f"Sensitive actions: {', '.join(sensitive_actions[:5])}"
                f"{'...' if len(sensitive_actions) > 5 else ''}"
            ),
            remediation=(
                "Scope Resource to specific ARNs (e.g. arn:aws:s3:::my-bucket/*). "
                "Use resource tags and IAM conditions to further restrict access."
            ),
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html",
            ],
        ))
    return findings


def check_privilege_escalation(statement: dict, resource_path: str) -> list[Finding]:
    """IAM-003: Detect known privilege-escalation action combinations."""
    findings = []
    effect = statement.get("Effect", "")
    if effect != "Allow":
        return findings

    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    actions_lower = {a.lower() for a in actions}

    # Pairs/sets of actions that together allow privilege escalation
    ESCALATION_VECTORS = [
        {
            "actions": {"iam:createpolicyversion"},
            "title":   "Can overwrite IAM policy versions → escalate to admin",
            "detail":  "CreatePolicyVersion allows replacing a managed policy with one that grants AdministratorAccess.",
        },
        {
            "actions": {"iam:attachuserpolicy", "iam:attachrolepolicy", "iam:attachgrouppolicy"},
            "title":   "Can attach arbitrary policies → privilege escalation",
            "detail":  "Attaching an existing high-privilege policy (e.g. AdministratorAccess) to any principal.",
            "any":     True,
        },
        {
            "actions": {"iam:putuserPolicy", "iam:putrolepolicy", "iam:putgrouppolicy"},
            "title":   "Can inline arbitrary policies → privilege escalation",
            "detail":  "Inline policy writes are equivalent to managed policy attachment for escalation purposes.",
            "any":     True,
        },
        {
            "actions": {"iam:createrole", "iam:passrole"},
            "title":   "CreateRole + PassRole → can create and assume privileged roles",
            "detail":  "Combined, these allow creating a new role with arbitrary trust/permissions then passing it to a service.",
        },
        {
            "actions": {"lambda:createfunction", "lambda:invokefunction", "iam:passrole"},
            "title":   "Lambda CreateFunction + InvokeFunction + PassRole → code execution as high-priv role",
            "detail":  "Classic serverless privilege escalation: deploy a function with a high-priv role, then invoke it.",
        },
        {
            "actions": {"iam:createaccesskey"},
            "title":   "Can create access keys for other IAM users",
            "detail":  "CreateAccessKey on any user (without resource scoping) allows creating long-lived credentials for admin users.",
        },
        {
            "actions": {"sts:assumerole"},
            "title":   "Broad AssumeRole on all resources",
            "detail":  "Combined with Resource: '*', this allows assuming any role in the account, including admin roles.",
        },
    ]

    for vector in ESCALATION_VECTORS:
        required = {a.lower() for a in vector["actions"]}
        any_match = vector.get("any", False)

        matched = (
            bool(required & actions_lower)  # at least one
            if any_match
            else required.issubset(actions_lower) or "*" in actions_lower
        )

        if matched:
            findings.append(Finding(
                rule_id="IAM-003",
                severity=CRITICAL,
                title=f"Privilege escalation vector: {vector['title']}",
                description=(
                    "This policy grants actions that, individually or combined, enable "
                    "a principal to elevate their own privileges or those of another "
                    "principal — potentially reaching AdministratorAccess."
                ),
                resource=resource_path,
                detail=vector["detail"],
                remediation=(
                    "Remove the escalation actions or tightly scope them with "
                    "Condition keys (e.g. iam:PermissionsBoundary, aws:RequestedRegion). "
                    "Refer to the AWS privilege escalation research by Rhino Security."
                ),
                references=[
                    "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/",
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
                ],
            ))

    return findings


def check_missing_mfa_condition(statement: dict, resource_path: str) -> list[Finding]:
    """IAM-004: Sensitive actions allowed without MFA condition."""
    findings = []
    effect = statement.get("Effect", "")
    if effect != "Allow":
        return findings

    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    SENSITIVE = {
        "iam:deleteuser", "iam:deletepolicy", "iam:detachuserpolicy",
        "s3:deletebucket", "ec2:terminateinstances", "rds:deletedbinstance",
        "sts:assumerole",
    }
    actions_lower = {a.lower() for a in actions}
    matched = SENSITIVE & actions_lower

    condition = statement.get("Condition", {})
    has_mfa = any(
        "mfa" in str(k).lower() or "mfa" in str(v).lower()
        for k, v in condition.items()
    )

    if matched and not has_mfa:
        findings.append(Finding(
            rule_id="IAM-004",
            severity=MEDIUM,
            title="Destructive/sensitive actions lack MFA enforcement condition",
            description=(
                "These sensitive or destructive actions are allowed without requiring "
                "the caller to have authenticated with MFA. If static credentials are "
                "leaked, an attacker could perform these actions."
            ),
            resource=resource_path,
            detail=f"Actions without MFA condition: {', '.join(sorted(matched))}",
            remediation=(
                'Add a Condition: {"Bool": {"aws:MultiFactorAuthPresent": "true"}} '
                "to any statement containing destructive or sensitive actions."
            ),
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html",
            ],
        ))

    return findings


def check_notaction(statement: dict, resource_path: str) -> list[Finding]:
    """IAM-005: Use of NotAction (denies everything except listed actions — often misconfigured)."""
    findings = []
    if "NotAction" in statement and statement.get("Effect") == "Allow":
        not_actions = statement["NotAction"]
        if isinstance(not_actions, str):
            not_actions = [not_actions]
        findings.append(Finding(
            rule_id="IAM-005",
            severity=HIGH,
            title="NotAction with Allow effect grants all actions except those listed",
            description=(
                "NotAction + Allow is a common misconfiguration. It allows every AWS "
                "action EXCEPT the ones listed — which is the opposite of what most "
                "authors intend. This is almost always broader than intended."
            ),
            resource=resource_path,
            detail=f"NotAction excludes only: {not_actions}",
            remediation=(
                "Replace NotAction+Allow with an explicit Action+Allow listing only "
                "what the principal needs. NotAction is rarely the right choice."
            ),
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html",
            ],
        ))
    return findings


def check_allow_all_principals(statement: dict, resource_path: str) -> list[Finding]:
    """IAM-006: Resource-based policies with Principal: '*' (public access)."""
    findings = []
    effect = statement.get("Effect", "Allow")
    principal = statement.get("Principal", None)

    if principal is None:
        return findings

    if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
        condition = statement.get("Condition", {})
        if not condition:
            findings.append(Finding(
                rule_id="IAM-006",
                severity=CRITICAL,
                title="Principal: '*' with no Condition — resource is publicly accessible",
                description=(
                    "A resource-based policy (S3 bucket policy, SQS policy, etc.) with "
                    "Principal: '*' and no Condition block allows any AWS account, "
                    "unauthenticated user, or anonymous internet request to perform the "
                    "allowed actions. This is a data exposure risk."
                ),
                resource=resource_path,
                detail="Principal: * | No restricting Condition block present",
                remediation=(
                    "Either restrict Principal to specific account ARNs, or add a "
                    "Condition such as aws:SourceAccount, aws:SourceArn, or "
                    "aws:PrincipalOrgID to limit the audience."
                ),
                references=[
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html",
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                ],
            ))
    return findings


def check_s3_public_actions(statement: dict, resource_path: str) -> list[Finding]:
    """IAM-007: S3 GetObject/ListBucket on public principal."""
    findings = []
    principal = statement.get("Principal", None)
    effect = statement.get("Effect", "")
    if principal is None or effect != "Allow":
        return findings

    if principal != "*" and principal != {"AWS": "*"}:
        return findings

    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    PUBLIC_S3 = {"s3:getobject", "s3:listbucket", "s3:getbucketacl", "s3:listallmybuckets"}
    matched = {a.lower() for a in actions} & PUBLIC_S3
    if matched:
        findings.append(Finding(
            rule_id="IAM-007",
            severity=HIGH,
            title="S3 data-read actions allowed for all principals (potential data leak)",
            description=(
                "Public read actions on an S3 bucket allow anyone on the internet to "
                "list or download bucket contents. This is one of the most common "
                "causes of large-scale cloud data breaches."
            ),
            resource=resource_path,
            detail=f"Public S3 actions: {', '.join(sorted(matched))}",
            remediation=(
                "Enable S3 Block Public Access at the account and bucket level. "
                "Use pre-signed URLs or CloudFront OAC for serving content publicly."
            ),
            references=[
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
            ],
        ))
    return findings


# ── Orchestrator ─────────────────────────────────────────────────────────────

CHECKS = [
    check_wildcard_actions,
    check_wildcard_resources,
    check_privilege_escalation,
    check_missing_mfa_condition,
    check_notaction,
    check_allow_all_principals,
    check_s3_public_actions,
]


def audit_policy(policy: dict, source_name: str) -> list[Finding]:
    """Run all checks against a parsed IAM policy document."""
    findings: list[Finding] = []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for i, stmt in enumerate(statements):
        sid = stmt.get("Sid", f"Statement[{i}]")
        resource_path = f"{source_name} → {sid}"
        for check_fn in CHECKS:
            findings.extend(check_fn(stmt, resource_path))

    return findings


def load_policy_file(path: str) -> dict | None:
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"  ⚠  Could not parse {path}: {e}", file=sys.stderr)
        return None
    except OSError as e:
        print(f"  ⚠  Could not read {path}: {e}", file=sys.stderr)
        return None


# ── Output formatters ────────────────────────────────────────────────────────

def print_banner():
    c = COLOURS
    print(f"""
{c['BOLD']}{c['HEADER']}╔══════════════════════════════════════════════════════╗
║          IAM Policy Auditor  — v1.0                  ║
║          Cloud Security Engineering Portfolio        ║
╚══════════════════════════════════════════════════════╝{c['RESET']}
""")


def print_findings(findings: list[Finding]):
    if not findings:
        print(f"  {COLOURS['GREEN']}✔  No issues found.{COLOURS['RESET']}\n")
        return

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
    for f in sorted_findings:
        col = f.colour()
        rst = COLOURS["RESET"]
        bld = COLOURS["BOLD"]
        print(f"  {col}{bld}[{f.severity}]{rst} {bld}{f.rule_id}: {f.title}{rst}")
        print(f"    Resource : {f.resource}")
        print(f"    Detail   : {f.detail}")
        print(f"    Fix      : {f.remediation}")
        if f.references:
            print(f"    Ref      : {f.references[0]}")
        print()


def print_summary(all_findings: list[Finding], files_scanned: int):
    counts = {s: 0 for s in [CRITICAL, HIGH, MEDIUM, LOW, INFO]}
    for f in all_findings:
        counts[f.severity] += 1

    c = COLOURS
    print(f"\n{c['BOLD']}{'─'*54}")
    print(f"  SUMMARY  ({files_scanned} file(s) scanned, {len(all_findings)} finding(s))")
    print(f"{'─'*54}{c['RESET']}")
    for sev, count in counts.items():
        col = c.get(sev, "")
        bar = "█" * count if count else "·"
        print(f"  {col}{sev:<10}{c['RESET']}  {count:>3}  {col}{bar}{c['RESET']}")
    print()

    if counts[CRITICAL] > 0:
        print(f"  {c['CRITICAL']}{c['BOLD']}⚠  CRITICAL issues found — remediate immediately!{c['RESET']}\n")


def save_json_report(findings: list[Finding], out_path: str):
    report = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    with open(out_path, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"  {COLOURS['GREEN']}✔  JSON report saved → {out_path}{COLOURS['RESET']}\n")


# ── CLI entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Audit AWS IAM policy JSON files for security misconfigurations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python iam_auditor.py --file policy.json
  python iam_auditor.py --dir ./policies/ --output report.json
  python iam_auditor.py --file policy.json --no-colour
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file", metavar="FILE", help="Single policy JSON file to audit")
    group.add_argument("--dir",  metavar="DIR",  help="Directory of policy JSON files to audit")
    parser.add_argument("--output",    metavar="FILE", help="Save findings as JSON report")
    parser.add_argument("--no-colour", action="store_true", help="Disable ANSI colour output")
    parser.add_argument("--min-severity", choices=[CRITICAL, HIGH, MEDIUM, LOW, INFO],
                        default=INFO, help="Only show findings at or above this severity")
    args = parser.parse_args()

    if args.no_colour:
        for k in COLOURS:
            COLOURS[k] = ""

    print_banner()

    # Collect files to scan
    files: list[str] = []
    if args.file:
        files = [args.file]
    else:
        for fname in os.listdir(args.dir):
            if fname.endswith(".json"):
                files.append(os.path.join(args.dir, fname))
        if not files:
            print(f"No JSON files found in {args.dir}", file=sys.stderr)
            sys.exit(1)

    all_findings: list[Finding] = []
    threshold = SEVERITY_ORDER[args.min_severity]

    for fpath in sorted(files):
        print(f"{COLOURS['BOLD']}Scanning: {fpath}{COLOURS['RESET']}")
        policy = load_policy_file(fpath)
        if policy is None:
            continue
        findings = audit_policy(policy, fpath)
        visible = [f for f in findings if SEVERITY_ORDER[f.severity] <= threshold]
        all_findings.extend(findings)
        print_findings(visible)

    print_summary(all_findings, len(files))

    if args.output:
        save_json_report(all_findings, args.output)

    # Exit code: 1 if any HIGH or CRITICAL found (useful for CI pipelines)
    has_blocking = any(SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[HIGH] for f in all_findings)
    sys.exit(1 if has_blocking else 0)


if __name__ == "__main__":
    main()
