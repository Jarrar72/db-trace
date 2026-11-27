"""Candidate remediation templates, Terraform/SQL patch generation, and log-replay verification."""

from __future__ import annotations

import copy
from collections.abc import Callable

from pydantic import BaseModel

from dbtrace.labeling.iam_eval import evaluate_iam_action
from dbtrace.labeling.oracle import db_role_can_read_table, enumerate_and_label_paths
from dbtrace.logs.generator import AccessLogEvent
from dbtrace.schema import CloudEnvironment


class RemediationResult(BaseModel):
    fix_id: str
    title: str
    description: str
    patch_snippet: str
    paths_before: int
    paths_after: int
    paths_eliminated: int
    elimination_rate: float
    legit_total: int
    legit_broken: int
    false_breakage_rate: float
    status: str  # "Verified Safe-to-Apply" | "Unsafe (Breaks Legitimate Traffic)" | "No Impact"


def _fix_enable_imdsv2(env: CloudEnvironment) -> tuple[CloudEnvironment, str]:
    fixed = copy.deepcopy(env)
    for c in fixed.computes:
        if c.kind == "ec2":
            c.imdsv2_required = True
            c.has_app_vuln = False  # IMDSv2 blocks unauthenticated metadata credential theft
    hcl = 'resource "aws_instance" "app" {\n  metadata_options {\n    http_tokens = "required" # Enforce IMDSv2\n  }\n}'
    return fixed, hcl


def _fix_restrict_public_rds(env: CloudEnvironment) -> tuple[CloudEnvironment, str]:
    fixed = copy.deepcopy(env)
    for rds in fixed.rds_instances:
        rds.publicly_accessible = False
    for sg in fixed.security_groups:
        for r in sg.ingress_rules:
            if r.from_port <= 5432 <= r.to_port and r.cidr == "0.0.0.0/0":
                r.cidr = "10.0.0.0/16"
    hcl = 'resource "aws_db_instance" "main" {\n  publicly_accessible = false\n}\n# SG ingress restricted to VPC CIDR 10.0.0.0/16'
    return fixed, hcl


def _fix_scope_iam_privesc(env: CloudEnvironment) -> tuple[CloudEnvironment, str]:
    fixed = copy.deepcopy(env)
    privesc_acts = {
        "iam:PassRole",
        "iam:SetDefaultPolicyVersion",
        "iam:CreatePolicyVersion",
        "iam:AttachRolePolicy",
        "iam:AttachUserPolicy",
        "iam:PutRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "rds:ModifyDBSnapshotAttribute",
    }
    for pol in fixed.policies:
        for stmt in pol.statements:
            if stmt.effect == "Allow":
                stmt.actions = [a for a in stmt.actions if a not in privesc_acts]
    hcl = '# Removed privilege-escalation & snapshot-sharing actions from IAM policy statements'
    return fixed, hcl


def _fix_revoke_pii_grant(env: CloudEnvironment) -> tuple[CloudEnvironment, str]:
    fixed = copy.deepcopy(env)
    for r in fixed.db_roles:
        if not r.is_rds_superuser:
            r.is_superuser = False
    for t in fixed.db_tables:
        if t.sensitivity.value in ("high", "pii"):
            t.grants.clear()
    sql = "REVOKE ALL PRIVILEGES ON TABLE public.customers_pii FROM ro_group;\nALTER ROLE app_service NOSUPERUSER;"
    return fixed, sql


def _fix_revoke_all_db_access_unsafe(env: CloudEnvironment) -> tuple[CloudEnvironment, str]:
    """Overly aggressive fix (blocks legitimate app traffic too) — demonstrates unsafe detection."""
    fixed = copy.deepcopy(env)
    for t in fixed.db_tables:
        t.grants.clear()
    for r in fixed.db_roles:
        if not r.is_rds_superuser:
            r.can_login = False
    sql = "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM app_service; -- WARNING: breaks app traffic"
    return fixed, sql


FIX_LIBRARY: list[tuple[str, str, str, Callable[[CloudEnvironment], tuple[CloudEnvironment, str]]]] = [
    (
        "enable_imdsv2",
        "Enforce IMDSv2 & Patch SSRF Exposure",
        "Requires session-oriented IMDSv2 tokens on EC2 instances, blocking SSRF metadata credential theft.",
        _fix_enable_imdsv2,
    ),
    (
        "restrict_public_rds",
        "Disable Public RDS & Restrict SG 5432",
        "Sets publicly_accessible=false and replaces 0.0.0.0/0 on port 5432 with private VPC CIDR.",
        _fix_restrict_public_rds,
    ),
    (
        "scope_iam_privesc",
        "Remove IAM Privilege-Escalation Actions",
        "Strips iam:PassRole, SetDefaultPolicyVersion, and ModifyDBSnapshotAttribute from non-admin policies.",
        _fix_scope_iam_privesc,
    ),
    (
        "revoke_pii_grant",
        "Revoke Excess PII Table Grants",
        "Removes superfluous SELECT grants on PII tables and drops unnecessary SUPERUSER flags.",
        _fix_revoke_pii_grant,
    ),
    (
        "revoke_all_db_unsafe",
        "Revoke All App DB Grants (Aggressive)",
        "Blocks all application DB logins and table grants — tested to verify safety simulator catches breakage.",
        _fix_revoke_all_db_access_unsafe,
    ),
]


def _replay_logs(env: CloudEnvironment, logs: list[AccessLogEvent]) -> tuple[int, int]:
    """Replay legitimate historical CloudTrail and pgaudit events against an environment."""
    policy_map = {p.id: p for p in env.policies}
    principal_map = {p.id: p for p in env.principals}
    rds_map = {r.id: r for r in env.rds_instances}
    sg_map = {sg.id: sg for sg in env.security_groups}
    role_map = {r.id: r for r in env.db_roles}
    table_map = {t.id: t for t in env.db_tables}

    legit_logs = [ev for ev in logs if ev.is_legitimate]
    broken = 0

    for ev in legit_logs:
        if ev.source == "cloudtrail" and ev.action == "rds-db:connect":
            prin = principal_map.get(ev.principal_id)
            if not prin or not evaluate_iam_action(prin, "rds-db:connect", "*", policy_map):
                broken += 1
        elif ev.source == "pgaudit":
            rds = rds_map.get(ev.rds_id or "")
            db_role = role_map.get(ev.db_role_id or "")
            table = table_map.get(ev.table_id or "")
            if not (rds and db_role and table):
                broken += 1
                continue
            # Check network SG still allows compute SG
            net_ok = True
            if ev.source_sg_id:
                net_ok = any(
                    r.from_port <= rds.port <= r.to_port
                    and (r.source_sg_id == ev.source_sg_id or r.cidr == "0.0.0.0/0")
                    for sg_id in rds.security_group_ids
                    if sg_id in sg_map
                    for r in sg_map[sg_id].ingress_rules
                )
            db_ok = db_role_can_read_table(db_role, table, role_map)
            if not (net_ok and db_ok):
                broken += 1

    return len(legit_logs), broken


def verify_remediation(
    env: CloudEnvironment,
    logs: list[AccessLogEvent],
    fix_id: str,
) -> RemediationResult:
    """Apply a candidate fix to a copy of env, re-evaluate attack paths, and replay logs."""
    entry = next((item for item in FIX_LIBRARY if item[0] == fix_id), None)
    if entry is None:
        raise ValueError(f"Unknown fix_id: {fix_id}")
    _, title, desc, fn = entry

    before_paths = sum(p.label_exploitable for p in enumerate_and_label_paths(env))
    fixed_env, snippet = fn(env)
    after_paths = sum(p.label_exploitable for p in enumerate_and_label_paths(fixed_env))
    eliminated = max(0, before_paths - after_paths)
    elim_rate = round(eliminated / before_paths, 4) if before_paths > 0 else 0.0

    legit_total, legit_broken = _replay_logs(fixed_env, logs)
    break_rate = round(legit_broken / legit_total, 4) if legit_total > 0 else 0.0

    if legit_broken > 0:
        status = "Unsafe (Breaks Legitimate Traffic)"
    elif eliminated > 0:
        status = "Verified Safe-to-Apply"
    else:
        status = "No Impact"

    return RemediationResult(
        fix_id=fix_id,
        title=title,
        description=desc,
        patch_snippet=snippet,
        paths_before=before_paths,
        paths_after=after_paths,
        paths_eliminated=eliminated,
        elimination_rate=elim_rate,
        legit_total=legit_total,
        legit_broken=legit_broken,
        false_breakage_rate=break_rate,
        status=status,
    )


def recommend_remediations(
    env: CloudEnvironment, logs: list[AccessLogEvent]
) -> list[RemediationResult]:
    """Evaluate all candidate fixes and rank safest + highest-impact first."""
    results = [verify_remediation(env, logs, fix_id) for fix_id, _, _, _ in FIX_LIBRARY]
    results.sort(key=lambda r: (r.legit_broken > 0, -r.paths_eliminated, r.false_breakage_rate))
    return results
