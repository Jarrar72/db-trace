"""Extract tabular configuration & behavioral features for each AccessPathRecord."""

from __future__ import annotations

import pandas as pd

from dbtrace.labeling.iam_eval import evaluate_iam_action, get_principal_statements, has_privesc_capability
from dbtrace.labeling.oracle import db_role_can_read_table, effective_db_role_closure
from dbtrace.logs.generator import AccessLogEvent
from dbtrace.schema import AccessPathRecord, CloudEnvironment, SensitivityLevel

FEATURE_COLUMNS = [
    "entry_has_mfa",
    "entry_is_external",
    "iam_wildcard_actions",
    "iam_has_privesc",
    "iam_has_explicit_deny",
    "iam_rds_connect_allowed",
    "iam_snapshot_modify",
    "has_compute",
    "compute_is_ec2",
    "compute_imdsv2_required",
    "compute_public_ip",
    "compute_has_app_vuln",
    "compute_leaked_creds",
    "rds_publicly_accessible",
    "rds_encrypted",
    "rds_iam_auth",
    "rds_public_snapshot",
    "sg_open_to_world_5432",
    "sg_allows_compute_5432",
    "subnet_route_to_igw",
    "db_role_can_login",
    "db_role_is_superuser",
    "db_role_inheritance_depth",
    "db_table_is_sensitive",
    "db_role_has_select_grant",
    "via_internet",
    "via_snapshot",
    "log_legit_connect_count",
    "log_legit_select_count",
]


def extract_path_features(
    env: CloudEnvironment,
    paths: list[AccessPathRecord],
    logs: list[AccessLogEvent] | None = None,
) -> pd.DataFrame:
    """Compute tabular feature matrix for all candidate paths in an environment."""
    policy_map = {p.id: p for p in env.policies}
    principal_map = {p.id: p for p in env.principals}
    compute_map = {c.id: c for c in env.computes}
    sg_map = {sg.id: sg for sg in env.security_groups}
    subnet_map = {s.id: s for s in env.subnets}
    rds_map = {r.id: r for r in env.rds_instances}
    role_map = {r.id: r for r in env.db_roles}
    table_map = {t.id: t for t in env.db_tables}

    ct_counts: dict[str, int] = {}
    pg_counts: dict[tuple[str, str], int] = {}
    for ev in logs or []:
        if ev.is_legitimate and ev.source == "cloudtrail":
            ct_counts[ev.principal_id] = ct_counts.get(ev.principal_id, 0) + 1
        elif ev.is_legitimate and ev.source == "pgaudit" and ev.db_role_id and ev.table_id:
            key = (ev.db_role_id, ev.table_id)
            pg_counts[key] = pg_counts.get(key, 0) + 1

    rows = []
    for p in paths:
        entry = principal_map[p.entry_principal_id]
        target_iam = principal_map.get(p.target_role_id, entry)
        comp = compute_map.get(p.compute_id) if p.compute_id else None
        rds = rds_map[p.rds_id]
        db_role = role_map.get(p.db_role_id)
        table = table_map[p.db_table_id]

        stmts = get_principal_statements(entry, policy_map) + get_principal_statements(target_iam, policy_map)
        wildcard = any("*" in s.actions or any(a.endswith(":*") for a in s.actions) for s in stmts if s.effect == "Allow")
        has_deny = any(s.effect == "Deny" for s in stmts)

        rds_sgs = [sg_map[sgid] for sgid in rds.security_group_ids if sgid in sg_map]
        open_5432 = any(
            r.from_port <= rds.port <= r.to_port and r.cidr == "0.0.0.0/0"
            for sg in rds_sgs
            for r in sg.ingress_rules
        )
        allows_comp_5432 = False
        if comp:
            allows_comp_5432 = any(
                r.from_port <= rds.port <= r.to_port and (r.source_sg_id in comp.security_group_ids or r.cidr == "0.0.0.0/0")
                for sg in rds_sgs
                for r in sg.ingress_rules
            )

        rds_sub = subnet_map.get(rds.subnet_id)
        comp_sub = subnet_map.get(comp.subnet_id) if comp else None
        route_igw = bool((rds_sub and rds_sub.route_to_igw) or (comp_sub and comp_sub.route_to_igw))

        closure = effective_db_role_closure(db_role, role_map) if db_role else set()
        can_select = db_role_can_read_table(db_role, table, role_map) if db_role else False

        rows.append({
            "path_id": p.path_id,
            "env_id": p.env_id,
            "label_exploitable": p.label_exploitable,
            "entry_has_mfa": int(entry.has_mfa),
            "entry_is_external": int(entry.is_external_entry),
            "iam_wildcard_actions": int(wildcard),
            "iam_has_privesc": int(has_privesc_capability(entry, policy_map)),
            "iam_has_explicit_deny": int(has_deny),
            "iam_rds_connect_allowed": int(
                evaluate_iam_action(target_iam, "rds-db:connect", "*", policy_map)
                or evaluate_iam_action(entry, "rds-db:connect", "*", policy_map)
            ),
            "iam_snapshot_modify": int(evaluate_iam_action(entry, "rds:ModifyDBSnapshotAttribute", "*", policy_map)),
            "has_compute": int(comp is not None),
            "compute_is_ec2": int(comp is not None and comp.kind == "ec2"),
            "compute_imdsv2_required": int(comp.imdsv2_required if comp else 1),
            "compute_public_ip": int(comp.has_public_ip if comp else 0),
            "compute_has_app_vuln": int(comp.has_app_vuln if comp else 0),
            "compute_leaked_creds": int(bool(comp and db_role and comp.leaked_db_role_id == db_role.id)),
            "rds_publicly_accessible": int(rds.publicly_accessible),
            "rds_encrypted": int(rds.encrypted),
            "rds_iam_auth": int(rds.iam_auth_enabled),
            "rds_public_snapshot": int(rds.has_public_snapshot),
            "sg_open_to_world_5432": int(open_5432),
            "sg_allows_compute_5432": int(allows_comp_5432),
            "subnet_route_to_igw": int(route_igw),
            "db_role_can_login": int(db_role.can_login if db_role else 0),
            "db_role_is_superuser": int(bool(db_role and (db_role.is_superuser or db_role.is_rds_superuser))),
            "db_role_inheritance_depth": max(0, len(closure) - 1),
            "db_table_is_sensitive": int(table.sensitivity in (SensitivityLevel.HIGH, SensitivityLevel.PII)),
            "db_role_has_select_grant": int(can_select),
            "via_internet": int(p.via_internet),
            "via_snapshot": int(p.via_snapshot),
            "log_legit_connect_count": ct_counts.get(target_iam.id, 0),
            "log_legit_select_count": pg_counts.get((db_role.id, table.id), 0) if db_role else 0,
        })

    return pd.DataFrame(rows)
