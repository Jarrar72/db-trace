"""What-If Security Simulation Engine for DB-TRACE.

Allows interactive modification of cloud and database security controls
and evaluates real-time risk delta, eliminated attack paths, and operational breakage.
"""

from __future__ import annotations

import copy
from typing import Any

from pydantic import BaseModel

from dbtrace.graph.builder import graph_to_cytoscape_elements
from dbtrace.labeling.oracle import db_role_can_read_table, enumerate_and_label_paths
from dbtrace.logs.generator import AccessLogEvent
from dbtrace.schema import CloudEnvironment


class WhatIfToggles(BaseModel):
    port_5432_open: bool = True
    iam_admin_access: bool = True
    db_role_inheritance: bool = True
    rds_public: bool = True
    imdsv2_required: bool = False


class WhatIfSimulationResult(BaseModel):
    baseline_risk_score: float
    simulated_risk_score: float
    risk_delta: float
    paths_before: int
    paths_after: int
    paths_eliminated: int
    elimination_rate: float
    legit_total: int
    legit_broken: int
    false_breakage_rate: float
    status: str
    impact_narrative: str
    active_exploitable_path_ids: list[str]
    graph_elements: dict[str, Any]


def simulate_what_if(
    env: CloudEnvironment,
    toggles: WhatIfToggles,
    logs: list[AccessLogEvent] | None = None,
) -> WhatIfSimulationResult:
    """Simulate the effect of virtual security policy changes on the cloud environment."""
    baseline_paths = enumerate_and_label_paths(env)
    baseline_exploitable = [p for p in baseline_paths if p.label_exploitable == 1]
    baseline_cnt = len(baseline_exploitable)
    baseline_score = 100.0 if baseline_cnt > 0 else 12.0

    # Clone environment to mutate in-memory
    sim_env = copy.deepcopy(env)
    changes_made: list[str] = []

    # 1. Port 5432 ingress restriction
    if not toggles.port_5432_open:
        for sg in sim_env.security_groups:
            # Sever all ingress rules covering port 5432
            sg.ingress_rules = [r for r in sg.ingress_rules if not (r.from_port <= 5432 <= r.to_port)]
        changes_made.append("Blocked all ingress rules on TCP port 5432 across all Security Groups")

    # 2. IAM Admin / Privesc revocation
    if not toggles.iam_admin_access:
        privesc_acts = {
            "*",
            "iam:*",
            "iam:PassRole",
            "iam:CreatePolicyVersion",
            "iam:SetDefaultPolicyVersion",
            "iam:AttachRolePolicy",
            "iam:AttachUserPolicy",
            "sts:AssumeRole",
            "rds:ModifyDBSnapshotAttribute",
        }
        for pol in sim_env.policies:
            for stmt in pol.statements:
                if stmt.effect == "Allow":
                    stmt.actions = [a for a in stmt.actions if a not in privesc_acts and a != "*"]
        changes_made.append("Revoked IAM wildcard actions (*) and privilege escalation primitives from instance policies")

    # 3. Database role inheritance
    if not toggles.db_role_inheritance:
        for role in sim_env.db_roles:
            role.member_of = []
            if not role.is_rds_superuser:
                role.is_superuser = False
        changes_made.append("Disabled transitive role inheritance (NOINHERIT) and stripped non-admin SUPERUSER flags")

    # 4. RDS Public Accessibility
    if not toggles.rds_public:
        for rds in sim_env.rds_instances:
            rds.publicly_accessible = False
        changes_made.append("Set RDS publicly_accessible = false to enforce private VPC endpoint isolation")

    # 5. EC2 IMDSv2 Enforcement
    if toggles.imdsv2_required:
        for c in sim_env.computes:
            if c.kind == "ec2":
                c.imdsv2_required = True
                c.has_app_vuln = False
        changes_made.append("Enforced IMDSv2 (http_tokens = 'required') on EC2 instances, neutralizing SSRF metadata credential theft")

    # Re-evaluate all paths through the deterministic oracle
    sim_paths = enumerate_and_label_paths(sim_env)
    sim_exploitable = [p for p in sim_paths if p.label_exploitable == 1]
    sim_cnt = len(sim_exploitable)
    paths_eliminated = max(0, baseline_cnt - sim_cnt)
    elim_rate = (paths_eliminated / max(1, baseline_cnt)) * 100.0

    if baseline_cnt == 0:
        sim_score = 10.0
    else:
        sim_score = round((sim_cnt / baseline_cnt) * 100.0, 1)

    risk_delta = round(sim_score - baseline_score, 1)

    # Historical log-replay breakage estimation
    legit_total = 0
    legit_broken = 0
    if logs:
        legit_logs = [e for e in logs if e.is_legitimate]
        legit_total = len(legit_logs)
        role_map = {r.id: r for r in sim_env.db_roles}
        # Check if legitimate DB queries are broken under the new simulated policies
        for log in legit_logs:
            if log.source == "pgaudit" and log.table_id and log.db_role_id:
                tbl = next((t for t in sim_env.db_tables if t.id == log.table_id), None)
                role = role_map.get(log.db_role_id)
                if role and tbl and not db_role_can_read_table(role, tbl, role_map):
                    legit_broken += 1

    false_breakage_rate = round((legit_broken / max(1, legit_total)) * 100.0, 2)

    if sim_cnt == 0 and legit_broken == 0:
        status = "Verified Safe-to-Apply"
        impact_narrative = (
            f"All {baseline_cnt} exploitable attack paths eliminated (100% reduction). "
            f"0/{legit_total} legitimate application transactions broken. Complete kill-chain neutralization."
        )
    elif sim_cnt == 0 and legit_broken > 0:
        status = "Warning: Minor Breakage"
        impact_narrative = (
            f"All attack paths eliminated, but {legit_broken} legitimate business query(s) were blocked. "
            f"Review role grants before enforcing in production."
        )
    elif sim_cnt < baseline_cnt:
        status = "Partial Mitigation"
        impact_narrative = (
            f"Eliminated {paths_eliminated} of {baseline_cnt} attack paths ({elim_rate:.0f}% reduction). "
            f"{sim_cnt} exploitable path(s) remain active via secondary vectors."
        )
    else:
        status = "No Significant Risk Reduction"
        impact_narrative = (
            "Current simulated policy changes did not sever the active attack path. "
            "Ensure the primary bottleneck (e.g. port 5432 ingress or database role grants) is addressed."
        )

    graph_elements = graph_to_cytoscape_elements(sim_env)

    return WhatIfSimulationResult(
        baseline_risk_score=baseline_score,
        simulated_risk_score=sim_score,
        risk_delta=risk_delta,
        paths_before=baseline_cnt,
        paths_after=sim_cnt,
        paths_eliminated=paths_eliminated,
        elimination_rate=round(elim_rate, 1),
        legit_total=legit_total,
        legit_broken=legit_broken,
        false_breakage_rate=false_breakage_rate,
        status=status,
        impact_narrative=impact_narrative,
        active_exploitable_path_ids=[p.path_id for p in sim_exploitable],
        graph_elements=graph_elements,
    )
