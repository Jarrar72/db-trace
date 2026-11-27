"""Deterministic attack-path oracle for labeling Identity->Compute->Network->DB paths."""

from __future__ import annotations

from collections import deque

from dbtrace.labeling.iam_eval import evaluate_iam_action, reachable_roles
from dbtrace.schema import (
    AccessPathRecord,
    CloudEnvironment,
    DBRole,
    DBTable,
    RDSInstance,
    SecurityGroup,
    SensitivityLevel,
)


def _sg_allows_port_from_cidr(sg: SecurityGroup, port: int, cidrs: tuple[str, ...] = ("0.0.0.0/0", "::/0")) -> bool:
    for rule in sg.ingress_rules:
        if rule.from_port <= port <= rule.to_port and rule.cidr in cidrs:
            return True
    return False


def _sg_allows_port_from_sg(rds_sg: SecurityGroup, source_sg_id: str, port: int) -> bool:
    for rule in rds_sg.ingress_rules:
        if rule.from_port <= port <= rule.to_port:
            if rule.source_sg_id == source_sg_id or rule.cidr == "0.0.0.0/0":
                return True
    return False


def effective_db_role_closure(start_role: DBRole, role_map: dict[str, DBRole]) -> set[str]:
    """Compute transitive PostgreSQL role memberships (respecting INHERIT)."""
    visited = {start_role.id}
    queue = deque([start_role.id])
    while queue:
        rid = queue.popleft()
        role = role_map.get(rid)
        if not role or not role.inherit:
            continue
        for parent_id in role.member_of_ids:
            if parent_id not in visited and parent_id in role_map:
                visited.add(parent_id)
                queue.append(parent_id)
    return visited


def db_role_can_read_table(role: DBRole, table: DBTable, role_map: dict[str, DBRole]) -> bool:
    if not role.can_login:
        return False
    closure = effective_db_role_closure(role, role_map)
    for rid in closure:
        r = role_map[rid]
        if r.is_superuser or r.is_rds_superuser:
            return True
        privs = table.grants.get(rid, [])
        if any(p in ("SELECT", "ALL") for p in privs):
            return True
    return False


def _check_network_from_internet(rds: RDSInstance, env: CloudEnvironment) -> tuple[bool, str | None, str]:
    if not rds.publicly_accessible:
        return False, None, "rds_not_publicly_accessible"
    subnet_map = {s.id: s for s in env.subnets}
    subnet = subnet_map.get(rds.subnet_id)
    if not subnet or not subnet.route_to_igw:
        return False, None, "no_igw_route"
    sg_map = {sg.id: sg for sg in env.security_groups}
    for sg_id in rds.security_group_ids:
        sg = sg_map.get(sg_id)
        if sg and _sg_allows_port_from_cidr(sg, rds.port):
            return True, sg_id, ""
    return False, None, "sg_blocks_internet_port"


def _check_network_from_compute(
    compute_sg_ids: list[str], rds: RDSInstance, env: CloudEnvironment
) -> tuple[bool, str | None, str | None, str]:
    sg_map = {sg.id: sg for sg in env.security_groups}
    for rds_sg_id in rds.security_group_ids:
        rds_sg = sg_map.get(rds_sg_id)
        if not rds_sg:
            continue
        for src_sg_id in compute_sg_ids:
            if _sg_allows_port_from_sg(rds_sg, src_sg_id, rds.port):
                return True, src_sg_id, rds_sg_id, ""
    return False, compute_sg_ids[0] if compute_sg_ids else None, rds.security_group_ids[0] if rds.security_group_ids else None, "sg_blocks_compute_to_rds"


def enumerate_and_label_paths(env: CloudEnvironment) -> list[AccessPathRecord]:
    """Enumerate candidate access paths in an environment and assign deterministic labels."""
    policy_map = {p.id: p for p in env.policies}
    principal_map = {p.id: p for p in env.principals}
    role_map = {r.id: r for r in env.db_roles}
    subnet_map = {s.id: s for s in env.subnets}
    records: list[AccessPathRecord] = []
    idx = 0

    entry_principals = [p for p in env.principals if p.is_external_entry or p.kind == "user"]
    if not entry_principals:
        entry_principals = env.principals[:2]

    for entry in entry_principals:
        reached_iam = reachable_roles(entry.id, env, policy_map)

        for rds in env.rds_instances:
            rds_roles = [r for r in env.db_roles if r.rds_id == rds.id]
            rds_tables = [t for t in env.db_tables if t.rds_id == rds.id]

            for table in rds_tables:
                is_sensitive = table.sensitivity in (SensitivityLevel.HIGH, SensitivityLevel.PII)

                # 1) Paths through Compute resources
                for comp in env.computes:
                    comp_role = principal_map.get(comp.iam_role_id) if comp.iam_role_id else None
                    # Entry can reach compute either via IAM role/lambda invoke or internet-facing app vuln
                    comp_subnet = subnet_map.get(comp.subnet_id)
                    internet_to_comp = bool(
                        comp.has_public_ip and comp_subnet and comp_subnet.route_to_igw and comp.has_app_vuln
                    )
                    iam_to_comp = bool(comp.iam_role_id and comp.iam_role_id in reached_iam)
                    can_reach_comp = internet_to_comp or iam_to_comp

                    net_ok, src_sg_id, rds_sg_id, net_reason = _check_network_from_compute(
                        comp.security_group_ids, rds, env
                    )

                    for db_role in rds_roles:
                        idx += 1
                        db_ok = db_role_can_read_table(db_role, table, role_map)
                        iam_db_ok = bool(
                            rds.iam_auth_enabled
                            and comp_role
                            and evaluate_iam_action(comp_role, "rds-db:connect", "*", policy_map)
                        )
                        creds_ok = comp.leaked_db_role_id == db_role.id
                        auth_ok = iam_db_ok or creds_ok

                        exploitable = 1 if (can_reach_comp and net_ok and auth_ok and db_ok and is_sensitive) else 0
                        reason = ""
                        if not exploitable:
                            if not is_sensitive:
                                reason = "low_sensitivity_table"
                            elif not can_reach_comp:
                                reason = "cannot_reach_compute"
                            elif not net_ok:
                                reason = net_reason
                            elif not auth_ok:
                                reason = "no_db_auth_or_creds"
                            elif not db_ok:
                                reason = "insufficient_db_grants"

                        records.append(
                            AccessPathRecord(
                                path_id=f"{env.env_id}_p{idx:04d}",
                                env_id=env.env_id,
                                scenario_type=env.scenario_type,
                                template_family=env.template_family,
                                entry_principal_id=entry.id,
                                target_role_id=comp.iam_role_id or entry.id,
                                compute_id=comp.id,
                                source_sg_id=src_sg_id,
                                rds_sg_id=rds_sg_id,
                                rds_id=rds.id,
                                db_role_id=db_role.id,
                                db_table_id=table.id,
                                via_internet=internet_to_comp,
                                via_snapshot=False,
                                label_exploitable=exploitable,
                                failure_reason=reason,
                            )
                        )

                # 2) Direct Internet -> RDS path (when publicly accessible or near-miss)
                net_ok, rds_sg_id, net_reason = _check_network_from_internet(rds, env)
                for db_role in rds_roles:
                    idx += 1
                    db_ok = db_role_can_read_table(db_role, table, role_map)
                    iam_db_ok = any(
                        rds.iam_auth_enabled
                        and evaluate_iam_action(principal_map[pid], "rds-db:connect", "*", policy_map)
                        for pid in reached_iam
                        if pid in principal_map
                    )
                    # Weak/default credentials or IAM auth on public RDS
                    exploitable = 1 if (net_ok and iam_db_ok and db_ok and is_sensitive) else 0
                    reason = "" if exploitable else (net_reason if not net_ok else "no_direct_iam_db_auth")
                    records.append(
                        AccessPathRecord(
                            path_id=f"{env.env_id}_p{idx:04d}",
                            env_id=env.env_id,
                            scenario_type=env.scenario_type,
                            template_family=env.template_family,
                            entry_principal_id=entry.id,
                            target_role_id=entry.id,
                            compute_id=None,
                            source_sg_id=None,
                            rds_sg_id=rds_sg_id or (rds.security_group_ids[0] if rds.security_group_ids else None),
                            rds_id=rds.id,
                            db_role_id=db_role.id,
                            db_table_id=table.id,
                            via_internet=True,
                            via_snapshot=False,
                            label_exploitable=exploitable,
                            failure_reason=reason,
                        )
                    )

                # 3) Snapshot exfiltration path
                if rds.has_public_snapshot or any(
                    evaluate_iam_action(principal_map[pid], "rds:ModifyDBSnapshotAttribute", "*", policy_map)
                    or evaluate_iam_action(principal_map[pid], "rds:RestoreDBInstanceFromDBSnapshot", "*", policy_map)
                    for pid in reached_iam
                    if pid in principal_map
                ):
                    idx += 1
                    snap_ok = rds.has_public_snapshot or any(
                        evaluate_iam_action(principal_map[pid], "rds:ModifyDBSnapshotAttribute", "*", policy_map)
                        for pid in reached_iam
                        if pid in principal_map
                    )
                    exploitable = 1 if (snap_ok and not rds.encrypted and is_sensitive) else 0
                    records.append(
                        AccessPathRecord(
                            path_id=f"{env.env_id}_p{idx:04d}",
                            env_id=env.env_id,
                            scenario_type=env.scenario_type,
                            template_family=env.template_family,
                            entry_principal_id=entry.id,
                            target_role_id=entry.id,
                            compute_id=None,
                            source_sg_id=None,
                            rds_sg_id=None,
                            rds_id=rds.id,
                            db_role_id=rds_roles[0].id if rds_roles else "none",
                            db_table_id=table.id,
                            via_internet=False,
                            via_snapshot=True,
                            label_exploitable=exploitable,
                            failure_reason="" if exploitable else "snapshot_encrypted_or_no_modify",
                        )
                    )

    return records
