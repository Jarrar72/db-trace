"""Build PyTorch Geometric HeteroData and NetworkX graphs from CloudEnvironment."""

from __future__ import annotations

from typing import Any

import networkx as nx
import torch
import torch_geometric.transforms as T
from torch_geometric.data import HeteroData

from dbtrace.labeling.iam_eval import evaluate_iam_action, has_privesc_capability
from dbtrace.schema import CloudEnvironment, SensitivityLevel


def build_hetero_data(env: CloudEnvironment) -> tuple[HeteroData, dict[str, dict[str, int]]]:
    """Convert a CloudEnvironment into a PyG HeteroData graph + node-ID index maps."""
    data = HeteroData()
    policy_map = {p.id: p for p in env.policies}
    idx_maps: dict[str, dict[str, int]] = {}

    # 1. Principals
    p_feats = []
    idx_maps["principal"] = {}
    for i, p in enumerate(env.principals):
        idx_maps["principal"][p.id] = i
        p_feats.append([
            1.0 if p.kind == "user" else 0.0,
            1.0 if p.kind == "role" else 0.0,
            1.0 if p.has_mfa else 0.0,
            1.0 if p.is_external_entry else 0.0,
            1.0 if has_privesc_capability(p, policy_map) else 0.0,
            1.0 if evaluate_iam_action(p, "rds-db:connect", "*", policy_map) else 0.0,
            1.0 if evaluate_iam_action(p, "rds:ModifyDBSnapshotAttribute", "*", policy_map) else 0.0,
        ])
    data["principal"].x = torch.tensor(p_feats or [[0.0] * 7], dtype=torch.float)

    # 2. Compute
    c_feats = []
    idx_maps["compute"] = {}
    subnet_map = {s.id: s for s in env.subnets}
    for i, c in enumerate(env.computes):
        idx_maps["compute"][c.id] = i
        sub = subnet_map.get(c.subnet_id)
        c_feats.append([
            1.0 if c.kind == "ec2" else 0.0,
            1.0 if c.imdsv2_required else 0.0,
            1.0 if c.has_public_ip else 0.0,
            1.0 if c.has_app_vuln else 0.0,
            1.0 if c.leaked_db_role_id else 0.0,
            1.0 if (sub and sub.route_to_igw) else 0.0,
        ])
    data["compute"].x = torch.tensor(c_feats or [[0.0] * 6], dtype=torch.float)

    # 3. Security Groups
    sg_feats = []
    idx_maps["security_group"] = {}
    for i, sg in enumerate(env.security_groups):
        idx_maps["security_group"][sg.id] = i
        open_5432 = any(r.from_port <= 5432 <= r.to_port and r.cidr == "0.0.0.0/0" for r in sg.ingress_rules)
        open_443 = any(r.from_port <= 443 <= r.to_port and r.cidr == "0.0.0.0/0" for r in sg.ingress_rules)
        sg_feats.append([
            1.0 if open_5432 else 0.0,
            1.0 if open_443 else 0.0,
            float(len(sg.ingress_rules)),
        ])
    data["security_group"].x = torch.tensor(sg_feats or [[0.0] * 3], dtype=torch.float)

    # 4. RDS Instances
    rds_feats = []
    idx_maps["rds"] = {}
    for i, rds in enumerate(env.rds_instances):
        idx_maps["rds"][rds.id] = i
        sub = subnet_map.get(rds.subnet_id)
        rds_feats.append([
            1.0 if rds.publicly_accessible else 0.0,
            1.0 if rds.encrypted else 0.0,
            1.0 if rds.iam_auth_enabled else 0.0,
            1.0 if rds.has_public_snapshot else 0.0,
            1.0 if (sub and sub.route_to_igw) else 0.0,
        ])
    data["rds"].x = torch.tensor(rds_feats or [[0.0] * 5], dtype=torch.float)

    # 5. DB Roles
    dbr_feats = []
    idx_maps["db_role"] = {}
    for i, r in enumerate(env.db_roles):
        idx_maps["db_role"][r.id] = i
        dbr_feats.append([
            1.0 if r.can_login else 0.0,
            1.0 if r.is_superuser else 0.0,
            1.0 if r.is_rds_superuser else 0.0,
            1.0 if r.inherit else 0.0,
        ])
    data["db_role"].x = torch.tensor(dbr_feats or [[0.0] * 4], dtype=torch.float)

    # 6. DB Tables
    dbt_feats = []
    idx_maps["db_table"] = {}
    for i, t in enumerate(env.db_tables):
        idx_maps["db_table"][t.id] = i
        dbt_feats.append([
            1.0 if t.sensitivity in (SensitivityLevel.HIGH, SensitivityLevel.PII) else 0.0,
            1.0 if t.sensitivity == SensitivityLevel.PII else 0.0,
            float(len(t.grants)),
        ])
    data["db_table"].x = torch.tensor(dbt_feats or [[0.0] * 3], dtype=torch.float)

    def _edge_tensor(pairs: list[tuple[int, int]]) -> torch.Tensor:
        if not pairs:
            return torch.empty((2, 0), dtype=torch.long)
        return torch.tensor(pairs, dtype=torch.long).t().contiguous()

    # Edges
    assume_edges = [
        (idx_maps["principal"][p.id], idx_maps["principal"][tid])
        for p in env.principals
        for tid in p.can_assume_ids
        if tid in idx_maps["principal"]
    ]
    data["principal", "can_assume", "principal"].edge_index = _edge_tensor(assume_edges)

    comp_role_edges = [
        (idx_maps["compute"][c.id], idx_maps["principal"][c.iam_role_id])
        for c in env.computes
        if c.iam_role_id and c.iam_role_id in idx_maps["principal"]
    ]
    data["compute", "uses_role", "principal"].edge_index = _edge_tensor(comp_role_edges)

    comp_sg_edges = [
        (idx_maps["compute"][c.id], idx_maps["security_group"][sg_id])
        for c in env.computes
        for sg_id in c.security_group_ids
        if sg_id in idx_maps["security_group"]
    ]
    data["compute", "in_sg", "security_group"].edge_index = _edge_tensor(comp_sg_edges)

    sg_rds_edges = [
        (idx_maps["security_group"][sg_id], idx_maps["rds"][rds.id])
        for rds in env.rds_instances
        for sg_id in rds.security_group_ids
        if sg_id in idx_maps["security_group"]
    ]
    data["security_group", "protects", "rds"].edge_index = _edge_tensor(sg_rds_edges)

    sg_allow_edges = []
    for rds_sg in env.security_groups:
        for rule in rds_sg.ingress_rules:
            if rule.source_sg_id and rule.source_sg_id in idx_maps["security_group"]:
                sg_allow_edges.append(
                    (idx_maps["security_group"][rule.source_sg_id], idx_maps["security_group"][rds_sg.id])
                )
    data["security_group", "allows_ingress", "security_group"].edge_index = _edge_tensor(sg_allow_edges)

    member_edges = [
        (idx_maps["db_role"][r.id], idx_maps["db_role"][mid])
        for r in env.db_roles
        for mid in r.member_of_ids
        if mid in idx_maps["db_role"]
    ]
    data["db_role", "member_of", "db_role"].edge_index = _edge_tensor(member_edges)

    grant_edges = [
        (idx_maps["db_role"][rid], idx_maps["db_table"][t.id])
        for t in env.db_tables
        for rid in t.grants
        if rid in idx_maps["db_role"]
    ]
    data["db_role", "granted", "db_table"].edge_index = _edge_tensor(grant_edges)

    rds_role_edges = [
        (idx_maps["rds"][r.rds_id], idx_maps["db_role"][r.id])
        for r in env.db_roles
        if r.rds_id in idx_maps["rds"]
    ]
    data["rds", "hosts_role", "db_role"].edge_index = _edge_tensor(rds_role_edges)

    data = T.ToUndirected()(data)
    return data, idx_maps


def build_nx_graph(env: CloudEnvironment) -> nx.DiGraph:
    """Build a lightweight NetworkX graph for API visualization & inspection."""
    g = nx.DiGraph()
    for p in env.principals:
        g.add_node(p.id, label=p.name, node_type="Principal", kind=p.kind)
        for tid in p.can_assume_ids:
            g.add_edge(p.id, tid, rel="CAN_ASSUME")
    for c in env.computes:
        g.add_node(c.id, label=c.name, node_type="Compute", kind=c.kind)
        if c.iam_role_id:
            g.add_edge(c.id, c.iam_role_id, rel="USES_ROLE")
        for sg_id in c.security_group_ids:
            g.add_edge(c.id, sg_id, rel="IN_SG")
        if c.leaked_db_role_id:
            g.add_edge(c.id, c.leaked_db_role_id, rel="HAS_CREDS_FOR")
    for sg in env.security_groups:
        g.add_node(sg.id, label=sg.name, node_type="SecurityGroup")
        for r in sg.ingress_rules:
            if r.source_sg_id:
                g.add_edge(r.source_sg_id, sg.id, rel=f"ALLOWS_{r.from_port}")
    for rds in env.rds_instances:
        g.add_node(rds.id, label=rds.name, node_type="RDSInstance", public=rds.publicly_accessible)
        for sg_id in rds.security_group_ids:
            g.add_edge(sg_id, rds.id, rel="PROTECTS")
    for r in env.db_roles:
        g.add_node(r.id, label=r.name, node_type="DBRole", superuser=r.is_superuser)
        g.add_edge(r.rds_id, r.id, rel="HOSTS_ROLE")
        for mid in r.member_of_ids:
            g.add_edge(r.id, mid, rel="MEMBER_OF")
    for t in env.db_tables:
        g.add_node(t.id, label=f"{t.schema_name}.{t.table_name}", node_type="DBTable", sensitivity=t.sensitivity.value)
        for rid, privs in t.grants.items():
            g.add_edge(rid, t.id, rel=",".join(privs))
    return g


def graph_to_cytoscape_elements(env: CloudEnvironment) -> dict[str, list[dict[str, Any]]]:
    """Return nodes and edges formatted for Cytoscape.js in the Next.js dashboard."""
    g = build_nx_graph(env)
    nodes = [{"data": {"id": nid, **attrs}} for nid, attrs in g.nodes(data=True)]
    edges = [
        {"data": {"id": f"{u}->{v}:{i}", "source": u, "target": v, **attrs}}
        for i, (u, v, attrs) in enumerate(g.edges(data=True))
    ]
    return {"nodes": nodes, "edges": edges}
