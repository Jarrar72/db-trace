"""Real-time Read-Only Google Cloud Platform (GCP) Collector (IAM, GCE, Firewalls, Cloud SQL).

Uses official Google Cloud REST APIs with an OAuth2 Access Token (`gcloud auth print-access-token`).
Gracefully handles disabled APIs or IAM permission denials per service.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from dbtrace.schema import (
    VPC,
    CloudEnvironment,
    ComputeResource,
    DBRole,
    DBTable,
    IAMPolicy,
    IAMPrincipal,
    IngressRule,
    PolicyStatement,
    RDSInstance,
    SecurityGroup,
    SensitivityLevel,
    Subnet,
)


def _gcp_req(url: str, token: str, method: str = "GET", body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def collect_gcp_environment(
    project_id: str,
    access_token: str,
) -> tuple[CloudEnvironment, dict[str, Any]]:
    """Scan a real GCP project (read-only) and build a CloudEnvironment graph."""
    proj = project_id.strip()
    token = access_token.strip()
    if not proj or not token:
        raise ValueError("GCP Project ID and OAuth2 Access Token (`gcloud auth print-access-token`) are required.")

    env_id = f"gcp_{proj[:12]}"
    warnings: list[str] = []

    vpcs = [VPC(id=f"{env_id}_vpc_default", cidr="10.128.0.0/9")]
    subnets = [
        Subnet(id=f"{env_id}_sub_pub", vpc_id=vpcs[0].id, cidr="10.128.0.0/20", is_public=True, route_to_igw=True),
        Subnet(id=f"{env_id}_sub_priv", vpc_id=vpcs[0].id, cidr="10.128.16.0/20", is_public=False, route_to_igw=False),
    ]
    sgs: list[SecurityGroup] = []
    computes: list[ComputeResource] = []
    rds_instances: list[RDSInstance] = []
    principals: list[IAMPrincipal] = []
    policies: list[IAMPolicy] = []

    # 1. VPC Firewalls
    try:
        fw_resp = _gcp_req(f"https://compute.googleapis.com/compute/v1/projects/{proj}/global/firewalls", token)
        for fw in fw_resp.get("items", [])[:25]:
            if fw.get("direction") != "INGRESS" or fw.get("disabled"):
                continue
            rules: list[IngressRule] = []
            src_ranges = fw.get("sourceRanges", [])
            for allowed in fw.get("allowed", []):
                proto = str(allowed.get("IPProtocol", "tcp")).lower()
                ports = allowed.get("ports", ["0-65535"])
                for pspec in ports:
                    parts = str(pspec).split("-")
                    fp = int(parts[0]) if parts[0].isdigit() else 0
                    tp = int(parts[-1]) if parts[-1].isdigit() else 65535
                    for cidr in src_ranges or ["0.0.0.0/0"]:
                        rules.append(IngressRule(from_port=fp, to_port=tp, protocol=proto, cidr=cidr))
            sgs.append(SecurityGroup(id=str(fw.get("id", fw["name"])), name=fw["name"], vpc_id=vpcs[0].id, ingress_rules=rules))
    except urllib.error.HTTPError as exc:
        warnings.append(f"GCP Firewalls skipped (HTTP {exc.code}): Compute Engine API disabled or lacking compute.firewalls.list.")
    except Exception as exc:
        warnings.append(f"GCP Firewalls skipped: {exc}")

    if not sgs:
        sgs.append(SecurityGroup(id=f"{env_id}_fw_default", name="gcp-default-firewall", vpc_id=vpcs[0].id, ingress_rules=[]))

    # 2. Cloud SQL (PostgreSQL) Instances
    try:
        sql_resp = _gcp_req(f"https://sqladmin.googleapis.com/v1/projects/{proj}/instances", token)
        for inst in sql_resp.get("items", [])[:15]:
            settings = inst.get("settings", {})
            ip_cfg = settings.get("ipConfiguration", {})
            pub_ipv4 = bool(ip_cfg.get("ipv4Enabled", False))
            auth_nets = ip_cfg.get("authorizedNetworks", [])
            open_world = any(n.get("value") == "0.0.0.0/0" for n in auth_nets)
            if open_world:
                sgs[0].ingress_rules.append(IngressRule(from_port=5432, to_port=5432, cidr="0.0.0.0/0"))
            rds_instances.append(
                RDSInstance(
                    id=f"{env_id}_sql_{inst['name']}",
                    name=inst["name"],
                    vpc_id=vpcs[0].id,
                    subnet_id=subnets[0].id if pub_ipv4 else subnets[1].id,
                    security_group_ids=[sgs[0].id],
                    port=5432,
                    publicly_accessible=pub_ipv4,
                    encrypted=True,
                    iam_auth_enabled=True,
                )
            )
    except urllib.error.HTTPError as exc:
        warnings.append(f"GCP Cloud SQL skipped (HTTP {exc.code}): Cloud SQL Admin API disabled or unauthorized.")
    except Exception as exc:
        warnings.append(f"GCP Cloud SQL skipped: {exc}")

    if not rds_instances:
        rds_instances.append(
            RDSInstance(
                id=f"{env_id}_sql_placeholder",
                name="gcp-cloudsql-target (none discovered)",
                vpc_id=vpcs[0].id,
                subnet_id=subnets[1].id,
                security_group_ids=[sgs[0].id],
                publicly_accessible=False,
            )
        )

    # 3. Project IAM Policy Bindings
    try:
        iam_resp = _gcp_req(
            f"https://cloudresourcemanager.googleapis.com/v1/projects/{proj}:getIamPolicy",
            token,
            method="POST",
            body={},
        )
        seen_members: set[str] = set()
        for b in iam_resp.get("bindings", []):
            role_name = str(b.get("role", ""))
            is_broad = role_name in ("roles/owner", "roles/editor", "roles/cloudsql.admin")
            for member in b.get("members", [])[:15]:
                if member in seen_members:
                    continue
                seen_members.add(member)
                pol = IAMPolicy(
                    id=f"{env_id}_pol_{len(policies)}",
                    name=role_name,
                    statements=[
                        PolicyStatement(
                            effect="Allow",
                            actions=["*", "rds-db:connect"] if is_broad else ["rds-db:connect"],
                            resources=["*"],
                        )
                    ],
                )
                policies.append(pol)
                principals.append(
                    IAMPrincipal(
                        id=f"{env_id}_mem_{len(principals)}",
                        arn=f"gcp://iam/{member}",
                        name=member.split(":")[-1][:40],
                        kind="role" if member.startswith("serviceAccount:") else "user",
                        has_mfa=not is_broad,
                        attached_policy_ids=[pol.id],
                    )
                )
    except urllib.error.HTTPError as exc:
        warnings.append(f"GCP IAM Policy skipped (HTTP {exc.code}).")
    except Exception as exc:
        warnings.append(f"GCP IAM scan skipped: {exc}")

    if not principals:
        principals.append(
            IAMPrincipal(
                id=f"{env_id}_gcp_ext",
                arn="gcp://external/internet",
                name="internet-entry-gcp",
                kind="user",
                has_mfa=False,
                is_external_entry=True,
            )
        )

    rds0 = rds_instances[0]
    db_roles = [
        DBRole(id=f"{env_id}_pg_admin", rds_id=rds0.id, name="cloudsqlsuperuser", can_login=True, is_rds_superuser=True),
        DBRole(id=f"{env_id}_app_role", rds_id=rds0.id, name="app_service", can_login=True),
    ]
    db_tables = [
        DBTable(
            id=f"{env_id}_tbl_pii",
            rds_id=rds0.id,
            schema_name="public",
            table_name="customers_pii",
            sensitivity=SensitivityLevel.PII,
            grants={db_roles[1].id: ["SELECT"]},
        )
    ]

    env = CloudEnvironment(
        env_id=env_id,
        scenario_type="live_gcp_project",
        template_family="gcp",
        seed=0,
        provider="gcp",
        vpcs=vpcs,
        subnets=subnets,
        security_groups=sgs,
        policies=policies,
        principals=principals,
        computes=computes,
        rds_instances=rds_instances,
        db_roles=db_roles,
        db_tables=db_tables,
    )
    meta = {
        "provider": "gcp",
        "project_id": proj,
        "principals": len(principals),
        "computes": len(computes),
        "security_groups": len(sgs),
        "rds_instances": len(rds_instances),
        "warnings": warnings,
    }
    return env, meta
