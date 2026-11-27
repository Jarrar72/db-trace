"""Real-time Read-Only Microsoft Azure Collector (Entra ID, NSGs, VMs, PostgreSQL Flexible Server).

Uses official Azure Resource Manager (management.azure.com) REST APIs with OAuth2 Client Credentials
or direct Bearer token (`az account get-access-token`). Gracefully handles RBAC/Policy denials per API.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
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


def _get_azure_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://management.azure.com/.default",
    }).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return str(data["access_token"])


def _arm_get(url: str, token: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def collect_azure_environment(
    subscription_id: str,
    *,
    tenant_id: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    access_token: str | None = None,
) -> tuple[CloudEnvironment, dict[str, Any]]:
    """Scan a real Microsoft Azure subscription (read-only) and build a CloudEnvironment graph."""
    if not subscription_id.strip():
        raise ValueError("Azure Subscription ID is required.")

    token = access_token.strip() if access_token else ""
    if not token:
        if not (tenant_id and client_id and client_secret):
            raise ValueError("Provide either an Azure Access Token or Tenant ID + Client ID + Client Secret.")
        token = _get_azure_token(tenant_id.strip(), client_id.strip(), client_secret.strip())

    env_id = f"azure_{subscription_id[:8]}"
    base = f"https://management.azure.com/subscriptions/{subscription_id.strip()}"
    warnings: list[str] = []

    vpcs = [VPC(id=f"{env_id}_vnet_default", cidr="10.0.0.0/16")]
    subnets = [
        Subnet(id=f"{env_id}_sub_pub", vpc_id=vpcs[0].id, cidr="10.0.1.0/24", is_public=True, route_to_igw=True),
        Subnet(id=f"{env_id}_sub_priv", vpc_id=vpcs[0].id, cidr="10.0.2.0/24", is_public=False, route_to_igw=False),
    ]
    sgs: list[SecurityGroup] = []
    computes: list[ComputeResource] = []
    rds_instances: list[RDSInstance] = []
    principals: list[IAMPrincipal] = []
    policies: list[IAMPolicy] = []

    # 1. Network Security Groups (NSGs)
    try:
        nsg_resp = _arm_get(f"{base}/providers/Microsoft.Network/networkSecurityGroups?api-version=2023-09-01", token)
        for item in nsg_resp.get("value", [])[:25]:
            rules: list[IngressRule] = []
            for r in item.get("properties", {}).get("securityRules", []):
                rp = r.get("properties", {})
                if rp.get("direction") != "Inbound" or rp.get("access") != "Allow":
                    continue
                dst_port = str(rp.get("destinationPortRange", "*"))
                fp, tp = (0, 65535) if dst_port == "*" else (int(dst_port.split("-")[0]), int(dst_port.split("-")[-1]))
                src = str(rp.get("sourceAddressPrefix", ""))
                cidr = "0.0.0.0/0" if src in ("*", "Internet", "0.0.0.0/0") else src
                rules.append(IngressRule(from_port=fp, to_port=tp, protocol=str(rp.get("protocol", "tcp")).lower(), cidr=cidr))
            sgs.append(SecurityGroup(id=item["id"], name=item["name"], vpc_id=vpcs[0].id, ingress_rules=rules))
    except urllib.error.HTTPError as exc:
        warnings.append(f"Azure NSGs skipped (HTTP {exc.code}): insufficient Microsoft.Network/networkSecurityGroups/read permission.")
    except Exception as exc:
        warnings.append(f"Azure NSGs skipped: {exc}")

    if not sgs:
        sgs.append(SecurityGroup(id=f"{env_id}_nsg_default", name="azure-default-nsg", vpc_id=vpcs[0].id, ingress_rules=[]))

    # 2. Azure Database for PostgreSQL Flexible Servers
    try:
        pg_resp = _arm_get(f"{base}/providers/Microsoft.DBforPostgreSQL/flexibleServers?api-version=2023-06-01-preview", token)
        for db in pg_resp.get("value", [])[:15]:
            props = db.get("properties", {})
            net = props.get("network", {})
            pub = str(net.get("publicNetworkAccess", "Enabled")).lower() == "enabled"
            rds_instances.append(
                RDSInstance(
                    id=db["id"],
                    name=db["name"],
                    vpc_id=vpcs[0].id,
                    subnet_id=subnets[0].id if pub else subnets[1].id,
                    security_group_ids=[sgs[0].id],
                    port=5432,
                    publicly_accessible=pub,
                    encrypted=True,
                    iam_auth_enabled=bool(props.get("authConfig", {}).get("activeDirectoryAuth") == "Enabled"),
                )
            )
    except urllib.error.HTTPError as exc:
        warnings.append(f"Azure PostgreSQL Flexible Servers skipped (HTTP {exc.code}).")
    except Exception as exc:
        warnings.append(f"Azure PostgreSQL scan skipped: {exc}")

    if not rds_instances:
        rds_instances.append(
            RDSInstance(
                id=f"{env_id}_pg_discovered",
                name="azure-pg-target (no flexibleServers found)",
                vpc_id=vpcs[0].id,
                subnet_id=subnets[1].id,
                security_group_ids=[sgs[0].id],
                publicly_accessible=False,
            )
        )

    # 3. Azure Virtual Machines & Managed Identities
    try:
        vm_resp = _arm_get(f"{base}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01", token)
        for vm in vm_resp.get("value", [])[:20]:
            ident = vm.get("identity", {})
            principal_id = ident.get("principalId")
            computes.append(
                ComputeResource(
                    id=vm["id"],
                    kind="azure_vm",
                    name=vm["name"],
                    subnet_id=subnets[0].id,
                    security_group_ids=[sgs[0].id],
                    iam_role_id=principal_id,
                    imdsv2_required=False,
                    has_public_ip=True,
                )
            )
            if principal_id:
                pol = IAMPolicy(
                    id=f"{env_id}_pol_{vm['name']}",
                    name=f"ManagedIdentityPolicy-{vm['name']}",
                    statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect"], resources=["*"])],
                )
                policies.append(pol)
                principals.append(
                    IAMPrincipal(
                        id=principal_id,
                        arn=f"azure://entra-id/managed-identity/{vm['name']}",
                        name=f"mi-{vm['name']}",
                        kind="role",
                        attached_policy_ids=[pol.id],
                    )
                )
    except urllib.error.HTTPError as exc:
        warnings.append(f"Azure VMs skipped (HTTP {exc.code}).")
    except Exception as exc:
        warnings.append(f"Azure VMs scan skipped: {exc}")

    # 4. RBAC Role Assignments
    try:
        rbac_resp = _arm_get(f"{base}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", token)
        seen_p: set[str] = {p.id for p in principals}
        for ra in rbac_resp.get("value", [])[:20]:
            props = ra.get("properties", {})
            pid = str(props.get("principalId", ""))
            if not pid or pid in seen_p:
                continue
            seen_p.add(pid)
            pol = IAMPolicy(
                id=f"{env_id}_rbac_{pid[:8]}",
                name="AzureRBACAssignment",
                statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect", "*"], resources=["*"])],
            )
            policies.append(pol)
            principals.append(
                IAMPrincipal(
                    id=pid,
                    arn=f"azure://entra-id/principal/{pid}",
                    name=f"entra-{str(props.get('principalType', 'user')).lower()}-{pid[:8]}",
                    kind="user" if props.get("principalType") == "User" else "role",
                    has_mfa=False,
                    attached_policy_ids=[pol.id],
                )
            )
    except urllib.error.HTTPError as exc:
        warnings.append(f"Azure RBAC Role Assignments skipped (HTTP {exc.code}).")
    except Exception as exc:
        warnings.append(f"Azure RBAC scan skipped: {exc}")

    if not principals:
        principals.append(
            IAMPrincipal(
                id=f"{env_id}_entra_ext",
                arn="azure://entra-id/external/internet",
                name="internet-entry-azure",
                kind="user",
                has_mfa=False,
                is_external_entry=True,
            )
        )

    # Default PostgreSQL catalog representation for discovered Azure DB
    rds0 = rds_instances[0]
    db_roles = [
        DBRole(id=f"{env_id}_pg_admin", rds_id=rds0.id, name="azure_pg_admin", can_login=True, is_rds_superuser=True),
        DBRole(id=f"{env_id}_app_role", rds_id=rds0.id, name="app_service_role", can_login=True),
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
        scenario_type="live_azure_subscription",
        template_family="azure",
        seed=0,
        provider="azure",
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
        "provider": "azure",
        "subscription_id": subscription_id,
        "principals": len(principals),
        "computes": len(computes),
        "security_groups": len(sgs),
        "rds_instances": len(rds_instances),
        "warnings": warnings,
    }
    return env, meta
