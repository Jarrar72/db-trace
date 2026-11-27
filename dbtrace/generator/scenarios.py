"""Vulnerable-by-design, near-miss, and benign cloud environment templates."""

from __future__ import annotations

import random

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


def _base_network(
    env_id: str, public_rds: bool = False, allow_compute_to_rds: bool = True
) -> tuple[list[VPC], list[Subnet], list[SecurityGroup]]:
    vpc = VPC(id=f"{env_id}_vpc", cidr="10.0.0.0/16")
    pub_sub = Subnet(id=f"{env_id}_sub_pub", vpc_id=vpc.id, cidr="10.0.1.0/24", is_public=True, route_to_igw=True)
    priv_sub = Subnet(id=f"{env_id}_sub_priv", vpc_id=vpc.id, cidr="10.0.2.0/24", is_public=False, route_to_igw=False)

    app_sg = SecurityGroup(
        id=f"{env_id}_sg_app",
        name="app-sg",
        vpc_id=vpc.id,
        ingress_rules=[IngressRule(from_port=443, to_port=443, cidr="0.0.0.0/0")],
    )
    rds_rules: list[IngressRule] = []
    if allow_compute_to_rds:
        rds_rules.append(IngressRule(from_port=5432, to_port=5432, source_sg_id=app_sg.id))
    if public_rds:
        rds_rules.append(IngressRule(from_port=5432, to_port=5432, cidr="0.0.0.0/0"))

    rds_sg = SecurityGroup(id=f"{env_id}_sg_rds", name="rds-sg", vpc_id=vpc.id, ingress_rules=rds_rules)
    return [vpc], [pub_sub, priv_sub], [app_sg, rds_sg]


def _base_db(
    env_id: str,
    rds_id: str,
    *,
    grant_select_to_app: bool = True,
    use_superuser: bool = False,
    sensitive: bool = True,
) -> tuple[list[DBRole], list[DBTable]]:
    admin_role = DBRole(
        id=f"{env_id}_db_admin",
        rds_id=rds_id,
        name="pg_admin",
        can_login=True,
        is_superuser=True,
        is_rds_superuser=True,
    )
    readonly_group = DBRole(
        id=f"{env_id}_db_ro_grp",
        rds_id=rds_id,
        name="ro_group",
        can_login=False,
    )
    app_role = DBRole(
        id=f"{env_id}_db_app",
        rds_id=rds_id,
        name="app_service",
        can_login=True,
        is_superuser=use_superuser,
        member_of_ids=[readonly_group.id] if grant_select_to_app else [],
    )
    analyst_role = DBRole(
        id=f"{env_id}_db_analyst",
        rds_id=rds_id,
        name="bi_analyst",
        can_login=True,
        member_of_ids=[readonly_group.id],
    )
    grants = {readonly_group.id: ["SELECT"]} if grant_select_to_app else {}
    customers = DBTable(
        id=f"{env_id}_tbl_customers",
        rds_id=rds_id,
        schema_name="public",
        table_name="customers_pii",
        sensitivity=SensitivityLevel.PII if sensitive else SensitivityLevel.LOW,
        grants=grants,
    )
    logs_tbl = DBTable(
        id=f"{env_id}_tbl_audit",
        rds_id=rds_id,
        schema_name="public",
        table_name="app_events",
        sensitivity=SensitivityLevel.LOW,
        grants={app_role.id: ["SELECT", "INSERT"], readonly_group.id: ["SELECT"]},
    )
    return [admin_role, readonly_group, app_role, analyst_role], [customers, logs_tbl]


def build_scenario(env_id: str, scenario_type: str, seed: int) -> CloudEnvironment:
    """Build a realistic AWS + Postgres environment for a given scenario template."""
    rng = random.Random(seed)
    public_rds = scenario_type in ("public_rds_iam", "near_miss_no_db_auth")
    allow_c2r = scenario_type != "near_miss_sg_blocked"
    vpcs, subnets, sgs = _base_network(env_id, public_rds=public_rds, allow_compute_to_rds=allow_c2r)

    rds_id = f"{env_id}_rds_main"
    rds = RDSInstance(
        id=rds_id,
        name=f"prod-pg-{env_id}",
        vpc_id=vpcs[0].id,
        subnet_id=subnets[0].id if public_rds else subnets[1].id,
        security_group_ids=[sgs[1].id],
        publicly_accessible=public_rds,
        encrypted=scenario_type not in ("rds_snapshot_unencrypted", "stratus_rds_share"),
        iam_auth_enabled=scenario_type in ("capital_one_ssrf", "lambda_privesc", "public_rds_iam", "iam_privesc_rollback"),
        has_public_snapshot=scenario_type == "rds_snapshot_unencrypted",
    )

    db_roles, db_tables = _base_db(
        env_id,
        rds_id,
        grant_select_to_app=(scenario_type != "near_miss_wrong_grant"),
        use_superuser=(scenario_type in ("rce_web_app", "capital_one_ssrf") and rng.random() < 0.5),
        sensitive=(scenario_type != "benign_low_sensitivity"),
    )

    policies: list[IAMPolicy] = []
    principals: list[IAMPrincipal] = []
    computes: list[ComputeResource] = []

    if scenario_type == "capital_one_ssrf":
        pol = IAMPolicy(
            id=f"{env_id}_pol_broad",
            name="OverBroadWAFDataPolicy",
            statements=[
                PolicyStatement(effect="Allow", actions=["rds-db:connect", "s3:*", "rds:Describe*"], resources=["*"])
            ],
        )
        role = IAMPrincipal(
            id=f"{env_id}_role_waf",
            arn=f"arn:aws:iam::111122223333:role/{env_id}-waf-role",
            name="waf-ec2-role",
            kind="role",
            attached_policy_ids=[pol.id],
        )
        ext = IAMPrincipal(
            id=f"{env_id}_ext_inet",
            arn="arn:aws:iam::000000000000:user/internet-attacker",
            name="internet-entry",
            kind="user",
            is_external_entry=True,
            has_mfa=False,
        )
        comp = ComputeResource(
            id=f"{env_id}_ec2_waf",
            kind="ec2",
            name="waf-proxy-ec2",
            subnet_id=subnets[0].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=role.id,
            imdsv2_required=False,
            has_public_ip=True,
            has_app_vuln=True,
        )
        policies.append(pol)
        principals.extend([ext, role])
        computes.append(comp)

    elif scenario_type in ("lambda_privesc", "iam_privesc_rollback"):
        privesc_action = (
            ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
            if scenario_type == "lambda_privesc"
            else ["iam:SetDefaultPolicyVersion", "iam:GetPolicyVersion"]
        )
        pol_dev = IAMPolicy(
            id=f"{env_id}_pol_dev",
            name="DevPrivescPolicy",
            statements=[PolicyStatement(effect="Allow", actions=privesc_action, resources=["*"])],
        )
        pol_db = IAMPolicy(
            id=f"{env_id}_pol_db",
            name="RDSConnectPolicy",
            statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect"], resources=["*"])],
        )
        priv_role = IAMPrincipal(
            id=f"{env_id}_role_db_admin",
            arn=f"arn:aws:iam::111122223333:role/{env_id}-db-role",
            name="prod-db-accessor",
            kind="role",
            attached_policy_ids=[pol_db.id],
        )
        dev_user = IAMPrincipal(
            id=f"{env_id}_user_dev",
            arn=f"arn:aws:iam::111122223333:user/{env_id}-dev",
            name="dev-user",
            kind="user",
            has_mfa=False,
            attached_policy_ids=[pol_dev.id],
        )
        comp = ComputeResource(
            id=f"{env_id}_lambda_etl",
            kind="lambda",
            name="etl-worker",
            subnet_id=subnets[1].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=priv_role.id,
            imdsv2_required=True,
            has_public_ip=False,
        )
        policies.extend([pol_dev, pol_db])
        principals.extend([dev_user, priv_role])
        computes.append(comp)

    elif scenario_type == "rce_web_app":
        pol = IAMPolicy(
            id=f"{env_id}_pol_web",
            name="WebAppPolicy",
            statements=[PolicyStatement(effect="Allow", actions=["logs:PutLogEvents"], resources=["*"])],
        )
        role = IAMPrincipal(
            id=f"{env_id}_role_web",
            arn=f"arn:aws:iam::111122223333:role/{env_id}-web-role",
            name="web-ec2-role",
            kind="role",
            attached_policy_ids=[pol.id],
        )
        ext = IAMPrincipal(
            id=f"{env_id}_ext_inet",
            arn="arn:aws:iam::000000000000:user/internet-attacker",
            name="internet-entry",
            kind="user",
            is_external_entry=True,
            has_mfa=False,
        )
        comp = ComputeResource(
            id=f"{env_id}_ec2_web",
            kind="ec2",
            name="legacy-web-app",
            subnet_id=subnets[0].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=role.id,
            imdsv2_required=True,
            has_public_ip=True,
            has_app_vuln=True,
            leaked_db_role_id=db_roles[2].id,
        )
        policies.append(pol)
        principals.extend([ext, role])
        computes.append(comp)

    elif scenario_type in ("rds_snapshot_unencrypted", "stratus_rds_share"):
        acts = (
            ["rds:DescribeDBSnapshots", "rds:ModifyDBSnapshotAttribute"]
            if scenario_type == "stratus_rds_share"
            else ["rds:DescribeDBSnapshots"]
        )
        pol = IAMPolicy(
            id=f"{env_id}_pol_snap",
            name="SnapshotOpsPolicy",
            statements=[PolicyStatement(effect="Allow", actions=acts, resources=["*"])],
        )
        user = IAMPrincipal(
            id=f"{env_id}_user_ops",
            arn=f"arn:aws:iam::111122223333:user/{env_id}-ops",
            name="ops-user",
            kind="user",
            has_mfa=False,
            attached_policy_ids=[pol.id],
        )
        comp = ComputeResource(
            id=f"{env_id}_ec2_bastion",
            kind="ec2",
            name="internal-bastion",
            subnet_id=subnets[1].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=None,
        )
        policies.append(pol)
        principals.append(user)
        computes.append(comp)

    elif scenario_type == "public_rds_iam":
        pol = IAMPolicy(
            id=f"{env_id}_pol_pub",
            name="PublicDBConnect",
            statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect"], resources=["*"])],
        )
        user = IAMPrincipal(
            id=f"{env_id}_user_ext",
            arn=f"arn:aws:iam::111122223333:user/{env_id}-contractor",
            name="contractor-user",
            kind="user",
            has_mfa=False,
            attached_policy_ids=[pol.id],
        )
        comp = ComputeResource(
            id=f"{env_id}_ec2_app",
            kind="ec2",
            name="app-host",
            subnet_id=subnets[1].id,
            security_group_ids=[sgs[0].id],
        )
        policies.append(pol)
        principals.append(user)
        computes.append(comp)

    else:
        # Near-miss & benign scenarios: explicit Deny, blocked SG, wrong grant, or least privilege
        stmts = [PolicyStatement(effect="Allow", actions=["rds-db:connect"], resources=["*"])]
        if scenario_type == "near_miss_explicit_deny":
            stmts.append(PolicyStatement(effect="Deny", actions=["rds-db:connect"], resources=["*"]))
        elif scenario_type == "benign_least_privilege":
            stmts = [PolicyStatement(effect="Allow", actions=["cloudwatch:GetMetricData"], resources=["*"])]

        pol = IAMPolicy(id=f"{env_id}_pol_std", name="StandardAppPolicy", statements=stmts)
        role = IAMPrincipal(
            id=f"{env_id}_role_app",
            arn=f"arn:aws:iam::111122223333:role/{env_id}-app-role",
            name="app-ec2-role",
            kind="role",
            attached_policy_ids=[pol.id],
        )
        user = IAMPrincipal(
            id=f"{env_id}_user_app",
            arn=f"arn:aws:iam::111122223333:user/{env_id}-svc",
            name="svc-user",
            kind="user",
            can_assume_ids=[role.id] if scenario_type != "benign_least_privilege" else [],
            attached_policy_ids=[pol.id],
        )
        comp = ComputeResource(
            id=f"{env_id}_ec2_app",
            kind="ec2",
            name="private-app-server",
            subnet_id=subnets[1].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=role.id,
            imdsv2_required=True,
            has_public_ip=False,
            has_app_vuln=False,
            leaked_db_role_id=db_roles[2].id if scenario_type in ("near_miss_sg_blocked", "near_miss_wrong_grant") else None,
        )
        policies.append(pol)
        principals.extend([user, role])
        computes.append(comp)

    return CloudEnvironment(
        env_id=env_id,
        scenario_type=scenario_type,
        template_family=scenario_type.split("_")[0],
        seed=seed,
        vpcs=vpcs,
        subnets=subnets,
        security_groups=sgs,
        policies=policies,
        principals=principals,
        computes=computes,
        rds_instances=[rds],
        db_roles=db_roles,
        db_tables=db_tables,
    )
