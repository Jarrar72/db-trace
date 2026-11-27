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
    public_rds = scenario_type in (
        "public_rds_iam",
        "near_miss_no_db_auth",
        "identity_no_mfa_snowflake",
        "azure_entra_postgres_pivot",
        "gcp_default_sa_cloudsql",
    )
    allow_c2r = scenario_type not in (
        "near_miss_sg_blocked",
        "near_miss_azure_private_endpoint",
        "near_miss_gcp_vpc_sc",
    )
    provider = (
        "azure"
        if scenario_type in ("azure_entra_postgres_pivot", "near_miss_azure_private_endpoint")
        else "gcp"
        if scenario_type in ("gcp_default_sa_cloudsql", "near_miss_gcp_vpc_sc")
        else "aws"
    )
    audit_logging_enabled = scenario_type not in ("leaked_key_takeover", "k8s_pod_cloud_pivot")
    vpcs, subnets, sgs = _base_network(env_id, public_rds=public_rds, allow_compute_to_rds=allow_c2r)

    rds_id = f"{env_id}_rds_main"
    rds = RDSInstance(
        id=rds_id,
        name=(
            f"az-pg-flex-{env_id}"
            if provider == "azure"
            else f"gcp-cloudsql-{env_id}"
            if provider == "gcp"
            else f"prod-pg-{env_id}"
        ),
        vpc_id=vpcs[0].id,
        subnet_id=subnets[0].id if public_rds else subnets[1].id,
        security_group_ids=[sgs[1].id],
        publicly_accessible=public_rds,
        encrypted=scenario_type not in ("rds_snapshot_unencrypted", "stratus_rds_share"),
        iam_auth_enabled=scenario_type in (
            "capital_one_ssrf",
            "lambda_privesc",
            "public_rds_iam",
            "iam_privesc_rollback",
            "leaked_key_takeover",
            "k8s_pod_cloud_pivot",
            "identity_no_mfa_snowflake",
            "cicd_oidc_supply_chain",
            "azure_entra_postgres_pivot",
            "gcp_default_sa_cloudsql",
            "ai_ml_notebook_exposure",
        ),
        has_public_snapshot=scenario_type == "rds_snapshot_unencrypted",
    )

    db_roles, db_tables = _base_db(
        env_id,
        rds_id,
        grant_select_to_app=(scenario_type != "near_miss_wrong_grant"),
        use_superuser=(
            scenario_type in ("rce_web_app", "capital_one_ssrf", "react2shell_rce_2025", "k8s_pod_cloud_pivot")
            and rng.random() < 0.65
        ),
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

    elif scenario_type == "leaked_key_takeover":
        # Chain B: Leaked static access key in Git repo -> IAM privesc -> Disable CloudTrail -> RDS exfil
        pol = IAMPolicy(
            id=f"{env_id}_pol_leaked",
            name="LeakedDevAdminPolicy",
            statements=[
                PolicyStatement(
                    effect="Allow",
                    actions=["iam:AttachUserPolicy", "sts:AssumeRole", "rds-db:connect", "cloudtrail:StopLogging"],
                    resources=["*"],
                )
            ],
        )
        user = IAMPrincipal(
            id=f"{env_id}_user_leaked",
            arn=f"arn:aws:iam::111122223333:user/{env_id}-git-leaked-dev",
            name="git-leaked-dev-key",
            kind="user",
            has_mfa=False,
            has_long_lived_key=True,
            attached_policy_ids=[pol.id],
        )
        comp = ComputeResource(
            id=f"{env_id}_ec2_ci",
            kind="ec2",
            name="build-runner-ec2",
            subnet_id=subnets[0].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=user.id,
            has_public_ip=True,
            imdsv2_required=False,
        )
        policies.append(pol)
        principals.append(user)
        computes.append(comp)

    elif scenario_type == "k8s_pod_cloud_pivot":
        # Chain C: Exposed K8s / IngressNightmare / runC privileged pod -> node cloud role -> RDS
        pol = IAMPolicy(
            id=f"{env_id}_pol_eks_node",
            name="EKSNodeOverBroadPolicy",
            statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect", "s3:*", "ec2:Describe*"], resources=["*"])],
        )
        role = IAMPrincipal(
            id=f"{env_id}_role_eks_node",
            arn=f"arn:aws:iam::111122223333:role/{env_id}-eks-worker-role",
            name="eks-worker-node-role",
            kind="role",
            attached_policy_ids=[pol.id],
        )
        ext = IAMPrincipal(
            id=f"{env_id}_ext_k8s",
            arn="arn:aws:iam::000000000000:external/ingress-nginx",
            name="internet-ingress-nginx",
            kind="user",
            has_mfa=False,
            is_external_entry=True,
        )
        comp = ComputeResource(
            id=f"{env_id}_k8s_pod",
            kind="k8s_pod",
            name="privileged-api-pod",
            subnet_id=subnets[0].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=role.id,
            imdsv2_required=False,
            has_public_ip=True,
            has_app_vuln=True,
            leaked_db_role_id=db_roles[2].id,
        )
        policies.append(pol)
        principals.extend([ext, role])
        computes.append(comp)

    elif scenario_type == "identity_no_mfa_snowflake":
        # Chain D: Stolen credential with no MFA (Snowflake 2024 / Scattered Spider pattern) -> Public DB
        pol = IAMPolicy(
            id=f"{env_id}_pol_nomfa",
            name="StandingAnalystDBPolicy",
            statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect", "rds:Describe*"], resources=["*"])],
        )
        user = IAMPrincipal(
            id=f"{env_id}_user_nomfa",
            arn=f"arn:aws:iam::111122223333:user/{env_id}-contractor-nomfa",
            name="stolen-cred-no-mfa",
            kind="user",
            has_mfa=False,
            has_long_lived_key=True,
            attached_policy_ids=[pol.id],
        )
        comp = ComputeResource(
            id=f"{env_id}_ec2_bi",
            kind="ec2",
            name="bi-portal-host",
            subnet_id=subnets[1].id,
            security_group_ids=[sgs[0].id],
        )
        policies.append(pol)
        principals.append(user)
        computes.append(comp)

    elif scenario_type == "cicd_oidc_supply_chain":
        # Chain E: Broad GitHub Actions OIDC trust (tj-actions / Google H1 2026 OIDC abuse)
        pol = IAMPolicy(
            id=f"{env_id}_pol_oidc",
            name="BroadOIDCDeployPolicy",
            statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect", "iam:PassRole", "secretsmanager:*"], resources=["*"])],
        )
        role = IAMPrincipal(
            id=f"{env_id}_role_oidc",
            arn=f"arn:aws:iam::111122223333:role/{env_id}-gh-oidc-deploy",
            name="github-oidc-broad-role",
            kind="role",
            has_mfa=False,
            has_broad_oidc_trust=True,
            attached_policy_ids=[pol.id],
        )
        ext = IAMPrincipal(
            id=f"{env_id}_ext_ci",
            arn="arn:aws:iam::000000000000:external/pr-workflow",
            name="untrusted-pr-workflow",
            kind="user",
            has_mfa=False,
            is_external_entry=True,
        )
        comp = ComputeResource(
            id=f"{env_id}_ci_runner",
            kind="ec2",
            name="ci-cd-deploy-runner",
            subnet_id=subnets[0].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=role.id,
            imdsv2_required=False,
            has_public_ip=True,
            has_app_vuln=True,
            leaked_db_role_id=db_roles[2].id,
        )
        policies.append(pol)
        principals.extend([ext, role])
        computes.append(comp)

    elif scenario_type == "react2shell_rce_2025":
        # 2025-2026 Internet-facing RCE (React2Shell CVE-2025-55182 / XWiki CVE-2025-24893)
        pol = IAMPolicy(
            id=f"{env_id}_pol_web_rce",
            name="WebFrontendAppPolicy",
            statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect", "s3:GetObject"], resources=["*"])],
        )
        role = IAMPrincipal(
            id=f"{env_id}_role_web_rce",
            arn=f"arn:aws:iam::111122223333:role/{env_id}-nextjs-ssr-role",
            name="nextjs-ssr-instance-role",
            kind="role",
            attached_policy_ids=[pol.id],
        )
        ext = IAMPrincipal(
            id=f"{env_id}_ext_rce",
            arn="arn:aws:iam::000000000000:external/cve-2025-55182",
            name="internet-react2shell-rce",
            kind="user",
            has_mfa=False,
            is_external_entry=True,
        )
        comp = ComputeResource(
            id=f"{env_id}_ec2_react",
            kind="ec2",
            name="public-nextjs-app-ec2",
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

    elif scenario_type == "azure_entra_postgres_pivot":
        # Chain F (Azure): Entra ID password spray / no Conditional Access + Public Azure PG Flexible Server
        pol = IAMPolicy(
            id=f"{env_id}_pol_az_owner",
            name="AzureSubscriptionContributor",
            statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect", "*"], resources=["*"])],
        )
        user = IAMPrincipal(
            id=f"{env_id}_az_entra_sp",
            arn=f"azure://entra-id/service-principal/{env_id}-legacy-app",
            name="entra-legacy-sp-no-mfa",
            kind="user",
            has_mfa=False,
            has_long_lived_key=True,
            attached_policy_ids=[pol.id],
        )
        comp = ComputeResource(
            id=f"{env_id}_az_vm",
            kind="azure_vm",
            name="az-app-vm-eastus",
            subnet_id=subnets[0].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=user.id,
            imdsv2_required=False,
            has_public_ip=True,
            has_app_vuln=True,
        )
        policies.append(pol)
        principals.append(user)
        computes.append(comp)

    elif scenario_type == "gcp_default_sa_cloudsql":
        # GCP: Default Compute Engine Service Account (Editor) + Cloud SQL Public IPv4
        pol = IAMPolicy(
            id=f"{env_id}_pol_gcp_editor",
            name="roles/editor-default-sa",
            statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect", "cloudsql.*", "*"], resources=["*"])],
        )
        sa = IAMPrincipal(
            id=f"{env_id}_gcp_sa",
            arn=f"gcp://iam/serviceAccount/{env_id}-compute@developer.gserviceaccount.com",
            name="default-compute-sa-editor",
            kind="role",
            has_mfa=False,
            attached_policy_ids=[pol.id],
        )
        ext = IAMPrincipal(
            id=f"{env_id}_ext_gcp",
            arn="gcp://external/internet",
            name="internet-entry-gcp",
            kind="user",
            has_mfa=False,
            is_external_entry=True,
        )
        comp = ComputeResource(
            id=f"{env_id}_gcp_gce",
            kind="gcp_gce",
            name="gce-web-instance-us-central1",
            subnet_id=subnets[0].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=sa.id,
            imdsv2_required=False,
            has_public_ip=True,
            has_app_vuln=True,
            leaked_db_role_id=db_roles[2].id,
        )
        policies.append(pol)
        principals.extend([ext, sa])
        computes.append(comp)

    elif scenario_type == "ai_ml_notebook_exposure":
        # 2025-2026 AI/ML Shadow Notebook / Model Endpoint with over-privileged DB access
        pol = IAMPolicy(
            id=f"{env_id}_pol_ml_nb",
            name="SageMakerFullDataAccess",
            statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect", "s3:*"], resources=["*"])],
        )
        role = IAMPrincipal(
            id=f"{env_id}_role_ml_nb",
            arn=f"arn:aws:iam::111122223333:role/{env_id}-ml-notebook-role",
            name="shadow-jupyter-ml-role",
            kind="role",
            attached_policy_ids=[pol.id],
        )
        ext = IAMPrincipal(
            id=f"{env_id}_ext_ml",
            arn="arn:aws:iam::000000000000:external/public-jupyter",
            name="internet-public-notebook",
            kind="user",
            has_mfa=False,
            is_external_entry=True,
        )
        comp = ComputeResource(
            id=f"{env_id}_ec2_ml",
            kind="ec2",
            name="public-ml-notebook-host",
            subnet_id=subnets[0].id,
            security_group_ids=[sgs[0].id],
            iam_role_id=role.id,
            imdsv2_required=False,
            has_public_ip=True,
            has_app_vuln=True,
            leaked_db_role_id=db_roles[2].id,
        )
        policies.append(pol)
        principals.extend([ext, role])
        computes.append(comp)

    else:
        # Near-miss & benign scenarios: explicit Deny, blocked SG, wrong grant, private endpoints, or least privilege
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
        provider=provider,
        audit_logging_enabled=audit_logging_enabled,
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
