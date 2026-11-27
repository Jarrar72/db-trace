"""Least-privilege read-only collectors for real AWS accounts and PostgreSQL/Neon DBs."""

from __future__ import annotations

import boto3
import psycopg
from botocore.exceptions import ClientError

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


def collect_postgres_grants(conn_str: str, rds_id: str = "real_pg_01") -> tuple[list[DBRole], list[DBTable]]:
    """Collect roles, memberships, and table grants from PostgreSQL/Neon using read-only catalog queries."""
    roles: list[DBRole] = []
    tables: list[DBTable] = []

    with psycopg.connect(conn_str, options="-c default_transaction_read_only=on") as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT oid::text, rolname, rolcanlogin, rolsuper, rolinherit
                FROM pg_roles
                WHERE rolname NOT LIKE 'pg_%'
                ORDER BY rolname
                """
            )
            role_rows = cur.fetchall()
            role_name_to_id = {r[1]: f"{rds_id}_role_{r[1]}" for r in role_rows}

            cur.execute(
                """
                SELECT m.rolname, g.rolname
                FROM pg_auth_members am
                JOIN pg_roles m ON am.member = m.oid
                JOIN pg_roles g ON am.roleid = g.oid
                """
            )
            memberships: dict[str, list[str]] = {}
            for member_name, group_name in cur.fetchall():
                if group_name in role_name_to_id:
                    memberships.setdefault(member_name, []).append(role_name_to_id[group_name])

            for _, rname, can_login, is_super, inherit in role_rows:
                roles.append(
                    DBRole(
                        id=role_name_to_id[rname],
                        rds_id=rds_id,
                        name=rname,
                        can_login=bool(can_login),
                        is_superuser=bool(is_super),
                        is_rds_superuser=rname == "rds_superuser",
                        inherit=bool(inherit),
                        member_of_ids=memberships.get(rname, []),
                    )
                )

            cur.execute(
                """
                SELECT table_schema, table_name, grantee, privilege_type
                FROM information_schema.role_table_grants
                WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
                """
            )
            table_grants: dict[tuple[str, str], dict[str, list[str]]] = {}
            for schema_n, tbl_n, grantee, priv in cur.fetchall():
                key = (schema_n, tbl_n)
                gmap = table_grants.setdefault(key, {})
                rid = role_name_to_id.get(grantee, grantee)
                gmap.setdefault(rid, []).append(priv)

            for (schema_n, tbl_n), gmap in table_grants.items():
                is_pii = any(k in tbl_n.lower() for k in ("user", "customer", "payment", "pii", "secret"))
                tables.append(
                    DBTable(
                        id=f"{rds_id}_tbl_{schema_n}_{tbl_n}",
                        rds_id=rds_id,
                        schema_name=schema_n,
                        table_name=tbl_n,
                        sensitivity=SensitivityLevel.PII if is_pii else SensitivityLevel.MEDIUM,
                        grants=gmap,
                    )
                )
    return roles, tables


def collect_aws_environment(
    env_id: str = "aws_live",
    region: str = "us-east-1",
    access_key_id: str | None = None,
    secret_access_key: str | None = None,
    session_token: str | None = None,
) -> tuple[CloudEnvironment, dict[str, object]]:
    """Read-only collection via boto3 SecurityAudit permissions, gracefully handling SCP-denied services."""
    session_kwargs: dict[str, str] = {"region_name": region}
    if access_key_id and secret_access_key:
        session_kwargs["aws_access_key_id"] = access_key_id
        session_kwargs["aws_secret_access_key"] = secret_access_key
        if session_token:
            session_kwargs["aws_session_token"] = session_token
    session = boto3.Session(**session_kwargs)
    sts = session.client("sts")
    iam = session.client("iam")
    ec2 = session.client("ec2")
    rds_client = session.client("rds")

    caller = sts.get_caller_identity()
    account_id = caller.get("Account", "unknown")
    caller_arn = caller.get("Arn", "unknown")

    warnings: list[str] = []
    policies: list[IAMPolicy] = []
    principals: list[IAMPrincipal] = []
    try:
        auth = iam.get_account_authorization_details(Filter=["User", "Role", "LocalManagedPolicy"])
        for p in auth.get("Policies", []):
            ver = next((v for v in p.get("PolicyVersionList", []) if v.get("IsDefaultVersion")), None)
            doc = ver.get("Document", {}) if ver else {}
            raw_stmts = doc.get("Statement", [])
            if isinstance(raw_stmts, dict):
                raw_stmts = [raw_stmts]
            stmts = [
                PolicyStatement(
                    effect=s.get("Effect", "Allow"),
                    actions=s.get("Action", []) if isinstance(s.get("Action"), list) else [s.get("Action", "*")],
                    resources=s.get("Resource", ["*"]) if isinstance(s.get("Resource"), list) else [s.get("Resource", "*")],
                )
                for s in raw_stmts
            ]
            policies.append(IAMPolicy(id=p["Arn"], name=p["PolicyName"], statements=stmts))

        for u in auth.get("UserDetailList", []):
            principals.append(
                IAMPrincipal(
                    id=u["Arn"],
                    arn=u["Arn"],
                    name=u["UserName"],
                    kind="user",
                    attached_policy_ids=[ap["PolicyArn"] for ap in u.get("AttachedManagedPolicies", [])],
                )
            )
        for r in auth.get("RoleDetailList", []):
            principals.append(
                IAMPrincipal(
                    id=r["Arn"],
                    arn=r["Arn"],
                    name=r["RoleName"],
                    kind="role",
                    attached_policy_ids=[ap["PolicyArn"] for ap in r.get("AttachedManagedPolicies", [])],
                )
            )
    except ClientError as exc:
        warnings.append(f"IAM blocked by policy/SCP: {exc.response['Error']['Code']}")

    vpcs: list[VPC] = []
    try:
        vpcs = [VPC(id=v["VpcId"], cidr=v.get("CidrBlock", "10.0.0.0/16")) for v in ec2.describe_vpcs().get("Vpcs", [])]
    except ClientError as exc:
        warnings.append(f"ec2:DescribeVpcs blocked by SCP: {exc.response['Error']['Code']}")

    subnets: list[Subnet] = []
    try:
        subnets = [
            Subnet(id=s["SubnetId"], vpc_id=s["VpcId"], cidr=s.get("CidrBlock", "10.0.0.0/24"))
            for s in ec2.describe_subnets().get("Subnets", [])
        ]
    except ClientError as exc:
        warnings.append(f"ec2:DescribeSubnets blocked by SCP: {exc.response['Error']['Code']}")

    sgs: list[SecurityGroup] = []
    try:
        for sg in ec2.describe_security_groups().get("SecurityGroups", []):
            rules = []
            for perm in sg.get("IpPermissions", []):
                fp, tp = perm.get("FromPort", 0), perm.get("ToPort", 65535)
                for ipr in perm.get("IpRanges", []):
                    rules.append(IngressRule(from_port=fp, to_port=tp, cidr=ipr.get("CidrIp")))
                for pair in perm.get("UserIdGroupPairs", []):
                    rules.append(IngressRule(from_port=fp, to_port=tp, source_sg_id=pair.get("GroupId")))
            sgs.append(SecurityGroup(id=sg["GroupId"], name=sg.get("GroupName", sg["GroupId"]), vpc_id=sg["VpcId"], ingress_rules=rules))
    except ClientError as exc:
        warnings.append(f"ec2:DescribeSecurityGroups blocked by SCP: {exc.response['Error']['Code']}")

    rds_list: list[RDSInstance] = []
    try:
        rds_list = [
            RDSInstance(
                id=db["DBInstanceIdentifier"],
                name=db["DBInstanceIdentifier"],
                vpc_id=db.get("DBSubnetGroup", {}).get("VpcId", vpcs[0].id if vpcs else "vpc-0"),
                subnet_id=subnets[0].id if subnets else "subnet-0",
                security_group_ids=[g["VpcSecurityGroupId"] for g in db.get("VpcSecurityGroups", [])],
                port=db.get("Endpoint", {}).get("Port", 5432),
                publicly_accessible=db.get("PubliclyAccessible", False),
                encrypted=db.get("StorageEncrypted", True),
                iam_auth_enabled=db.get("IAMDatabaseAuthenticationEnabled", False),
            )
            for db in rds_client.describe_db_instances().get("DBInstances", [])
        ]
    except ClientError as exc:
        warnings.append(f"rds:DescribeDBInstances blocked by SCP: {exc.response['Error']['Code']}")

    computes: list[ComputeResource] = []
    role_by_name = {p.name: p.id for p in principals if p.kind == "role"}
    try:
        for res in ec2.describe_instances().get("Reservations", []):
            for inst in res.get("Instances", []):
                iid = inst["InstanceId"]
                name_tag = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), iid)
                imdsv2 = inst.get("MetadataOptions", {}).get("HttpTokens", "optional") == "required"
                prof_arn = inst.get("IamInstanceProfile", {}).get("Arn", "")
                prof_name = prof_arn.split("/")[-1] if prof_arn else ""
                matched_role_id = role_by_name.get(prof_name)
                computes.append(
                    ComputeResource(
                        id=iid,
                        kind="ec2",
                        name=name_tag,
                        subnet_id=inst.get("SubnetId", "subnet-0"),
                        security_group_ids=[g["GroupId"] for g in inst.get("SecurityGroups", [])],
                        iam_role_id=matched_role_id,
                        imdsv2_required=imdsv2,
                        has_public_ip=bool(inst.get("PublicIpAddress")),
                    )
                )
    except ClientError as exc:
        warnings.append(f"ec2:DescribeInstances blocked by SCP: {exc.response['Error']['Code']}")

    env = CloudEnvironment(
        env_id=env_id,
        scenario_type="live_aws_scan",
        template_family="live",
        seed=0,
        vpcs=vpcs,
        subnets=subnets,
        security_groups=sgs,
        policies=policies,
        principals=principals,
        computes=computes,
        rds_instances=rds_list,
    )
    meta = {
        "account_id": account_id,
        "caller_arn": caller_arn,
        "region": region,
        "warnings": warnings,
    }
    return env, meta
