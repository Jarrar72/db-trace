"""Least-privilege read-only collectors for real AWS accounts and PostgreSQL/Neon DBs."""

from __future__ import annotations

import boto3
import psycopg

from dbtrace.schema import (
    VPC,
    CloudEnvironment,
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


def collect_aws_environment(env_id: str = "aws_live", region: str = "us-east-1") -> CloudEnvironment:
    """Read-only collection via boto3 SecurityAudit permissions."""
    iam = boto3.client("iam", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    rds_client = boto3.client("rds", region_name=region)

    auth = iam.get_account_authorization_details(Filter=["User", "Role", "LocalManagedPolicy"])
    policies: list[IAMPolicy] = []
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

    principals: list[IAMPrincipal] = []
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

    vpcs = [VPC(id=v["VpcId"], cidr=v.get("CidrBlock", "10.0.0.0/16")) for v in ec2.describe_vpcs().get("Vpcs", [])]
    subnets = [
        Subnet(id=s["SubnetId"], vpc_id=s["VpcId"], cidr=s.get("CidrBlock", "10.0.0.0/24"))
        for s in ec2.describe_subnets().get("Subnets", [])
    ]
    sgs = []
    for sg in ec2.describe_security_groups().get("SecurityGroups", []):
        rules = []
        for perm in sg.get("IpPermissions", []):
            fp, tp = perm.get("FromPort", 0), perm.get("ToPort", 65535)
            for ipr in perm.get("IpRanges", []):
                rules.append(IngressRule(from_port=fp, to_port=tp, cidr=ipr.get("CidrIp")))
            for pair in perm.get("UserIdGroupPairs", []):
                rules.append(IngressRule(from_port=fp, to_port=tp, source_sg_id=pair.get("GroupId")))
        sgs.append(SecurityGroup(id=sg["GroupId"], name=sg.get("GroupName", sg["GroupId"]), vpc_id=sg["VpcId"], ingress_rules=rules))

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

    return CloudEnvironment(
        env_id=env_id,
        scenario_type="live_aws_scan",
        template_family="live",
        seed=0,
        vpcs=vpcs,
        subnets=subnets,
        security_groups=sgs,
        policies=policies,
        principals=principals,
        rds_instances=rds_list,
    )
