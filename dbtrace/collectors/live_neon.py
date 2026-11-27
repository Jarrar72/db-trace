"""Live Neon/PostgreSQL cloud scanner, realistic vulnerability seeder, and live SQL remediator."""

from __future__ import annotations

import psycopg

from dbtrace.collectors.aws_pg import collect_postgres_grants
from dbtrace.schema import (
    VPC,
    CloudEnvironment,
    ComputeResource,
    IAMPolicy,
    IAMPrincipal,
    IngressRule,
    PolicyStatement,
    RDSInstance,
    SecurityGroup,
    Subnet,
)


def seed_live_neon_vulnerabilities(conn_str: str) -> dict[str, object]:
    """Create realistic, safe-to-test PostgreSQL misconfigurations on the live Neon cloud DB."""
    actions_taken: list[str] = []
    with psycopg.connect(conn_str, autocommit=True) as conn:
        with conn.cursor() as cur:
            # 1. Create realistic tables (PII + non-PII)
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS public.customers_pii (
                    id SERIAL PRIMARY KEY,
                    full_name TEXT,
                    email TEXT,
                    ssn_last4 TEXT
                );
                CREATE TABLE IF NOT EXISTS public.payment_cards_pii (
                    id SERIAL PRIMARY KEY,
                    customer_id INT,
                    card_token TEXT
                );
                CREATE TABLE IF NOT EXISTS public.app_events (
                    id SERIAL PRIMARY KEY,
                    event_type TEXT,
                    created_at TIMESTAMPTZ DEFAULT now()
                );
                """
            )
            actions_taken.append("Ensured tables: customers_pii, payment_cards_pii, app_events")

            # 2. Create overly permissive grants to PUBLIC (classic real-world Postgres misconfiguration)
            cur.execute("GRANT SELECT ON TABLE public.customers_pii TO PUBLIC;")
            cur.execute("GRANT SELECT ON TABLE public.payment_cards_pii TO PUBLIC;")
            cur.execute("GRANT SELECT, INSERT ON TABLE public.app_events TO PUBLIC;")
            actions_taken.append("Injected misconfiguration: GRANT SELECT ON customers_pii & payment_cards_pii TO PUBLIC")

    return {"status": "seeded", "actions": actions_taken}


def apply_live_neon_fix(conn_str: str, table_name: str = "customers_pii") -> dict[str, object]:
    """Apply a verified SQL remediation directly to the live Neon cloud database."""
    allowed = {"customers_pii", "payment_cards_pii"}
    if table_name not in allowed:
        raise ValueError(f"Unsupported table for live fix: {table_name}")
    sql = f"REVOKE ALL PRIVILEGES ON TABLE public.{table_name} FROM PUBLIC;"
    with psycopg.connect(conn_str, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
    return {"status": "applied", "sql": sql}


def scan_live_neon_environment(conn_str: str) -> tuple[CloudEnvironment, dict[str, object]]:
    """Collect real roles & grants from Neon Cloud Postgres and build a live CloudEnvironment graph."""
    rds_id = "neon_cloud_prod"
    roles, tables = collect_postgres_grants(conn_str, rds_id=rds_id)

    # Check if PUBLIC has SELECT on any table (pg_catalog / information_schema)
    public_grants: dict[str, list[str]] = {}
    with psycopg.connect(conn_str, options="-c default_transaction_read_only=on") as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT table_name, privilege_type
                FROM information_schema.role_table_grants
                WHERE grantee = 'PUBLIC' AND table_schema = 'public'
                """
            )
            for tbl, priv in cur.fetchall():
                public_grants.setdefault(tbl, []).append(priv)

    # Attach PUBLIC grants onto login roles so transitive exposure is accurately modeled
    for t in tables:
        if t.table_name in public_grants:
            for r in roles:
                if r.can_login:
                    t.grants.setdefault(r.id, [])
                    for priv in public_grants[t.table_name]:
                        if priv not in t.grants[r.id]:
                            t.grants[r.id].append(priv)

    # Wrap the real Neon database inside its cloud network/IAM context (public endpoint on port 5432)
    vpc = VPC(id="neon_vpc", cidr="10.0.0.0/16")
    pub_sub = Subnet(id="neon_sub_pub", vpc_id=vpc.id, cidr="10.0.1.0/24", is_public=True, route_to_igw=True)
    app_sg = SecurityGroup(
        id="neon_sg_app",
        name="cloud-app-sg",
        vpc_id=vpc.id,
        ingress_rules=[IngressRule(from_port=443, to_port=443, cidr="0.0.0.0/0")],
    )
    rds_sg = SecurityGroup(
        id="neon_sg_db",
        name="neon-endpoint-sg",
        vpc_id=vpc.id,
        ingress_rules=[
            IngressRule(from_port=5432, to_port=5432, cidr="0.0.0.0/0"),
            IngressRule(from_port=5432, to_port=5432, source_sg_id=app_sg.id),
        ],
    )
    pol = IAMPolicy(
        id="neon_pol_app",
        name="AppDBAccessPolicy",
        statements=[PolicyStatement(effect="Allow", actions=["rds-db:connect", "rds:Describe*"], resources=["*"])],
    )
    role = IAMPrincipal(
        id="neon_role_app",
        arn="arn:aws:iam::live-cloud:role/web-api-role",
        name="web-api-role",
        kind="role",
        attached_policy_ids=[pol.id],
    )
    ext = IAMPrincipal(
        id="neon_ext_inet",
        arn="arn:aws:iam::000000000000:user/external-internet",
        name="internet-attacker",
        kind="user",
        is_external_entry=True,
        has_mfa=False,
        attached_policy_ids=[pol.id],
    )
    comp = ComputeResource(
        id="neon_app_srv",
        kind="ec2",
        name="public-api-server",
        subnet_id=pub_sub.id,
        security_group_ids=[app_sg.id],
        iam_role_id=role.id,
        imdsv2_required=False,
        has_public_ip=True,
        has_app_vuln=True,
        leaked_db_role_id=roles[0].id if roles else None,
    )
    rds = RDSInstance(
        id=rds_id,
        name="ep-frosty-credit (Neon Cloud PG 18)",
        vpc_id=vpc.id,
        subnet_id=pub_sub.id,
        security_group_ids=[rds_sg.id],
        port=5432,
        publicly_accessible=True,
        encrypted=True,
        iam_auth_enabled=True,
    )

    env = CloudEnvironment(
        env_id="live_neon_cloud",
        scenario_type="live_neon_postgres",
        template_family="live_cloud",
        seed=2026,
        vpcs=[vpc],
        subnets=[pub_sub],
        security_groups=[app_sg, rds_sg],
        policies=[pol],
        principals=[ext, role],
        computes=[comp],
        rds_instances=[rds],
        db_roles=roles,
        db_tables=tables,
    )
    meta = {
        "host": "ep-frosty-credit-bfm5ne8d.c-5.us-west-2.aws.neon.tech",
        "roles_discovered": len(roles),
        "tables_discovered": len(tables),
        "public_grant_tables": list(public_grants.keys()),
    }
    return env, meta
