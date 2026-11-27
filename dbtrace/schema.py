"""Shared Pydantic schemas for AWS + PostgreSQL cloud environments and attack paths."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class SensitivityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PII = "pii"


class PolicyStatement(BaseModel):
    effect: Literal["Allow", "Deny"]
    actions: list[str] = Field(default_factory=list)
    not_actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=lambda: ["*"])
    condition: dict[str, dict[str, object]] = Field(default_factory=dict)


class IAMPolicy(BaseModel):
    id: str
    name: str
    is_aws_managed: bool = False
    statements: list[PolicyStatement] = Field(default_factory=list)


class IAMPrincipal(BaseModel):
    id: str
    arn: str
    name: str
    kind: Literal["user", "role", "group"]
    has_mfa: bool = True
    is_external_entry: bool = False
    attached_policy_ids: list[str] = Field(default_factory=list)
    inline_statements: list[PolicyStatement] = Field(default_factory=list)
    trust_principals: list[str] = Field(default_factory=list)
    can_assume_ids: list[str] = Field(default_factory=list)
    boundary_policy_id: str | None = None


class ComputeResource(BaseModel):
    id: str
    kind: Literal["ec2", "lambda"]
    name: str
    subnet_id: str
    security_group_ids: list[str] = Field(default_factory=list)
    iam_role_id: str | None = None
    imdsv2_required: bool = True
    has_public_ip: bool = False
    has_app_vuln: bool = False
    leaked_db_role_id: str | None = None


class IngressRule(BaseModel):
    from_port: int
    to_port: int
    protocol: str = "tcp"
    cidr: str | None = None
    source_sg_id: str | None = None


class SecurityGroup(BaseModel):
    id: str
    name: str
    vpc_id: str
    ingress_rules: list[IngressRule] = Field(default_factory=list)


class Subnet(BaseModel):
    id: str
    vpc_id: str
    cidr: str
    is_public: bool = False
    route_to_igw: bool = False


class VPC(BaseModel):
    id: str
    cidr: str = "10.0.0.0/16"


class RDSInstance(BaseModel):
    id: str
    name: str
    vpc_id: str
    subnet_id: str
    security_group_ids: list[str] = Field(default_factory=list)
    port: int = 5432
    publicly_accessible: bool = False
    encrypted: bool = True
    iam_auth_enabled: bool = False
    has_public_snapshot: bool = False


class DBRole(BaseModel):
    id: str
    rds_id: str
    name: str
    can_login: bool = True
    is_superuser: bool = False
    is_rds_superuser: bool = False
    inherit: bool = True
    member_of_ids: list[str] = Field(default_factory=list)


class DBTable(BaseModel):
    id: str
    rds_id: str
    schema_name: str = "public"
    table_name: str
    sensitivity: SensitivityLevel = SensitivityLevel.MEDIUM
    # role_id -> list of privileges (SELECT, INSERT, UPDATE, DELETE, ALL)
    grants: dict[str, list[str]] = Field(default_factory=dict)


class CloudEnvironment(BaseModel):
    env_id: str
    scenario_type: str
    template_family: str
    seed: int
    vpcs: list[VPC] = Field(default_factory=list)
    subnets: list[Subnet] = Field(default_factory=list)
    security_groups: list[SecurityGroup] = Field(default_factory=list)
    policies: list[IAMPolicy] = Field(default_factory=list)
    principals: list[IAMPrincipal] = Field(default_factory=list)
    computes: list[ComputeResource] = Field(default_factory=list)
    rds_instances: list[RDSInstance] = Field(default_factory=list)
    db_roles: list[DBRole] = Field(default_factory=list)
    db_tables: list[DBTable] = Field(default_factory=list)


class AccessPathRecord(BaseModel):
    """A candidate Identity -> Compute -> Network -> RDS -> DBRole -> DBTable path."""

    path_id: str
    env_id: str
    scenario_type: str
    template_family: str
    entry_principal_id: str
    target_role_id: str
    compute_id: str | None = None
    source_sg_id: str | None = None
    rds_sg_id: str | None = None
    rds_id: str
    db_role_id: str
    db_table_id: str
    via_internet: bool = False
    via_snapshot: bool = False
    label_exploitable: int = 0
    failure_reason: str = ""
