"""Offline AWS IAM policy evaluator and privilege-escalation detector."""

from __future__ import annotations

import fnmatch
from collections import deque

from dbtrace.schema import CloudEnvironment, IAMPolicy, IAMPrincipal, PolicyStatement


def _match_pattern(pattern: str, value: str) -> bool:
    if pattern == "*":
        return True
    return fnmatch.fnmatchcase(value.lower(), pattern.lower())


def _statement_matches(stmt: PolicyStatement, action: str, resource: str) -> bool:
    res_match = any(_match_pattern(r, resource) for r in stmt.resources)
    if not res_match:
        return False
    if stmt.actions:
        return any(_match_pattern(a, action) for a in stmt.actions)
    if stmt.not_actions:
        return not any(_match_pattern(a, action) for a in stmt.not_actions)
    return False


def get_principal_statements(
    principal: IAMPrincipal, policy_map: dict[str, IAMPolicy]
) -> list[PolicyStatement]:
    stmts = list(principal.inline_statements)
    for pid in principal.attached_policy_ids:
        pol = policy_map.get(pid)
        if pol:
            stmts.extend(pol.statements)
    return stmts


def evaluate_iam_action(
    principal: IAMPrincipal,
    action: str,
    resource: str,
    policy_map: dict[str, IAMPolicy],
) -> bool:
    """Evaluate AWS IAM effective permission: Explicit Deny > Boundary > Allow."""
    stmts = get_principal_statements(principal, policy_map)

    for stmt in stmts:
        if stmt.effect == "Deny" and _statement_matches(stmt, action, resource):
            return False

    allowed = any(
        stmt.effect == "Allow" and _statement_matches(stmt, action, resource) for stmt in stmts
    )
    if not allowed:
        return False

    if principal.boundary_policy_id:
        boundary = policy_map.get(principal.boundary_policy_id)
        if boundary is None:
            return False
        b_deny = any(
            s.effect == "Deny" and _statement_matches(s, action, resource)
            for s in boundary.statements
        )
        b_allow = any(
            s.effect == "Allow" and _statement_matches(s, action, resource)
            for s in boundary.statements
        )
        if b_deny or not b_allow:
            return False

    return True


def has_privesc_capability(principal: IAMPrincipal, policy_map: dict[str, IAMPolicy]) -> bool:
    """Check Rhino Security Labs IAM privilege-escalation prerequisite combinations."""
    ev = lambda act: evaluate_iam_action(principal, act, "*", policy_map)  # noqa: E731

    if ev("iam:SetDefaultPolicyVersion") or ev("iam:CreatePolicyVersion"):
        return True
    if ev("iam:AttachRolePolicy") or ev("iam:AttachUserPolicy") or ev("iam:PutRolePolicy"):
        return True
    if ev("iam:UpdateAssumeRolePolicy"):
        return True
    if ev("iam:PassRole") and (
        (ev("lambda:CreateFunction") and ev("lambda:InvokeFunction")) or ev("ec2:RunInstances")
    ):
        return True
    return False


def reachable_roles(
    start_principal_id: str,
    env: CloudEnvironment,
    policy_map: dict[str, IAMPolicy],
) -> set[str]:
    """BFS over sts:AssumeRole and privilege-escalation edges to find reachable role IDs."""
    p_map = {p.id: p for p in env.principals}
    visited: set[str] = {start_principal_id}
    queue: deque[str] = deque([start_principal_id])

    while queue:
        curr_id = queue.popleft()
        curr = p_map.get(curr_id)
        if curr is None:
            continue

        # Direct sts:AssumeRole edges
        if evaluate_iam_action(curr, "sts:AssumeRole", "*", policy_map):
            for target_id in curr.can_assume_ids:
                target = p_map.get(target_id)
                if target and target_id not in visited:
                    if not target.trust_principals or curr_id in target.trust_principals or "*" in target.trust_principals:
                        visited.add(target_id)
                        queue.append(target_id)

        # Privilege escalation lets a principal reach privileged roles in the env
        if has_privesc_capability(curr, policy_map):
            for candidate in env.principals:
                if candidate.kind == "role" and candidate.id not in visited:
                    visited.add(candidate.id)
                    queue.append(candidate.id)

    return visited
