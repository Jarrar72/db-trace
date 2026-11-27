"""Generate realistic CloudTrail and pgaudit logs for remediation verification."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel

from dbtrace.schema import CloudEnvironment


class AccessLogEvent(BaseModel):
    event_id: str
    env_id: str
    timestamp: str
    source: str  # "cloudtrail" or "pgaudit"
    principal_id: str
    db_role_id: str | None = None
    rds_id: str | None = None
    table_id: str | None = None
    action: str
    source_sg_id: str | None = None
    source_ip: str = "10.0.1.25"
    is_legitimate: bool = True
    is_attack: bool = False


def generate_env_logs(
    env: CloudEnvironment, n_days: int = 30, seed: int = 42
) -> list[AccessLogEvent]:
    """Generate legitimate business-hours CloudTrail + pgaudit traffic for an environment."""
    rng = random.Random(seed + env.seed)
    events: list[AccessLogEvent] = []
    base_time = datetime(2026, 10, 1, 9, 0, 0, tzinfo=UTC)
    ev_idx = 0

    rds = env.rds_instances[0] if env.rds_instances else None
    app_roles = [r for r in env.db_roles if r.can_login and not r.is_superuser]
    non_ext_principals = [p for p in env.principals if not p.is_external_entry]

    for day in range(n_days):
        day_start = base_time + timedelta(days=day)
        # Legitimate application traffic (Compute -> RDS -> app_events / low-sensitivity tables)
        n_daily = rng.randint(4, 8)
        for _ in range(n_daily):
            ev_idx += 1
            ts = day_start + timedelta(minutes=rng.randint(0, 480))
            comp = env.computes[0] if env.computes else None
            prin_id = comp.iam_role_id if (comp and comp.iam_role_id) else (
                non_ext_principals[0].id if non_ext_principals else env.principals[0].id
            )
            if rds and rds.iam_auth_enabled:
                events.append(
                    AccessLogEvent(
                        event_id=f"{env.env_id}_ct_{ev_idx:05d}",
                        env_id=env.env_id,
                        timestamp=ts.isoformat(),
                        source="cloudtrail",
                        principal_id=prin_id,
                        rds_id=rds.id,
                        action="rds-db:connect",
                        source_sg_id=comp.security_group_ids[0] if comp and comp.security_group_ids else None,
                        is_legitimate=True,
                    )
                )
            if rds and app_roles and env.db_tables:
                ev_idx += 1
                # Legitimate app queries mostly hit non-PII tables, occasionally PII via app_service
                target_tbl = env.db_tables[-1]
                db_role = app_roles[0]
                events.append(
                    AccessLogEvent(
                        event_id=f"{env.env_id}_pg_{ev_idx:05d}",
                        env_id=env.env_id,
                        timestamp=ts.isoformat(),
                        source="pgaudit",
                        principal_id=prin_id,
                        db_role_id=db_role.id,
                        rds_id=rds.id,
                        table_id=target_tbl.id,
                        action="SELECT",
                        source_sg_id=comp.security_group_ids[0] if comp and comp.security_group_ids else None,
                        is_legitimate=True,
                    )
                )

    return events
