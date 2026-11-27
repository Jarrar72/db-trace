"""CLI to generate synthetic AWS+PostgreSQL environments and labeled access paths."""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import pandas as pd

from dbtrace.generator.scenarios import build_scenario
from dbtrace.labeling.oracle import enumerate_and_label_paths
from dbtrace.schema import CloudEnvironment, DBRole, DBTable, SensitivityLevel

SCENARIO_WEIGHTS: list[tuple[str, float]] = [
    ("capital_one_ssrf", 0.08),
    ("lambda_privesc", 0.06),
    ("iam_privesc_rollback", 0.05),
    ("rce_web_app", 0.06),
    ("rds_snapshot_unencrypted", 0.04),
    ("stratus_rds_share", 0.04),
    ("public_rds_iam", 0.06),
    # 2015-2026 Multi-Cloud Attack Chains (Chains B-F, RCE, AI/ML)
    ("leaked_key_takeover", 0.06),
    ("k8s_pod_cloud_pivot", 0.06),
    ("identity_no_mfa_snowflake", 0.06),
    ("cicd_oidc_supply_chain", 0.06),
    ("react2shell_rce_2025", 0.06),
    ("azure_entra_postgres_pivot", 0.06),
    ("gcp_default_sa_cloudsql", 0.06),
    ("ai_ml_notebook_exposure", 0.04),
    # Benign Look-Alikes & Near-Misses (Multi-Cloud)
    ("near_miss_explicit_deny", 0.04),
    ("near_miss_sg_blocked", 0.04),
    ("near_miss_wrong_grant", 0.03),
    ("near_miss_azure_private_endpoint", 0.02),
    ("near_miss_gcp_vpc_sc", 0.02),
    ("benign_least_privilege", 0.02),
    ("benign_low_sensitivity", 0.02),
]


def _augment_environment(env: CloudEnvironment, rng: random.Random) -> CloudEnvironment:
    """Add realistic variation (extra tables & DB roles) so 100 envs yield ~3,000-5,000 paths."""
    rds = env.rds_instances[0]
    extra_tables = rng.randint(1, 3)
    for t_i in range(extra_tables):
        sens = rng.choice([SensitivityLevel.LOW, SensitivityLevel.MEDIUM, SensitivityLevel.HIGH, SensitivityLevel.PII])
        grants = {env.db_roles[1].id: ["SELECT"]} if rng.random() < 0.7 else {}
        env.db_tables.append(
            DBTable(
                id=f"{env.env_id}_tbl_extra_{t_i}",
                rds_id=rds.id,
                schema_name="public" if rng.random() < 0.7 else "analytics",
                table_name=f"orders_{t_i}" if sens != SensitivityLevel.PII else f"payments_pii_{t_i}",
                sensitivity=sens,
                grants=grants,
            )
        )
    if rng.random() < 0.6:
        env.db_roles.append(
            DBRole(
                id=f"{env.env_id}_db_svc_ro",
                rds_id=rds.id,
                name="reporting_svc",
                can_login=True,
                member_of_ids=[env.db_roles[1].id] if rng.random() < 0.5 else [],
            )
        )
    return env


def generate_dataset(n_envs: int = 100, seed: int = 42, out_dir: Path = Path("data")) -> dict[str, object]:
    rng = random.Random(seed)
    envs_dir = out_dir / "envs"
    envs_dir.mkdir(parents=True, exist_ok=True)

    names = [s for s, _ in SCENARIO_WEIGHTS]
    weights = [w for _, w in SCENARIO_WEIGHTS]

    all_paths = []
    for i in range(n_envs):
        env_id = f"env_{i:03d}"
        scenario = rng.choices(names, weights=weights, k=1)[0]
        env_seed = seed + i * 31
        env = build_scenario(env_id, scenario, env_seed)
        env = _augment_environment(env, rng)

        (envs_dir / f"{env_id}.json").write_text(env.model_dump_json(indent=2), encoding="utf-8")
        paths = enumerate_and_label_paths(env)
        all_paths.extend([p.model_dump() for p in paths])

    df = pd.DataFrame(all_paths)
    df.to_csv(out_dir / "paths.csv", index=False)

    n_pos = int(df["label_exploitable"].sum()) if len(df) else 0
    manifest = {
        "n_environments": n_envs,
        "n_paths": len(df),
        "n_exploitable": n_pos,
        "exploitable_ratio": round(n_pos / max(len(df), 1), 4),
        "seed": seed,
        "scenarios": df["scenario_type"].value_counts().to_dict() if len(df) else {},
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate DB-TRACE synthetic dataset")
    parser.add_argument("--n", type=int, default=100, help="Number of environments")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--out", type=Path, default=Path("data"), help="Output directory")
    args = parser.parse_args()
    manifest = generate_dataset(n_envs=args.n, seed=args.seed, out_dir=args.out)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
