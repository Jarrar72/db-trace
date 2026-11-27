"""Unit tests for the synthetic generator, IAM evaluator, oracle, and log generator."""

from pathlib import Path

from dbtrace.generator.__main__ import generate_dataset
from dbtrace.generator.scenarios import build_scenario
from dbtrace.labeling.iam_eval import evaluate_iam_action
from dbtrace.labeling.oracle import enumerate_and_label_paths
from dbtrace.logs.generator import generate_env_logs
from dbtrace.schema import IAMPolicy, IAMPrincipal, PolicyStatement


def test_iam_explicit_deny_overrides_allow() -> None:
    pol = IAMPolicy(
        id="p1",
        name="AllowAndDeny",
        statements=[
            PolicyStatement(effect="Allow", actions=["rds-db:*"], resources=["*"]),
            PolicyStatement(effect="Deny", actions=["rds-db:connect"], resources=["*"]),
        ],
    )
    prin = IAMPrincipal(
        id="u1",
        arn="arn:aws:iam::123:user/u1",
        name="u1",
        kind="user",
        attached_policy_ids=["p1"],
    )
    assert evaluate_iam_action(prin, "rds-db:connect", "*", {"p1": pol}) is False
    assert evaluate_iam_action(prin, "rds-db:other", "*", {"p1": pol}) is True


def test_capital_one_and_near_miss_labels() -> None:
    cap_one = build_scenario("env_cap1", "capital_one_ssrf", seed=1)
    cap_paths = enumerate_and_label_paths(cap_one)
    assert any(p.label_exploitable == 1 for p in cap_paths)

    for nm in ("near_miss_explicit_deny", "near_miss_sg_blocked", "near_miss_wrong_grant", "benign_least_privilege"):
        env = build_scenario(f"env_{nm}", nm, seed=2)
        paths = enumerate_and_label_paths(env)
        assert all(p.label_exploitable == 0 for p in paths), f"{nm} should have 0 exploitable paths"


def test_generate_dataset_and_logs(tmp_path: Path) -> None:
    manifest = generate_dataset(n_envs=10, seed=42, out_dir=tmp_path)
    assert manifest["n_environments"] == 10
    assert manifest["n_paths"] > 50
    assert (tmp_path / "paths.csv").exists()

    env = build_scenario("env_logs", "capital_one_ssrf", seed=7)
    logs = generate_env_logs(env, n_days=5, seed=7)
    assert len(logs) > 0
    assert all(ev.is_legitimate for ev in logs)
