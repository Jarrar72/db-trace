"""Tests for remediation verification simulator and FastAPI endpoints."""

from fastapi.testclient import TestClient

from dbtrace.api.app import app
from dbtrace.generator.scenarios import build_scenario
from dbtrace.logs.generator import generate_env_logs
from dbtrace.remediation.engine import recommend_remediations, verify_remediation


def test_remediation_safe_vs_unsafe_verification() -> None:
    env = build_scenario("env_rem", "capital_one_ssrf", seed=2019)
    logs = generate_env_logs(env, n_days=10, seed=2019)

    safe = verify_remediation(env, logs, "enable_imdsv2")
    assert safe.paths_eliminated > 0
    assert safe.legit_broken == 0
    assert safe.status == "Verified Safe-to-Apply"

    unsafe = verify_remediation(env, logs, "revoke_all_db_unsafe")
    assert unsafe.legit_broken > 0
    assert unsafe.status == "Unsafe (Breaks Legitimate Traffic)"

    ranked = recommend_remediations(env, logs)
    assert ranked[0].legit_broken == 0

    # Different scenario (lambda_privesc) must surface scope_iam_privesc, not enable_imdsv2
    lam_env = build_scenario("env_lam", "lambda_privesc", seed=5)
    lam_logs = generate_env_logs(lam_env, n_days=10, seed=5)
    lam_recs = recommend_remediations(lam_env, lam_logs)
    lam_ids = {r.fix_id for r in lam_recs}
    assert "scope_iam_privesc" in lam_ids
    assert "enable_imdsv2" not in lam_ids


def test_api_demo_endpoints() -> None:
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    g_resp = client.get("/environments/demo_capital_one/graph")
    assert g_resp.status_code == 200
    assert len(g_resp.json()["nodes"]) > 0

    p_resp = client.get("/environments/demo_capital_one/paths")
    assert p_resp.status_code == 200
    assert len(p_resp.json()["paths"]) > 0

    r_resp = client.get("/environments/demo_capital_one/remediate")
    assert r_resp.status_code == 200
    assert len(r_resp.json()["remediations"]) > 0
