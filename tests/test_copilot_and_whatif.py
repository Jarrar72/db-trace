"""Tests for AI Security Copilot, What-If Simulator, and Executive Report Generator."""

from fastapi.testclient import TestClient

from dbtrace.api.app import app
from dbtrace.generator.scenarios import build_scenario
from dbtrace.labeling.oracle import enumerate_and_label_paths
from dbtrace.llm.copilot import answer_copilot_query
from dbtrace.remediation.whatif import WhatIfToggles, simulate_what_if
from dbtrace.reports.generator import generate_executive_report

client = TestClient(app)


def test_copilot_grounded_response():
    env = build_scenario("demo_test_copilot", "capital_one_ssrf", seed=101)
    paths = [p.model_dump() for p in enumerate_and_label_paths(env)]
    explanations = {
        paths[0]["path_id"]: {
            "top_features": [
                {"feature": "sg_open_to_world_5432", "label": "Security Group allows 0.0.0.0/0 on port 5432", "shap_value": 0.42},
                {"feature": "compute_imdsv2_required", "label": "EC2 enforces IMDSv2 session tokens", "shap_value": -0.15},
            ]
        }
    }
    remediations = [
        {
            "fix_id": "fix_sg_01",
            "title": "Restrict Public RDS Security Group",
            "description": "Revoke 0.0.0.0/0 ingress",
            "patch_snippet": "resource \"aws_security_group\" ...",
            "paths_eliminated": 1,
            "legit_broken": 0,
            "legit_total": 50,
            "status": "Verified Safe-to-Apply",
        }
    ]

    res = answer_copilot_query("Why is my database at critical risk?", env, paths, explanations, remediations)
    assert "CRITICAL RISK" in res.answer or "Critical Risk" in res.answer
    assert len(res.evidence) > 0
    assert len(res.suggested_followups) > 0
    assert res.confidence_label != ""


def test_what_if_simulation_engine():
    env = build_scenario("demo_test_whatif", "capital_one_ssrf", seed=102)
    toggles = WhatIfToggles(
        port_5432_open=False,  # Close port 5432
        iam_admin_access=True,
        db_role_inheritance=True,
        rds_public=True,
        imdsv2_required=False,
    )
    result = simulate_what_if(env, toggles)
    assert result.paths_eliminated >= 1
    assert result.simulated_risk_score < result.baseline_risk_score
    assert result.risk_delta < 0
    assert "eliminated" in result.impact_narrative.lower()


def test_executive_report_generator():
    env = build_scenario("demo_test_report", "capital_one_ssrf", seed=103)
    paths = [p.model_dump() for p in enumerate_and_label_paths(env)]
    rep = generate_executive_report(env, paths, {}, [])
    assert rep.environment_id == "demo_test_report"
    assert rep.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    assert len(rep.compliance_findings) > 0
    assert "CIS AWS Benchmark" in rep.compliance_findings[0].framework or "NIST" in rep.compliance_findings[0].framework


def test_api_copilot_and_whatif_endpoints():
    r_chat = client.post("/api/copilot/chat", json={"env_id": "demo_capital_one", "message": "Why is my database at risk?"})
    assert r_chat.status_code == 200
    d_chat = r_chat.json()
    assert "answer" in d_chat
    assert len(d_chat["evidence"]) > 0

    r_whatif = client.post("/api/what-if/simulate", json={
        "env_id": "demo_capital_one",
        "toggles": {
            "port_5432_open": False,
            "iam_admin_access": True,
            "db_role_inheritance": True,
            "rds_public": False,
            "imdsv2_required": True,
        }
    })
    assert r_whatif.status_code == 200
    d_whatif = r_whatif.json()
    assert d_whatif["paths_eliminated"] >= 1
    assert d_whatif["status"] == "Verified Safe-to-Apply"

    r_rep = client.get("/api/reports/assessment/demo_capital_one")
    assert r_rep.status_code == 200
    d_rep = r_rep.json()
    assert d_rep["risk_level"] == "CRITICAL"
    assert len(d_rep["compliance_findings"]) > 0
