"""FastAPI backend serving attack-path risk scores, SHAP explanations, and verified remediations."""

from __future__ import annotations

import json
import pickle
from pathlib import Path

import numpy as np
import shap
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from dbtrace.config import settings
from dbtrace.features.extract import FEATURE_COLUMNS, extract_path_features
from dbtrace.generator.scenarios import build_scenario
from dbtrace.graph.builder import build_hetero_data, graph_to_cytoscape_elements
from dbtrace.labeling.oracle import enumerate_and_label_paths
from dbtrace.llm.narrator import narrate_remediation
from dbtrace.logs.generator import generate_env_logs
from dbtrace.models.gnn import HeteroPathEncoder
from dbtrace.remediation.engine import recommend_remediations
from dbtrace.schema import CloudEnvironment

app = FastAPI(title="DB-TRACE API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _data_dir() -> Path:
    return settings.data_dir


def _load_env(env_id: str) -> CloudEnvironment:
    if env_id == "demo_capital_one":
        return build_scenario("demo_capital_one", "capital_one_ssrf", seed=2019)
    path = _data_dir() / "envs" / f"{env_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Environment {env_id} not found")
    return CloudEnvironment.model_validate_json(path.read_text(encoding="utf-8"))


def _load_bundle(sample_env: CloudEnvironment) -> dict | None:
    bundle_path = _data_dir() / "artifacts" / "model_bundle.pkl"
    gnn_path = _data_dir() / "artifacts" / "gnn_weights.pt"
    if not bundle_path.exists() or not gnn_path.exists():
        return None
    with open(bundle_path, "rb") as f:
        bundle = pickle.load(f)
    sample_data, _ = build_hetero_data(sample_env)
    bundle["gnn"] = HeteroPathEncoder.load_weights(str(gnn_path), sample_data)
    return bundle


def _score_env_paths(env: CloudEnvironment) -> tuple[list[dict], list[dict]]:
    paths = enumerate_and_label_paths(env)
    logs = generate_env_logs(env, n_days=30, seed=settings.random_seed)
    df = extract_path_features(env, paths, logs)
    bundle = _load_bundle(env)

    if bundle is not None and len(paths) > 0:
        gnn = bundle["gnn"]
        xgb_hyb = bundle["xgb_hyb"]
        feat_names = bundle["feature_names"]
        emb = gnn.transform({env.env_id: env}, {env.env_id: paths}, [env.env_id])
        X = np.hstack([df[FEATURE_COLUMNS].to_numpy(dtype=float), emb])
        probs = xgb_hyb.predict_proba(X)[:, 1]
        try:
            explainer = shap.TreeExplainer(xgb_hyb)
            sv = explainer.shap_values(X)
            if isinstance(sv, list):
                sv = sv[-1]
        except Exception:
            sv = np.zeros_like(X)
    else:
        feat_names = FEATURE_COLUMNS
        X = df[FEATURE_COLUMNS].to_numpy(dtype=float)
        probs = np.array([float(p.label_exploitable) for p in paths])
        sv = np.zeros_like(X)

    scored = []
    explanations = []
    for i, p in enumerate(paths):
        scored.append({
            **p.model_dump(),
            "risk_score": round(float(probs[i]), 4),
        })
        top_idx = np.argsort(-np.abs(sv[i]))[:8]
        explanations.append({
            "path_id": p.path_id,
            "risk_score": round(float(probs[i]), 4),
            "top_features": [
                {
                    "feature": feat_names[j],
                    "value": round(float(X[i, j]), 4),
                    "shap_value": round(float(sv[i, j]), 4),
                }
                for j in top_idx
            ],
        })
    scored.sort(key=lambda r: -r["risk_score"])
    return scored, explanations


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


@app.get("/metrics")
def metrics() -> dict:
    report_path = _data_dir() / "artifacts" / "eval_report.json"
    manifest_path = _data_dir() / "manifest.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Evaluation report not found. Run training first.")
    return {
        "manifest": json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {},
        "evaluation": json.loads(report_path.read_text(encoding="utf-8")),
    }


@app.get("/environments")
def list_environments() -> list[dict[str, object]]:
    envs_dir = _data_dir() / "envs"
    items = [{"env_id": "demo_capital_one", "scenario_type": "capital_one_ssrf", "is_demo": True}]
    if envs_dir.exists():
        for f in sorted(envs_dir.glob("*.json"))[:30]:
            env = CloudEnvironment.model_validate_json(f.read_text(encoding="utf-8"))
            items.append({"env_id": env.env_id, "scenario_type": env.scenario_type, "is_demo": False})
    return items


@app.get("/environments/{env_id}/graph")
def get_environment_graph(env_id: str) -> dict:
    env = _load_env(env_id)
    return {"env_id": env.env_id, "scenario_type": env.scenario_type, **graph_to_cytoscape_elements(env)}


@app.get("/environments/{env_id}/paths")
def get_environment_paths(env_id: str) -> dict:
    env = _load_env(env_id)
    scored, explanations = _score_env_paths(env)
    exp_map = {e["path_id"]: e for e in explanations}
    return {"env_id": env.env_id, "paths": scored, "explanations": exp_map}


@app.get("/environments/{env_id}/remediate")
def remediate_environment(env_id: str) -> dict:
    env = _load_env(env_id)
    logs = generate_env_logs(env, n_days=30, seed=settings.random_seed)
    recs = recommend_remediations(env, logs)
    scored, explanations = _score_env_paths(env)
    top_exp = explanations[0]["top_features"] if explanations else []
    top_path_id = scored[0]["path_id"] if scored else f"{env_id}_p0001"
    narrated = [
        {**r.model_dump(), "narration": narrate_remediation(top_path_id, top_exp, r)}
        for r in recs
    ]
    return {"env_id": env.env_id, "remediations": narrated}
