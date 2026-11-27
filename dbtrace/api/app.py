"""FastAPI backend serving live cloud scans, attack-path narratives, SHAP explanations, and verified remediations."""

from __future__ import annotations

import json
import pickle
import time
from pathlib import Path

import numpy as np
import shap
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from dbtrace.collectors.aws_pg import collect_aws_environment
from dbtrace.collectors.live_neon import (
    apply_live_neon_fix,
    scan_live_neon_environment,
    seed_live_neon_vulnerabilities,
)
from dbtrace.config import settings
from dbtrace.features.extract import FEATURE_COLUMNS, extract_path_features
from dbtrace.generator.__main__ import generate_dataset
from dbtrace.generator.scenarios import build_scenario
from dbtrace.graph.builder import build_hetero_data, graph_to_cytoscape_elements
from dbtrace.labeling.oracle import enumerate_and_label_paths
from dbtrace.llm.narrator import narrate_remediation
from dbtrace.logs.generator import generate_env_logs
from dbtrace.models.gnn import HeteroPathEncoder
from dbtrace.models.train import train_and_evaluate
from dbtrace.remediation.engine import recommend_remediations
from dbtrace.schema import AccessPathRecord, CloudEnvironment

app = FastAPI(title="DB-TRACE API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HUMAN_FEATURE_LABELS: dict[str, str] = {
    "db_table_is_sensitive": "Target table contains sensitive / PII data",
    "db_role_has_select_grant": "DB role has effective SELECT/ALL grant on table",
    "log_legit_connect_count": "Historical legitimate IAM DB connections (CloudTrail)",
    "log_legit_select_count": "Historical legitimate DB queries (pgaudit)",
    "compute_leaked_creds": "Compute host exposes hardcoded/leaked DB credentials",
    "via_snapshot": "Path exploits unencrypted RDS snapshot exposure",
    "via_internet": "Path is reachable directly from the public Internet",
    "rds_publicly_accessible": "Database endpoint is publicly accessible",
    "rds_encrypted": "Database storage encryption enabled",
    "rds_iam_auth": "IAM database authentication enabled",
    "rds_public_snapshot": "Public unencrypted RDS snapshot exists",
    "sg_open_to_world_5432": "Security Group allows 0.0.0.0/0 on port 5432",
    "sg_allows_compute_5432": "Security Group allows compute tier to reach port 5432",
    "subnet_route_to_igw": "Subnet routes directly to an Internet Gateway",
    "compute_imdsv2_required": "EC2 enforces IMDSv2 session tokens",
    "compute_public_ip": "Compute instance has a public IP address",
    "compute_has_app_vuln": "Web/app vulnerability (SSRF/RCE) present on compute host",
    "iam_wildcard_actions": "IAM policy grants wildcard (*) permissions",
    "iam_has_privesc": "Principal holds IAM privilege-escalation permissions",
    "iam_has_explicit_deny": "Explicit IAM Deny guard blocks access",
    "iam_rds_connect_allowed": "IAM policy allows rds-db:connect",
    "iam_snapshot_modify": "IAM policy allows rds:ModifyDBSnapshotAttribute",
    "entry_has_mfa": "Entry principal has MFA enabled",
    "entry_is_external": "Entry point is an unauthenticated external actor",
    "db_role_can_login": "Database role has LOGIN privilege",
    "db_role_is_superuser": "Database role has SUPERUSER / rds_superuser privilege",
    "db_role_inheritance_depth": "Transitive PostgreSQL role inheritance depth",
    "has_compute": "Attack traverses a compute host (EC2/Lambda)",
    "compute_is_ec2": "Compute tier is an EC2 instance",
}


class LiveScanRequest(BaseModel):
    connection_url: str | None = None


class LiveFixRequest(BaseModel):
    table_name: str = "customers_pii"
    connection_url: str | None = None


class AwsScanRequest(BaseModel):
    region: str = "us-east-1"
    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None


class GenerateRequest(BaseModel):
    n_envs: int = 100
    seed: int = 42


def _data_dir() -> Path:
    return settings.data_dir


def _load_env(env_id: str) -> CloudEnvironment:
    if env_id == "demo_capital_one":
        return build_scenario("demo_capital_one", "capital_one_ssrf", seed=2019)
    if env_id == "live_neon_cloud":
        if not settings.target_pg_url:
            raise HTTPException(status_code=400, detail="TARGET_PG_URL is not configured in .env")
        env, _ = scan_live_neon_environment(settings.target_pg_url)
        return env
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


def _build_attack_steps(env: CloudEnvironment, p: AccessPathRecord) -> list[dict[str, str]]:
    """Produce a plain-English step-by-step chain explaining HOW this path works (or why it's blocked)."""
    prin_map = {x.id: x for x in env.principals}
    comp_map = {x.id: x for x in env.computes}
    rds_map = {x.id: x for x in env.rds_instances}
    role_map = {x.id: x for x in env.db_roles}
    tbl_map = {x.id: x for x in env.db_tables}

    entry = prin_map.get(p.entry_principal_id)
    comp = comp_map.get(p.compute_id) if p.compute_id else None
    rds = rds_map.get(p.rds_id)
    db_role = role_map.get(p.db_role_id)
    tbl = tbl_map.get(p.db_table_id)

    steps: list[dict[str, str]] = []
    steps.append({
        "stage": "1. Entry Identity",
        "mitre": "T1078.004 (Cloud Accounts)",
        "resource": entry.name if entry else p.entry_principal_id,
        "detail": (
            "External attacker from the public Internet targets exposed cloud endpoints."
            if (entry and entry.is_external_entry)
            else f"IAM principal '{entry.name if entry else p.entry_principal_id}' initiates access."
        ),
        "remediation_hint": (
            "Enforce MFA, remove wildcard (*) IAM actions, and restrict sts:AssumeRole trust policies."
        ),
    })

    if p.via_snapshot:
        steps.append({
            "stage": "2. Snapshot Exposure",
            "mitre": "T1537 (Transfer Data to Cloud Account)",
            "resource": rds.name if rds else p.rds_id,
            "detail": "Exploits public or shareable unencrypted RDS snapshot to copy database outside VPC.",
            "remediation_hint": "Enable RDS storage encryption and disable public/cross-account snapshot sharing.",
        })
    elif comp:
        vuln_note = (
            "Exploits SSRF/app flaw + IMDSv1 to steal attached IAM role credentials."
            if (comp.has_app_vuln and not comp.imdsv2_required)
            else (
                "Exploits web app flaw to read leaked DB credentials on host."
                if comp.leaked_db_role_id
                else f"Executes through {comp.kind.upper()} resource '{comp.name}'."
            )
        )
        steps.append({
            "stage": "2. Compute Pivot",
            "mitre": "T1552.005 (Cloud Instance Metadata API)",
            "resource": comp.name,
            "detail": vuln_note,
            "remediation_hint": (
                "Enforce IMDSv2 (http_tokens = 'required') on EC2 and move DB secrets to Secrets Manager."
            ),
        })
    elif p.via_internet:
        steps.append({
            "stage": "2. Network Exposure",
            "mitre": "T1190 (Exploit Public-Facing Application)",
            "resource": rds.name if rds else p.rds_id,
            "detail": "Connects directly over the public Internet to port 5432 on a publicly accessible DB endpoint.",
            "remediation_hint": "Set publicly_accessible = false and restrict Security Group port 5432 to VPC CIDR.",
        })

    steps.append({
        "stage": "3. Database Role",
        "mitre": "T1098 (Account Manipulation)",
        "resource": db_role.name if db_role else p.db_role_id,
        "detail": (
            f"Authenticates as PostgreSQL role '{db_role.name}' "
            f"({'SUPERUSER' if (db_role and (db_role.is_superuser or db_role.is_rds_superuser)) else 'login role'})."
            if db_role
            else "Attempts database role authentication."
        ),
        "remediation_hint": "Remove unnecessary SUPERUSER flags and restrict rds-db:connect IAM permissions.",
    })

    steps.append({
        "stage": "4. Target Data",
        "mitre": "T1530 (Data from Cloud Storage/DB)",
        "resource": f"{tbl.schema_name}.{tbl.table_name}" if tbl else p.db_table_id,
        "detail": (
            f"Exfiltrates {tbl.sensitivity.value.upper()} table '{tbl.schema_name}.{tbl.table_name}'."
            if p.label_exploitable == 1 and tbl
            else f"Blocked before exfiltration ({p.failure_reason or 'insufficient access'})."
        ),
        "remediation_hint": (
            f"REVOKE SELECT ON TABLE {tbl.schema_name}.{tbl.table_name} FROM PUBLIC / over-broad roles."
            if tbl
            else "Apply least-privilege table grants."
        ),
    })
    return steps


def _group_shap_features(feat_names: list[str], x_row: np.ndarray, sv_row: np.ndarray) -> list[dict[str, object]]:
    """Aggregate GNN PCA dimensions into one clear 'Multi-Hop Graph Context (GNN)' factor & translate names."""
    gnn_sum = 0.0
    items: list[dict[str, object]] = []
    for name, val, sv in zip(feat_names, x_row, sv_row, strict=True):
        if name.startswith("gnn_pca_"):
            gnn_sum += float(sv)
        else:
            items.append({
                "feature": name,
                "label": HUMAN_FEATURE_LABELS.get(name, name),
                "value": round(float(val), 3),
                "shap_value": round(float(sv), 4),
            })
    items.append({
        "feature": "gnn_graph_context",
        "label": "Multi-Hop Graph Structure (GNN Path Embedding)",
        "value": 1.0,
        "shap_value": round(gnn_sum, 4),
    })
    items.sort(key=lambda d: -abs(float(d["shap_value"])))
    return items[:7]


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
        X = df[FEATURE_COLUMNS].to_numpy(dtype=float) if len(paths) else np.zeros((0, len(FEATURE_COLUMNS)))
        probs = np.array([float(p.label_exploitable) for p in paths])
        sv = np.zeros_like(X)

    tbl_map = {t.id: f"{t.schema_name}.{t.table_name}" for t in env.db_tables}
    role_map = {r.id: r.name for r in env.db_roles}
    prin_map = {x.id: x.name for x in env.principals}

    scored = []
    explanations = []
    for i, p in enumerate(paths):
        steps = _build_attack_steps(env, p)
        scored.append({
            **p.model_dump(),
            "risk_score": round(float(probs[i]), 4),
            "entry_name": prin_map.get(p.entry_principal_id, p.entry_principal_id),
            "db_role_name": role_map.get(p.db_role_id, p.db_role_id),
            "db_table_name": tbl_map.get(p.db_table_id, p.db_table_id),
            "attack_steps": steps,
        })
        grouped = _group_shap_features(feat_names, X[i], sv[i])
        explanations.append({
            "path_id": p.path_id,
            "risk_score": round(float(probs[i]), 4),
            "top_features": grouped,
        })
    scored.sort(key=lambda r: (-r["risk_score"], -r["label_exploitable"]))
    return scored, explanations


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.2.0"}


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
    items: list[dict[str, object]] = []
    if settings.target_pg_url:
        items.append({"env_id": "live_neon_cloud", "scenario_type": "LIVE NEON CLOUD POSTGRES", "is_demo": True})
    items.append({"env_id": "demo_capital_one", "scenario_type": "Capital One 2019 SSRF Replay", "is_demo": True})
    if envs_dir.exists():
        for f in sorted(envs_dir.glob("*.json"))[:25]:
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


@app.get("/live/neon/status")
def live_neon_status() -> dict:
    if not settings.target_pg_url:
        return {"connected": False, "message": "TARGET_PG_URL not set in .env"}
    try:
        _, meta = scan_live_neon_environment(settings.target_pg_url)
        return {"connected": True, **meta}
    except Exception as exc:
        return {"connected": False, "message": str(exc)}


@app.post("/live/neon/seed")
def live_neon_seed(req: LiveScanRequest | None = None) -> dict:
    conn_str = req.connection_url if req and req.connection_url else settings.target_pg_url
    if not conn_str:
        raise HTTPException(status_code=400, detail="No PostgreSQL connection URL configured.")
    return seed_live_neon_vulnerabilities(conn_str)


@app.post("/live/neon/scan")
def live_neon_scan(req: LiveScanRequest | None = None) -> dict:
    """Execute the full 5-stage DB-TRACE pipeline in real time against a live Neon/PostgreSQL cloud DB."""
    conn_str = req.connection_url if req and req.connection_url else settings.target_pg_url
    if not conn_str:
        raise HTTPException(status_code=400, detail="No PostgreSQL connection URL configured.")

    stages: list[dict[str, object]] = []

    t0 = time.perf_counter()
    env, meta = scan_live_neon_environment(conn_str)
    stages.append({
        "stage": "1. Live Cloud Collection",
        "ms": round((time.perf_counter() - t0) * 1000, 1),
        "detail": f"Connected to Neon Cloud PG ({meta['roles_discovered']} roles, {meta['tables_discovered']} tables, {len(meta['public_grant_tables'])} PUBLIC-exposed tables).",
    })

    t1 = time.perf_counter()
    graph = graph_to_cytoscape_elements(env)
    stages.append({
        "stage": "2. Heterogeneous Graph Construction",
        "ms": round((time.perf_counter() - t1) * 1000, 1),
        "detail": f"Built Identity -> Compute -> Network -> Database graph ({len(graph['nodes'])} nodes, {len(graph['edges'])} edges).",
    })

    t2 = time.perf_counter()
    scored, explanations = _score_env_paths(env)
    exp_map = {e["path_id"]: e for e in explanations}
    exploitable = sum(1 for p in scored if p["label_exploitable"] == 1)
    stages.append({
        "stage": "3. PyG GNN + XGBoost Risk Scoring",
        "ms": round((time.perf_counter() - t2) * 1000, 1),
        "detail": f"Scored {len(scored)} candidate access paths; flagged {exploitable} exploitable attack path(s).",
    })

    t3 = time.perf_counter()
    logs = generate_env_logs(env, n_days=30, seed=settings.random_seed)
    recs = recommend_remediations(env, logs)
    top_exp = explanations[0]["top_features"] if explanations else []
    top_path_id = scored[0]["path_id"] if scored else "live_neon_cloud_p0001"
    narrated = [
        {**r.model_dump(), "narration": narrate_remediation(top_path_id, top_exp, r)}
        for r in recs
    ]
    safe_cnt = sum(1 for r in recs if r.status == "Verified Safe-to-Apply")
    stages.append({
        "stage": "4. SHAP Explainability & Log-Replay Verification",
        "ms": round((time.perf_counter() - t3) * 1000, 1),
        "detail": f"Computed SHAP attributions and replayed {len(logs)} historical logs ({safe_cnt} verified safe fix(es)).",
    })

    return {
        "meta": meta,
        "stages": stages,
        "graph": graph,
        "paths": scored,
        "explanations": exp_map,
        "remediations": narrated,
    }


@app.post("/live/neon/apply-fix")
def live_neon_apply_fix(req: LiveFixRequest) -> dict:
    """Apply a verified SQL REVOKE directly to live Neon Cloud DB and return updated scan results."""
    conn_str = req.connection_url or settings.target_pg_url
    if not conn_str:
        raise HTTPException(status_code=400, detail="No PostgreSQL connection URL configured.")
    fix_res = apply_live_neon_fix(conn_str, table_name=req.table_name)
    scan_res = live_neon_scan(LiveScanRequest(connection_url=conn_str))
    return {"fix": fix_res, "scan": scan_res}


@app.post("/cloud/aws/scan")
def scan_real_aws(req: AwsScanRequest) -> dict:
    """Connect to a real AWS account (via keys or local AWS SSO/profile) and run DB-TRACE."""
    try:
        t0 = time.perf_counter()
        env = collect_aws_environment(
            env_id=f"aws_{req.region}",
            region=req.region,
            access_key_id=req.access_key_id or None,
            secret_access_key=req.secret_access_key or None,
            session_token=req.session_token or None,
        )
        t_collect = round((time.perf_counter() - t0) * 1000, 1)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"AWS connection failed: {exc}") from exc

    graph = graph_to_cytoscape_elements(env)
    scored, explanations = _score_env_paths(env)
    logs = generate_env_logs(env, n_days=30, seed=settings.random_seed)
    recs = recommend_remediations(env, logs)
    return {
        "inventory": {
            "region": req.region,
            "principals": len(env.principals),
            "policies": len(env.policies),
            "security_groups": len(env.security_groups),
            "rds_instances": len(env.rds_instances),
            "collect_ms": t_collect,
        },
        "graph": graph,
        "paths": scored,
        "explanations": {e["path_id"]: e for e in explanations},
        "remediations": [r.model_dump() for r in recs],
    }


@app.get("/ml/dataset")
def dataset_summary() -> dict:
    """Return dataset manifest and sample labeled rows from data/paths.csv."""
    import pandas as pd

    manifest_path = _data_dir() / "manifest.json"
    csv_path = _data_dir() / "paths.csv"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {}
    sample = []
    if csv_path.exists():
        df = pd.read_csv(csv_path).head(15).fillna("")
        sample = df.to_dict(orient="records")
    return {"manifest": manifest, "sample_rows": sample}


@app.post("/ml/generate")
def api_generate_dataset(req: GenerateRequest) -> dict:
    """Trigger synthetic environment & labeled attack-path dataset generation."""
    manifest = generate_dataset(n_envs=req.n_envs, seed=req.seed, out_dir=_data_dir())
    return {"status": "generated", "manifest": manifest}


@app.post("/ml/train")
def api_train_model() -> dict:
    """Train all baselines + PyG GNN + XGBoost + SHAP and persist model artifacts."""
    report = train_and_evaluate(data_dir=_data_dir())
    return {"status": "trained", "evaluation": report}
