"""End-to-end training, baseline comparison, calibration, SHAP, and evaluation."""

from __future__ import annotations

import json
import pickle
from collections import defaultdict
from pathlib import Path

import mlflow
import numpy as np
import pandas as pd
import shap
import xgboost as xgb
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler

from dbtrace.config import settings
from dbtrace.features.extract import FEATURE_COLUMNS, extract_path_features
from dbtrace.labeling.oracle import enumerate_and_label_paths
from dbtrace.logs.generator import generate_env_logs
from dbtrace.models.gnn import HeteroPathEncoder
from dbtrace.schema import AccessPathRecord, CloudEnvironment


def _compute_metrics(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> dict[str, object]:
    y_pred = (y_prob >= threshold).astype(int)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist()
    return {
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "pr_auc": round(float(average_precision_score(y_true, y_prob)), 4),
        "mcc": round(float(matthews_corrcoef(y_true, y_pred)), 4),
        "brier": round(float(brier_score_loss(y_true, y_prob)), 4),
        "confusion_matrix": cm,
        "threshold": round(float(threshold), 3),
    }


def _tune_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> float:
    """Pick threshold maximizing F1 while prioritizing Recall >= 0.85 and Precision >= 0.80."""
    best_t, best_f1 = 0.5, -1.0
    for t in np.linspace(0.15, 0.85, 71):
        pred = (y_prob >= t).astype(int)
        rec = recall_score(y_true, pred, zero_division=0)
        prec = precision_score(y_true, pred, zero_division=0)
        f1 = f1_score(y_true, pred, zero_division=0)
        if rec >= 0.85 and prec >= 0.80 and f1 > best_f1:
            best_f1, best_t = f1, float(t)
    if best_f1 < 0:
        for t in np.linspace(0.15, 0.85, 71):
            f1 = f1_score(y_true, (y_prob >= t).astype(int), zero_division=0)
            if f1 > best_f1:
                best_f1, best_t = f1, float(t)
    return best_t


def _mcnemar_stat(y_true: np.ndarray, pred_a: np.ndarray, pred_b: np.ndarray) -> dict[str, float]:
    a_ok = pred_a == y_true
    b_ok = pred_b == y_true
    b_only = int(np.sum((~a_ok) & b_ok))
    a_only = int(np.sum(a_ok & (~b_ok)))
    denom = a_only + b_only
    chi2 = ((abs(a_only - b_only) - 1) ** 2 / denom) if denom > 0 else 0.0
    return {"a_only_correct": a_only, "b_only_correct": b_only, "chi2_continuity": round(float(chi2), 4)}


def load_dataset_frames(data_dir: Path = Path("data")) -> tuple[dict[str, CloudEnvironment], dict[str, list[AccessPathRecord]], pd.DataFrame]:
    envs: dict[str, CloudEnvironment] = {}
    paths_by_env: dict[str, list[AccessPathRecord]] = defaultdict(list)
    frames = []

    for env_file in sorted((data_dir / "envs").glob("*.json")):
        env = CloudEnvironment.model_validate_json(env_file.read_text(encoding="utf-8"))
        envs[env.env_id] = env
        epaths = enumerate_and_label_paths(env)
        paths_by_env[env.env_id] = epaths
        logs = generate_env_logs(env, n_days=30, seed=settings.random_seed)
        frames.append(extract_path_features(env, epaths, logs))

    df = pd.concat(frames, ignore_index=True)
    return envs, paths_by_env, df


def train_and_evaluate(data_dir: Path = Path("data")) -> dict[str, object]:
    envs, paths_by_env, df = load_dataset_frames(data_dir)
    artifacts_dir = data_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Leakage-safe 80/20 split grouped by env_id
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=settings.random_seed)
    splits = list(sgkf.split(df, df["label_exploitable"], groups=df["env_id"]))
    train_idx, test_idx = splits[0]
    train_df = df.iloc[train_idx].reset_index(drop=True)
    test_df = df.iloc[test_idx].reset_index(drop=True)

    train_env_ids = sorted(train_df["env_id"].unique().tolist())
    test_env_ids = sorted(test_df["env_id"].unique().tolist())

    X_train_tab = train_df[FEATURE_COLUMNS].to_numpy(dtype=float)
    y_train = train_df["label_exploitable"].to_numpy(dtype=int)
    X_test_tab = test_df[FEATURE_COLUMNS].to_numpy(dtype=float)
    y_test = test_df["label_exploitable"].to_numpy(dtype=int)

    # B0: Rule-based CIS-style heuristic (public RDS OR open 5432 OR wildcard IAM)
    b0_prob = (
        (test_df["rds_publicly_accessible"] == 1)
        | (test_df["sg_open_to_world_5432"] == 1)
        | (test_df["iam_wildcard_actions"] == 1)
    ).astype(float).to_numpy()

    # B1: Graph reachability baseline (compute/internet reachable + network + db grant, ignoring IAM deny/sensitivity)
    b1_prob = (
        ((test_df["sg_allows_compute_5432"] == 1) | (test_df["sg_open_to_world_5432"] == 1))
        & (test_df["db_role_has_select_grant"] == 1)
    ).astype(float).to_numpy()

    # B2: Logistic Regression (tabular)
    scaler = StandardScaler()
    lr = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=settings.random_seed)
    lr.fit(scaler.fit_transform(X_train_tab), y_train)
    b2_prob = lr.predict_proba(scaler.transform(X_test_tab))[:, 1]

    # B3: XGBoost (tabular only)
    pos = max(int(y_train.sum()), 1)
    neg = max(int((1 - y_train).sum()), 1)
    xgb_tab = xgb.XGBClassifier(
        n_estimators=180,
        max_depth=5,
        learning_rate=0.06,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=neg / pos,
        eval_metric="logloss",
        random_state=settings.random_seed,
    )
    xgb_tab.fit(X_train_tab, y_train)
    b3_prob = xgb_tab.predict_proba(X_test_tab)[:, 1]
    b3_thresh = _tune_threshold(y_train, xgb_tab.predict_proba(X_train_tab)[:, 1])

    # B4: GNN only (PyG HeteroGraphSAGE trained ONLY on train_env_ids)
    gnn = HeteroPathEncoder(hidden_channels=32, pca_dim=16, seed=settings.random_seed)
    gnn.fit(envs, paths_by_env, train_env_ids, epochs=25)

    # Order rows by env_id order to align GNN embeddings cleanly
    def _ordered_gnn_features(sub_df: pd.DataFrame, env_ids: list[str]) -> tuple[np.ndarray, np.ndarray, pd.DataFrame]:
        ordered = pd.concat([sub_df[sub_df["env_id"] == eid] for eid in env_ids], ignore_index=True)
        emb = gnn.transform(envs, paths_by_env, env_ids)
        probs = gnn.predict_gnn_proba(envs, paths_by_env, env_ids)
        return emb, probs, ordered

    emb_train, _, tr_ord = _ordered_gnn_features(train_df, train_env_ids)
    emb_test, b4_prob, te_ord = _ordered_gnn_features(test_df, test_env_ids)

    emb_cols = [f"gnn_pca_{i}" for i in range(emb_train.shape[1])]
    X_train_hyb = np.hstack([tr_ord[FEATURE_COLUMNS].to_numpy(dtype=float), emb_train])
    y_train_ord = tr_ord["label_exploitable"].to_numpy(dtype=int)
    X_test_hyb = np.hstack([te_ord[FEATURE_COLUMNS].to_numpy(dtype=float), emb_test])
    y_test_ord = te_ord["label_exploitable"].to_numpy(dtype=int)

    # B5: Proposed Hybrid (GNN Embeddings + Tabular -> XGBoost + Isotonic Calibration)
    xgb_hyb = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.06,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=neg / pos,
        eval_metric="logloss",
        random_state=settings.random_seed,
    )
    xgb_hyb.fit(X_train_hyb, y_train_ord)

    cal_model = CalibratedClassifierCV(xgb_hyb, method="isotonic", cv=3)
    cal_model.fit(X_train_hyb, y_train_ord)
    b5_prob_raw = xgb_hyb.predict_proba(X_test_hyb)[:, 1]
    b5_prob_cal = cal_model.predict_proba(X_test_hyb)[:, 1]
    b5_thresh = _tune_threshold(y_train_ord, xgb_hyb.predict_proba(X_train_hyb)[:, 1])

    # SHAP TreeExplainer (with safe native fallback)
    all_feat_names = FEATURE_COLUMNS + emb_cols
    try:
        explainer = shap.TreeExplainer(xgb_hyb)
        shap_vals = explainer.shap_values(X_test_hyb)
        if isinstance(shap_vals, list):
            shap_vals = shap_vals[-1]
    except Exception:
        dmat = xgb.DMatrix(X_test_hyb, feature_names=all_feat_names)
        shap_vals = xgb_hyb.get_booster().predict(dmat, pred_contribs=True)[:, :-1]

    mean_abs = np.abs(shap_vals).mean(axis=0)
    shap_summary = {
        name: round(float(val), 5)
        for name, val in sorted(zip(all_feat_names, mean_abs, strict=True), key=lambda x: -x[1])[:12]
    }

    report = {
        "split": {
            "train_envs": len(train_env_ids),
            "test_envs": len(test_env_ids),
            "train_paths": len(tr_ord),
            "test_paths": len(te_ord),
            "test_positive_rate": round(float(y_test_ord.mean()), 4),
        },
        "models": {
            "B0_rule_cis": _compute_metrics(y_test, b0_prob, 0.5),
            "B1_graph_reachability": _compute_metrics(y_test, b1_prob, 0.5),
            "B2_logistic_regression": _compute_metrics(y_test, b2_prob, 0.5),
            "B3_xgboost_tabular": _compute_metrics(y_test, b3_prob, b3_thresh),
            "B4_gnn_only": _compute_metrics(y_test_ord, b4_prob, 0.5),
            "B5_gnn_xgboost_hybrid": _compute_metrics(y_test_ord, b5_prob_raw, b5_thresh),
            "B5_calibrated": _compute_metrics(y_test_ord, b5_prob_cal, 0.5),
        },
        "mcnemar_b3_vs_b5": _mcnemar_stat(
            y_test_ord,
            (xgb_tab.predict_proba(te_ord[FEATURE_COLUMNS].to_numpy(dtype=float))[:, 1] >= b3_thresh).astype(int),
            (b5_prob_raw >= b5_thresh).astype(int),
        ),
        "top_shap_features": shap_summary,
    }

    (artifacts_dir / "eval_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    gnn.save_weights(str(artifacts_dir / "gnn_weights.pt"))
    with open(artifacts_dir / "model_bundle.pkl", "wb") as f:
        pickle.dump(
            {
                "xgb_hyb": xgb_hyb,
                "cal_model": cal_model,
                "threshold": b5_thresh,
                "feature_names": all_feat_names,
            },
            f,
        )

    # Track in local MLflow
    mlflow.set_tracking_uri(settings.mlflow_tracking_uri)
    mlflow.set_experiment("db-trace")
    with mlflow.start_run(run_name="hybrid-gnn-xgboost"):
        mlflow.log_metrics({
            "b5_precision": report["models"]["B5_gnn_xgboost_hybrid"]["precision"],
            "b5_recall": report["models"]["B5_gnn_xgboost_hybrid"]["recall"],
            "b5_f1": report["models"]["B5_gnn_xgboost_hybrid"]["f1"],
            "b5_pr_auc": report["models"]["B5_gnn_xgboost_hybrid"]["pr_auc"],
            "b3_f1": report["models"]["B3_xgboost_tabular"]["f1"],
        })
        mlflow.log_artifact(str(artifacts_dir / "eval_report.json"))

    return report


def main() -> None:
    report = train_and_evaluate()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
