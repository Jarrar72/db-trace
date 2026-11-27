# Model Card: DB-TRACE Hybrid Risk Classifier (GNN + XGBoost + SHAP)

## Model Overview
- **Architecture**: Heterogeneous GraphSAGE (`torch_geometric.nn.to_hetero`) producing node and path-level embeddings (reduced via PCA to 16 dimensions), concatenated with 29 tabular cloud/database configuration & behavioral features, classified by **XGBoost** with isotonic probability calibration.
- **Intended Use**: Prioritizing exploitable multi-hop attack paths (`Identity -> Compute -> Network -> RDS -> DBRole -> DBTable`) in cloud PostgreSQL environments and pairing them with log-verified remediations.
- **Out-of-Scope**: Autonomous production remediation without human review; non-PostgreSQL engines.

## Evaluation Protocol
- **Data Split**: Leakage-safe 80% train / 20% test split grouped by environment (`StratifiedGroupKFold` on `env_id`). All GNN weights, scalers, and PCA projections are fit strictly on training environments.
- **Target Benchmarks**: Recall >= 85% (minimize missed exploitable paths) and Precision >= 80% (preserve analyst trust).
- **Metrics Reported**: Precision, Recall, F1, PR-AUC, MCC, Accuracy, Brier Score, 2x2 Confusion Matrix, and McNemar's test against tabular-only XGBoost.

## Explainability & Safety
- **SHAP TreeExplainer** explains per-path risk scores and global feature importance.
- **Remediation Verification**: Every candidate fix is replayed against historical CloudTrail and `pgaudit` logs before being marked `Verified Safe-to-Apply`.
