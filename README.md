# DB-TRACE

**AI-Driven Contextual Risk Detection and Verified Remediation for Cloud Database Security**

DB-TRACE models cloud environments (AWS IAM, compute, network/security groups, RDS, and PostgreSQL grants) as a heterogeneous graph, learns path-level risk using a hybrid **Graph Neural Network (PyTorch Geometric) + XGBoost** pipeline with **SHAP** explainability, and verifies proposed remediations by replaying historical access logs (CloudTrail & `pgaudit`) before anything is applied.

## Quickstart (Local)

```powershell
cd db-trace
uv sync --extra dev
uv run pytest
```
