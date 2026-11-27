# Data Card: DB-TRACE Synthetic Cloud Attack-Path Dataset

## Overview
- **Size**: 100 synthetic AWS + PostgreSQL environments generating ~3,000–5,000 labeled access paths.
- **Scenario Templates**: Capital One SSRF/IMDSv1, CloudGoat (`rds_snapshot`, `rce_web_app`, `lambda_privesc`, `iam_privesc_rollback`), Stratus Red Team (`rds_share`), public RDS+IAM, plus near-miss negatives (explicit Deny, blocked SG, wrong DB grant) and benign least-privilege environments.
- **Labeling Oracle**: Deterministic multi-hop evaluator checking (1) IAM effective-allow (`Explicit Deny > Boundary > Allow`), (2) VPC/Subnet/SG reachability on port 5432, and (3) PostgreSQL transitive role-membership and `SELECT`/`ALL` grant closure on sensitive/PII tables.
- **Access Logs**: 30-day synthetic CloudTrail and `pgaudit` legitimate business-hours traffic per environment for remediation replay verification.
