"""Grounded Remediation Narrator backed by SHAP attributions & verified patches."""

from __future__ import annotations

import json
import urllib.request

from dbtrace.config import settings
from dbtrace.remediation.engine import RemediationResult


def narrate_remediation(
    path_id: str,
    top_shap: list[dict[str, object]],
    remediation: RemediationResult,
) -> dict[str, object]:
    """Produce a grounded explanation citing SHAP features and the verified remediation."""
    shap_citations = [f"{item['feature']} (impact={item['shap_value']:+.3f})" for item in top_shap[:3]]
    fallback_summary = (
        f"Path {path_id} was flagged primarily due to: {', '.join(shap_citations)}. "
        f"Applying '{remediation.title}' eliminates {remediation.paths_eliminated} exploitable path(s) "
        f"with {remediation.legit_broken}/{remediation.legit_total} legitimate calls broken "
        f"(status: {remediation.status})."
    )

    if settings.llm_provider == "none" or not settings.llm_base_url:
        return {"summary": fallback_summary, "citations": shap_citations, "provider": "deterministic"}

    prompt = (
        "You are a cloud security analyst. Write a concise 2-sentence explanation citing ONLY the provided "
        "SHAP features and verification numbers. Do not invent any resource names.\n"
        f"Path: {path_id}\nSHAP: {json.dumps(top_shap[:4])}\n"
        f"Fix: {remediation.title} | Eliminated: {remediation.paths_eliminated} | "
        f"Broken legit calls: {remediation.legit_broken}/{remediation.legit_total} | Status: {remediation.status}"
    )
    try:
        req = urllib.request.Request(
            f"{settings.llm_base_url.rstrip('/')}/chat/completions",
            data=json.dumps({
                "model": settings.llm_model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
            }).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {settings.llm_api_key}"} if settings.llm_api_key else {}),
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            text = body["choices"][0]["message"]["content"].strip()
            return {"summary": text, "citations": shap_citations, "provider": settings.llm_provider}
    except Exception:
        return {"summary": fallback_summary, "citations": shap_citations, "provider": "deterministic-fallback"}
