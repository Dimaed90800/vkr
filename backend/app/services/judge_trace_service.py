from __future__ import annotations


def classify_dify_issue(
    resolution_mode: str | None,
    raw_reason: str | None = None,
    reasoning_summary: str | None = None,
):
    mode = str(resolution_mode or "")
    raw = str(raw_reason or "")
    summary = str(reasoning_summary or "")
    text = f"{raw}\n{summary}".lower()

    if mode in {"dify_direct_match", "unified_direct_match"}:
        return "direct_match"
    if (
        (mode.startswith("dify_") or mode.startswith("unified_"))
        and "recovery" in mode
    ):
        return "semantic_recovery"
    if mode == "rule_based_direct":
        return "rule_based_direct"

    if mode in {"dify_rule_based_fallback", "unified_invalid_selection_fallback"}:
        return "invalid_candidate_key"

    if mode in {"dify_exception_fallback", "unified_no_dify_fallback"}:
        if "status code 402" in text or "more credits" in text or "can only afford" in text:
            return "provider_credit_limit"
        if "could not extract selected_key from dify workflow outputs: {}" in text:
            return "empty_outputs"
        if "timeout" in text:
            return "provider_timeout"
        if "status code" in text or "api request failed" in text or "plugininvokeerror" in text:
            return "provider_error"
        return "exception_fallback_other"

    if mode == "unified_rule_based_override":
        return "rule_based_override"

    if "fallback" in text:
        return "fallback_other"

    return "unknown"
