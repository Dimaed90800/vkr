"""Phase 17B-3b — graph-only query parameter candidates for injection_testing compiler.

MVP: GET/HEAD only, query parameter names from ``Operation.query_params``,
no path/body, no LLM/scenario text. Used only by ScenarioPlanCompiler.
"""
from __future__ import annotations

try:
    from backend.models.api_graph import Operation
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import Operation

# Fixed subset for automatic planner MVP (no nosql_like / path_traversal_marker).
INJECTION_COMPILER_PAYLOAD_FAMILIES: tuple[str, ...] = (
    "sql_like",
    "template_marker",
    "xss_reflection_marker",
)

_SENSITIVE_QUERY_SUBSTR: tuple[str, ...] = (
    "authorization",
    "token",
    "cookie",
    "password",
    "api_key",
    "secret",
    "access_token",
    "refresh_token",
)


def injection_query_param_name_is_sensitive(name: str) -> bool:
    lower = (name or "").strip().lower()
    if not lower:
        return True
    return any(substr in lower for substr in _SENSITIVE_QUERY_SUBSTR)


def safe_query_parameter_candidates_for_operation(
    operation: Operation,
    *,
    max_candidates: int = 2,
) -> list[dict[str, str]]:
    """Return ``[{"name": ..., "in": "query"}, ...]`` from graph only."""
    method = str(operation.method or "").upper()
    if method not in {"GET", "HEAD"}:
        return []
    out: list[dict[str, str]] = []
    for raw in operation.query_params or []:
        n = str(raw or "").strip()
        if not n or injection_query_param_name_is_sensitive(n):
            continue
        if any(c.get("name") == n for c in out):
            continue
        out.append({"name": n, "in": "query"})
        if len(out) >= max_candidates:
            break
    return out
