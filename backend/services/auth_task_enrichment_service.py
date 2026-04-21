from __future__ import annotations

from copy import deepcopy
from typing import Any


class AuthTaskEnrichmentService:
    def enrich(self, task: dict[str, Any], roles: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        enriched = deepcopy(task)
        auth_context = dict(enriched.get("auth_context") or {})
        role_names = [str(item.get("name") or item.get("role") or "").strip() for item in list(roles or []) if str(item.get("name") or item.get("role") or "").strip()]
        if role_names and not auth_context.get("owner_role"):
            auth_context["owner_role"] = role_names[0]
        if len(role_names) > 1 and not auth_context.get("other_role"):
            auth_context["other_role"] = role_names[1]
        enriched["auth_context"] = auth_context
        return enriched
