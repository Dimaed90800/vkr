from __future__ import annotations

from copy import deepcopy

try:
    from backend.services.hypothesis_family_registry import FAMILY_DEFINITIONS
except ModuleNotFoundError:  # pragma: no cover
    from services.hypothesis_family_registry import FAMILY_DEFINITIONS


class HypothesisFamilyResolver:
    def resolve(self, endpoint, features: dict[str, bool]) -> list[dict]:
        candidates: list[dict] = []

        def add(family_id: str, score: float, noise_delta: float = 0.0, feasibility_delta: float = 0.0) -> None:
            definition = deepcopy(FAMILY_DEFINITIONS[family_id])
            noise_penalty = self._clamp(float(definition["noise_penalty_hint"]) + noise_delta)
            evidence_feasibility = self._clamp(float(definition["feasibility_hint"]) + feasibility_delta)
            candidate = {
                "family_id": family_id,
                "title": definition["title"],
                "category": definition["category"],
                "score": self._clamp(score),
                "recommended_tool": list(definition["recommended_tools"])[0] if definition["recommended_tools"] else "noop_outcome",
                "recommended_tools": list(definition["recommended_tools"]),
                "expected_evidence": list(definition["expected_evidence"]),
                "default_vuln_type": definition["default_vuln_type"],
                "noise_penalty": noise_penalty,
                "evidence_feasibility": evidence_feasibility,
            }
            candidates.append(candidate)

        auth_required = bool(getattr(endpoint, "auth_required", False))
        method = str(getattr(endpoint, "method", "GET") or "GET").upper()
        path = str(getattr(endpoint, "path", "") or "").strip().lower()

        if features.get("has_path_object_id") or features.get("has_query_object_id"):
            add("object_authorization", 0.82 + (0.08 if auth_required else 0.0), feasibility_delta=0.04)

        if features.get("is_collection_like"):
            boost = 0.08 if features.get("is_privileged") else 0.0
            add("collection_access_control", 0.72 + boost + (0.05 if auth_required else 0.0))

        if features.get("is_privileged"):
            add("privileged_function_access", 0.88 + (0.04 if auth_required else 0.0), feasibility_delta=0.03)

        if features.get("is_self_scoped"):
            add("self_scope_cross_user_access", 0.68 + (0.05 if auth_required else 0.0), noise_delta=0.08)

        if method in {"POST", "PUT", "PATCH"} and features.get("has_sensitive_body_fields"):
            add("property_level_authorization", 0.84 + (0.04 if auth_required else -0.05))
            add("mass_assignment", 0.8 + (0.03 if features.get("has_body_object_id") else 0.0))

        if features.get("has_auth_semantics") and any(token in path for token in ("login", "signup", "signin", "register", "token", "password", "otp")):
            add("authentication_weakness", 0.8, noise_delta=0.02)
            add("resource_abuse_rate_limit", 0.78, feasibility_delta=0.04)
        elif features.get("has_auth_semantics"):
            add("authentication_weakness", 0.62, noise_delta=0.06)

        if features.get("is_exposure_prone_get"):
            add("excessive_data_exposure", 0.74 + (0.05 if features.get("is_collection_like") else 0.0))

        if features.get("has_workflow_verbs"):
            add("invalid_transition", 0.8, feasibility_delta=0.02)
            add("repeated_sensitive_action", 0.74)
            if features.get("has_auth_semantics"):
                add("cross_role_workflow_abuse", 0.78, feasibility_delta=0.03)

        if features.get("has_body_fields"):
            add("body_input_injection", 0.76)
        if features.get("has_query_params"):
            add("query_input_injection", 0.78)
        if features.get("has_body_fields") or features.get("has_query_params"):
            add("reflection_or_template_sink", 0.68 + (0.04 if method == "GET" else 0.0))

        if features.get("has_url_field"):
            add("url_fetch_or_ssrf", 0.66, noise_delta=0.05, feasibility_delta=-0.08)

        if features.get("is_privileged") or features.get("is_doc_or_inventory_like") or features.get("is_versioned"):
            add("security_misconfiguration", 0.69 + (0.05 if features.get("is_doc_or_inventory_like") else 0.0))

        if features.get("is_versioned"):
            add("improper_assets_management", 0.82, feasibility_delta=0.02)

        if features.get("is_doc_or_inventory_like"):
            add("documentation_inventory_leak", 0.86, feasibility_delta=0.04)

        if features.get("has_search_semantics") and not any(item["family_id"] == "resource_abuse_rate_limit" for item in candidates):
            add("resource_abuse_rate_limit", 0.64, noise_delta=0.04)

        deduped = self._dedupe(candidates)
        if not deduped:
            add("generic_anomaly_probe", 0.24)
            deduped = self._dedupe(candidates)

        return sorted(deduped, key=lambda item: float(item["score"]), reverse=True)

    def _dedupe(self, candidates: list[dict]) -> list[dict]:
        best_by_family: dict[str, dict] = {}
        for item in candidates:
            family_id = str(item.get("family_id") or "").strip()
            if not family_id:
                continue
            current = best_by_family.get(family_id)
            if current is None or float(item.get("score") or 0.0) > float(current.get("score") or 0.0):
                best_by_family[family_id] = item
        return list(best_by_family.values())

    def _clamp(self, value: float) -> float:
        return max(0.0, min(1.0, round(float(value), 4)))
