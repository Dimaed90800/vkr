from __future__ import annotations

try:
    from backend.models.api_surface import NormalizedApiSurface
    from backend.models.synthesized_context import SynthesizedSecurityContext
    from backend.services.endpoint_feature_extractor import EndpointFeatureExtractor
    from backend.services.hypothesis_family_resolver import HypothesisFamilyResolver
    from backend.services.openapi_baseline_synthesis_service import OpenApiBaselineSynthesisService
    from backend.services.resource_family_inference_service import ResourceFamilyInferenceService
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface
    from models.synthesized_context import SynthesizedSecurityContext
    from services.endpoint_feature_extractor import EndpointFeatureExtractor
    from services.hypothesis_family_resolver import HypothesisFamilyResolver
    from services.openapi_baseline_synthesis_service import OpenApiBaselineSynthesisService
    from services.resource_family_inference_service import ResourceFamilyInferenceService


class TaskGenerator:
    CONTROLLED_AUTH_OBJECTS = {
        "/identity/api/v2/vehicle/{id}/location": {
            "object_param_name": "carId",
            "object_id_candidates": ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
        }
    }
    FAMILY_CLASS = {
        "object_authorization": "authorization",
        "collection_access_control": "authorization",
        "privileged_function_access": "authorization",
        "self_scope_cross_user_access": "authorization",
        "property_level_authorization": "authorization",
        "mass_assignment": "authorization",
        "authentication_weakness": "authorization",
        "excessive_data_exposure": "business_logic",
        "resource_abuse_rate_limit": "business_logic",
        "invalid_transition": "business_logic",
        "repeated_sensitive_action": "business_logic",
        "cross_role_workflow_abuse": "business_logic",
        "body_input_injection": "injection",
        "query_input_injection": "injection",
        "reflection_or_template_sink": "injection",
        "url_fetch_or_ssrf": "business_logic",
        "security_misconfiguration": "business_logic",
        "improper_assets_management": "business_logic",
        "documentation_inventory_leak": "business_logic",
        "generic_anomaly_probe": "business_logic",
    }
    FAMILY_SUBTYPE = {
        "object_authorization": "bola",
        "collection_access_control": "generic_access_control",
        "privileged_function_access": "function_level_authorization",
        "self_scope_cross_user_access": "horizontal_privilege",
        "property_level_authorization": "property_level_authorization",
        "mass_assignment": "mass_assignment",
        "authentication_weakness": "auth_bootstrap",
        "excessive_data_exposure": "excessive_data_exposure",
        "resource_abuse_rate_limit": "rate_abuse",
        "invalid_transition": "invalid_transition",
        "repeated_sensitive_action": "repeated_sensitive_action",
        "cross_role_workflow_abuse": "cross_role_workflow_abuse",
        "body_input_injection": "input_injection",
        "query_input_injection": "input_injection",
        "reflection_or_template_sink": "reflection_probe",
        "url_fetch_or_ssrf": "generic_anomaly_probe",
        "security_misconfiguration": "security_misconfiguration",
        "improper_assets_management": "improper_assets_management",
        "documentation_inventory_leak": "documentation_inventory_leak",
        "generic_anomaly_probe": "generic_anomaly_probe",
    }
    TOOL_BY_CLASS = {
        "authorization": "auth_test_access",
        "injection": "injection_test",
        "business_logic": "logic_test",
    }
    WORKER_ROLE_BY_CLASS = {
        "authorization": "Auth & Identity Agent",
        "injection": "Contract & Negative Testing Agent",
        "business_logic": "Business Flow / Stateful Agent",
    }
    AUTH_HIGH_PRIORITY_SUBSTRINGS = (
        "/admin",
        "/management",
        "/moderation",
        "/internal",
        "/merchant",
        "/mechanic",
        "/mechanic_report",
        "/users/all",
        "/orders/all",
        "/shop/orders/all",
        "/vehicle/vehicles",
        "/vehicle/{vehicleid}/location",
        "/vehicle/{id}/location",
        "/videos/{video_id}",
        "/videos/{id}",
        "/posts/{postid}",
        "/posts/{id}",
        "/reports/{id}",
        "/customers",
        "/accounts",
        "/reports",
        "/inventory",
    )
    AUTH_COLLECTION_HINTS = ("all", "list", "users", "orders", "vehicles", "customers", "accounts")
    AUTH_LOW_PRIORITY_SEGMENTS = {"dashboard", "me", "profile", "self"}
    WORKFLOW_HIGH_PRIORITY_SUBSTRINGS = (
        "/shop/orders",
        "/return_order",
        "/apply_coupon",
        "/validate-coupon",
        "/checkout",
        "/pay",
        "/redeem",
        "/order",
        "/status",
        "/mechanic_report",
        "/service_requests",
    )

    def __init__(self) -> None:
        self.feature_extractor = EndpointFeatureExtractor()
        self.family_resolver = HypothesisFamilyResolver()
        self.baseline_synthesis = OpenApiBaselineSynthesisService()
        self.family_inference = ResourceFamilyInferenceService()

    def generate(
        self,
        surface: NormalizedApiSurface,
        roles: list[dict] | None = None,
        capabilities: dict[str, bool] | None = None,
        synthesized_context: SynthesizedSecurityContext | None = None,
        openapi_spec_text: str | None = None,
    ) -> list[dict]:
        role_names = self._role_names(roles or [])
        owner_role = role_names[0]
        other_role = role_names[1]
        capability_state = dict(capabilities or {})
        tasks: list[dict] = []
        counters: dict[str, int] = {"authorization": 0, "injection": 0, "business_logic": 0}

        for endpoint in surface.endpoints:
            features = self.feature_extractor.extract(endpoint)
            family_candidates = self.family_resolver.resolve(endpoint, features)
            family_candidates = self._augment_with_requested_classes(endpoint, family_candidates, features, synthesized_context)
            selected_families = self._select_family_candidates(endpoint, family_candidates)
            for family_candidate in selected_families:
                candidate_class = self.FAMILY_CLASS[family_candidate["family_id"]]
                counters[candidate_class] += 1
                subtype = self._subtype(family_candidate["family_id"], endpoint, features, synthesized_context)
                readiness = self._readiness(candidate_class, family_candidate["family_id"], endpoint, capability_state, synthesized_context)
                allowed_tools = self._allowed_tools(candidate_class, family_candidate["family_id"], endpoint, capability_state, synthesized_context)
                tool_preference = self._tool_preference(candidate_class, family_candidate["family_id"], readiness)
                preparation_options = self._preparation_options(candidate_class, family_candidate["family_id"], endpoint, capability_state, synthesized_context)
                test_strategy = self._test_strategy(candidate_class, family_candidate["family_id"], readiness, preparation_options)
                expected_evidence = list(family_candidate.get("expected_evidence") or [])
                recommended_next_step = allowed_tools[0] if allowed_tools else family_candidate.get("recommended_tool")
                task_id = f"task_{candidate_class}_{counters[candidate_class]:03d}"
                task = {
                    "id": task_id,
                    "class": candidate_class,
                    "subtype": subtype,
                    "endpoint": endpoint.path,
                    "method": endpoint.method,
                    "params": {
                        "path_params": endpoint.path_params,
                        "query_params": endpoint.query_params,
                        "body_fields": endpoint.body_fields,
                        "object_id_candidates": self._object_id_candidates(endpoint),
                        "selected_object_id": self._selected_object_id(endpoint),
                        "requires_object_id_enrichment": self._requires_object_id_enrichment(candidate_class, family_candidate["family_id"], endpoint),
                        "object_param_name": self._object_param_name(endpoint) or None,
                    },
                    "auth_context": {
                        "owner_role": owner_role,
                        "other_role": other_role,
                        "token_strategy": "cross_role_replay",
                    },
                    "hypothesis": self._hypothesis(candidate_class, family_candidate["family_id"], endpoint),
                    "priority": self._priority(candidate_class, family_candidate, endpoint, features, synthesized_context, openapi_spec_text),
                    "retry_count": 0,
                    "rework_hint": None,
                    "status": "pending",
                    "allowed_tools": allowed_tools,
                    "readiness": readiness,
                    "required_capabilities": self._required_capabilities(candidate_class, family_candidate["family_id"], endpoint),
                    "prerequisites": self._prerequisites(candidate_class, family_candidate["family_id"], endpoint),
                    "preparation_options": preparation_options,
                    "test_strategy": test_strategy,
                    "strategy_family": self._strategy_family(candidate_class, family_candidate["family_id"], test_strategy),
                    "capability_state": capability_state,
                    "context_hints": self._context_hints(candidate_class, family_candidate, endpoint, features, synthesized_context, openapi_spec_text),
                    "hypothesis_family": family_candidate["family_id"],
                    "expected_evidence": expected_evidence,
                    "evidence_feasibility": float(family_candidate.get("evidence_feasibility") or 0.0),
                    "noise_risk": float(family_candidate.get("noise_penalty") or 0.0),
                    "recommended_next_step": recommended_next_step,
                    "worker_role": self.WORKER_ROLE_BY_CLASS.get(candidate_class),
                    "preferred_tool": tool_preference["preferred_tool"],
                    "fallback_tools": tool_preference["fallback_tools"],
                    "artifact_requirements": tool_preference["artifact_requirements"],
                    "budget_profile": tool_preference["budget_profile"],
                    "tool_preference": tool_preference,
                }
                tasks.append(task)

        return sorted(tasks, key=lambda item: int(item.get("priority", 0) or 0), reverse=True)

    def _augment_with_requested_classes(self, endpoint, family_candidates: list[dict], features: dict[str, bool], synthesized_context: SynthesizedSecurityContext | None = None) -> list[dict]:
        augmented = list(family_candidates)
        present_families = {str(item.get("family_id") or "") for item in augmented}
        present_classes = {self.FAMILY_CLASS.get(str(item.get("family_id") or "")) for item in augmented}
        requested_classes = {str(item or "").strip() for item in (getattr(endpoint, "candidate_classes", []) or []) if str(item or "").strip()}
        for candidate_class in ("authorization", "injection", "business_logic"):
            if candidate_class not in requested_classes and not self._is_hinted_target(candidate_class, endpoint.path, synthesized_context):
                continue
            if candidate_class in present_classes:
                continue
            family_id = self._fallback_family_for_class(candidate_class, endpoint, features)
            if family_id and family_id not in present_families:
                definition = self.family_resolver.resolve(endpoint, features)
                synthetic = {
                    "family_id": family_id,
                    "title": "",
                    "category": "",
                    "score": 0.58,
                    "recommended_tool": self.TOOL_BY_CLASS[candidate_class],
                    "recommended_tools": [self.TOOL_BY_CLASS[candidate_class]],
                    "expected_evidence": [],
                    "default_vuln_type": self.FAMILY_SUBTYPE.get(family_id, "generic_access_control"),
                    "noise_penalty": 0.28,
                    "evidence_feasibility": 0.58,
                }
                # If the resolver already knows this family but filtered it below threshold, reuse its richer metadata.
                for item in definition:
                    if item.get("family_id") == family_id:
                        synthetic = item
                        break
                augmented.append(synthetic)
                present_families.add(family_id)
                present_classes.add(candidate_class)
        return sorted(augmented, key=lambda item: float(item.get("score") or 0.0), reverse=True)

    def _fallback_family_for_class(self, candidate_class: str, endpoint, features: dict[str, bool]) -> str | None:
        if candidate_class == "authorization":
            if self._is_authish_path(endpoint.path):
                return "authentication_weakness"
            if features.get("is_self_scoped"):
                return "self_scope_cross_user_access"
            if features.get("is_collection_like"):
                return "collection_access_control"
            return "collection_access_control"
        if candidate_class == "injection":
            if str(getattr(endpoint, "method", "GET") or "GET").upper() == "GET":
                return "query_input_injection"
            return "body_input_injection"
        if features.get("is_exposure_prone_get"):
            return "excessive_data_exposure"
        return "invalid_transition"

    def _select_family_candidates(self, endpoint, family_candidates: list[dict]) -> list[dict]:
        selected: list[dict] = []
        selected_by_class: dict[str, int] = {"authorization": 0, "injection": 0, "business_logic": 0}
        for candidate in family_candidates:
            family_id = str(candidate.get("family_id") or "")
            candidate_class = self.FAMILY_CLASS.get(family_id)
            if candidate_class is None:
                continue
            score = float(candidate.get("score") or 0.0)
            if score < 0.55 and family_id != "generic_anomaly_probe":
                continue
            max_per_class = 2 if candidate_class == "authorization" else 1
            if selected_by_class[candidate_class] >= max_per_class:
                continue
            if family_id == "generic_anomaly_probe" and selected:
                continue
            selected.append(candidate)
            selected_by_class[candidate_class] += 1
        if not selected and family_candidates:
            selected.append(family_candidates[0])
        return selected

    def _priority(self, candidate_class: str, family_candidate: dict, endpoint, features: dict[str, bool], synthesized_context: SynthesizedSecurityContext | None = None, openapi_spec_text: str | None = None) -> int:
        base_risk = self._base_risk(candidate_class, endpoint, features)
        score = float(family_candidate.get("score") or 0.0)
        evidence_feasibility = float(family_candidate.get("evidence_feasibility") or 0.0)
        noise_risk = float(family_candidate.get("noise_penalty") or 0.0)
        computed = base_risk + evidence_feasibility + (score * 0.85) - noise_risk
        priority = max(1, min(100, int(round(computed * 40))))
        spec_summary = self.baseline_synthesis.endpoint_support_summary(openapi_spec_text, endpoint.path, endpoint.method)
        feasibility = float(spec_summary.get("success_path_feasibility") or 0.0)
        if feasibility >= 0.8:
            priority = min(100, priority + 8)
        elif feasibility <= 0.35:
            priority = max(1, priority - 8)
        if candidate_class == "authorization":
            priority = max(1, min(100, priority + self._authorization_priority_adjustment(endpoint)))
        if candidate_class == "business_logic":
            priority = max(1, min(100, priority + self._business_logic_priority_adjustment(self.FAMILY_SUBTYPE[family_candidate["family_id"]], endpoint)))
        if candidate_class in {"authorization", "business_logic"} and spec_summary.get("creator_candidates"):
            priority = min(100, priority + 6)
        if candidate_class in {"authorization", "business_logic"} and spec_summary.get("list_candidates"):
            priority = min(100, priority + 4)
        class_hint = self._class_hint(candidate_class, endpoint, synthesized_context)
        if class_hint and self._is_hinted_target(candidate_class, endpoint.path, synthesized_context):
            priority = min(100, priority + int(round(float(class_hint.confidence or 0.0) * 10)))
            priority = min(100, priority + int(round(float(class_hint.priority_hint or 0.0) * 20)))
        if candidate_class == "authorization" and self._requires_object_id_enrichment(candidate_class, family_candidate["family_id"], endpoint):
            priority = max(1, priority - 25)
        return priority

    def _base_risk(self, candidate_class: str, endpoint, features: dict[str, bool]) -> float:
        scores = getattr(endpoint, "candidate_scores", None)
        explicit_score = float(getattr(scores, candidate_class, 0.0) or 0.0)
        if explicit_score > 0.0:
            return explicit_score
        if candidate_class == "authorization":
            return 0.72 if (features.get("is_privileged") or features.get("has_path_object_id") or getattr(endpoint, "auth_required", False)) else 0.56
        if candidate_class == "injection":
            return 0.66 if (features.get("has_body_fields") or features.get("has_query_params")) else 0.5
        return 0.64 if (features.get("has_workflow_verbs") or features.get("is_exposure_prone_get") or features.get("is_versioned")) else 0.52

    def _subtype(self, family_id: str, endpoint, features: dict[str, bool], synthesized_context: SynthesizedSecurityContext | None = None) -> str:
        if family_id == "privileged_function_access" and str(getattr(endpoint, "method", "GET") or "GET").upper() == "GET":
            return "vertical_privilege"
        if family_id == "authentication_weakness" and self._is_auth_bootstrap_endpoint(endpoint.path, synthesized_context):
            return "auth_bootstrap"
        return self.FAMILY_SUBTYPE.get(family_id, "generic_access_control")

    def _hypothesis(self, candidate_class: str, family_id: str, endpoint) -> str:
        mapping = {
            "object_authorization": "Cross-role access to the same object may be possible.",
            "collection_access_control": "A user may access another user's collection or tenant-wide list.",
            "privileged_function_access": "A low-privileged user may be able to reach a privileged function.",
            "self_scope_cross_user_access": "A self-scoped endpoint may expose another user's data.",
            "property_level_authorization": "Protected properties may be writable despite authorization boundaries.",
            "mass_assignment": "Unexpected sensitive properties may be bound from client input.",
            "authentication_weakness": "Authentication bootstrap and credential handling should be exercised before authorization testing.",
            "excessive_data_exposure": "The endpoint may expose sensitive or unnecessary fields in its response.",
            "resource_abuse_rate_limit": "The endpoint may lack effective throttling or abuse protections.",
            "invalid_transition": "The workflow may accept an invalid sequence of actions.",
            "repeated_sensitive_action": "A sensitive action may be repeatable without proper guardrails.",
            "cross_role_workflow_abuse": "A role may perform a workflow step outside its intended scope.",
            "body_input_injection": "Body input may reach an unsafe sink without validation.",
            "query_input_injection": "Query input may reach an unsafe sink without validation.",
            "reflection_or_template_sink": "User-controlled input may be reflected or rendered unsafely.",
            "url_fetch_or_ssrf": "A URL-like field may trigger unintended outbound fetch behavior.",
            "security_misconfiguration": "The endpoint may leak configuration, debug, or CORS weaknesses.",
            "improper_assets_management": "Older or undocumented API versions may still be exposed.",
            "documentation_inventory_leak": "Documentation or inventory endpoints may reveal attack surface unnecessarily.",
            "generic_anomaly_probe": "The endpoint shows enough weak signals to justify a bounded anomaly probe.",
        }
        return mapping.get(family_id, f"{candidate_class.title()} behavior should be tested with bounded evidence.")

    def _readiness(self, candidate_class: str, family_id: str, endpoint, capabilities: dict[str, bool], synthesized_context: SynthesizedSecurityContext | None = None) -> str:
        if candidate_class == "authorization":
            if family_id == "authentication_weakness" and not capabilities.get("has_auth_profiles"):
                return "needs_preparation"
            if family_id in {"property_level_authorization", "mass_assignment"}:
                if capabilities.get("has_multi_role_auth"):
                    return "ready_to_test"
                if capabilities.get("has_api_surface"):
                    return "needs_preparation"
                return "cannot_proceed"
            if not capabilities.get("has_auth_profiles") and capabilities.get("has_api_surface"):
                return "needs_preparation"
            if capabilities.get("has_multi_role_auth") and (
                family_id != "object_authorization" or bool(self._selected_object_id(endpoint))
            ):
                return "ready_to_test"
            if capabilities.get("has_multi_role_auth") and family_id == "object_authorization":
                return "needs_preparation"
            return "cannot_proceed"
        if candidate_class == "injection":
            if endpoint.query_params or endpoint.body_fields or endpoint.path_params:
                return "ready_to_test"
            if capabilities.get("has_api_surface") or self._is_hinted_target(candidate_class, endpoint.path, synthesized_context):
                return "needs_preparation"
            return "cannot_proceed"
        if family_id in {
            "excessive_data_exposure",
            "resource_abuse_rate_limit",
            "security_misconfiguration",
            "improper_assets_management",
            "documentation_inventory_leak",
        }:
            return "ready_to_test" if capabilities.get("has_api_surface") else "cannot_proceed"
        if family_id == "url_fetch_or_ssrf":
            return "cannot_proceed"
        if capabilities.get("has_workflow_hints"):
            return "ready_to_test"
        if capabilities.get("has_api_surface") or self._is_hinted_target(candidate_class, endpoint.path, synthesized_context):
            return "needs_preparation"
        return "cannot_proceed"

    def _allowed_tools(self, candidate_class: str, family_id: str, endpoint, capabilities: dict[str, bool], synthesized_context: SynthesizedSecurityContext | None = None) -> list[str]:
        readiness = self._readiness(candidate_class, family_id, endpoint, capabilities, synthesized_context)
        if candidate_class == "authorization":
            if readiness == "ready_to_test":
                if family_id in {"property_level_authorization", "mass_assignment"}:
                    return ["akto_authz_scan", "astf_top10_suite", "property_mutation_test"]
                return ["akto_authz_scan", "astf_top10_suite", "auth_test_access"]
            if self._is_auth_bootstrap_endpoint(endpoint.path, synthesized_context):
                return ["auto_provision"]
            if family_id == "authentication_weakness":
                if capabilities.get("has_register_endpoint") and capabilities.get("has_login_endpoint"):
                    return ["auto_provision"]
                return ["auth_probe_entrypoints"]
            if not capabilities.get("has_auth_profiles") and capabilities.get("has_api_surface"):
                if capabilities.get("has_register_endpoint") and capabilities.get("has_login_endpoint"):
                    return ["auto_provision"]
                return ["auth_probe_entrypoints"]
            if family_id == "object_authorization":
                return ["create_test_object"]
            return ["noop_outcome"]
        if candidate_class == "injection":
            if readiness == "ready_to_test":
                if family_id == "reflection_or_template_sink":
                    return ["schemathesis_negative_test", "cats_fuzz_test", "reflection_probe", "injection_test"]
                return ["schemathesis_negative_test", "cats_fuzz_test", "astf_top10_suite", "injection_test", "reflection_probe", "path_fuzz_probe"]
            if readiness == "needs_preparation":
                return ["input_shape_probe"]
            return ["noop_outcome"]
        if readiness == "ready_to_test":
            mapping = {
                "excessive_data_exposure": ["akto_authz_scan", "astf_top10_suite", "data_exposure_test"],
                "resource_abuse_rate_limit": ["cats_fuzz_test", "astf_top10_suite", "resource_abuse_test"],
                "security_misconfiguration": ["astf_top10_suite", "misconfiguration_test"],
                "improper_assets_management": ["akto_inventory_discovery", "astf_top10_suite", "version_diff_test"],
                "documentation_inventory_leak": ["akto_inventory_discovery", "astf_top10_suite", "version_diff_test"],
                "url_fetch_or_ssrf": ["noop_outcome"],
            }
            return mapping.get(family_id, ["restler_fuzz", "schemathesis_stateful_test", "logic_test"])
        if readiness == "needs_preparation":
            return ["workflow_probe"]
        return ["noop_outcome"]

    def _tool_preference(self, candidate_class: str, family_id: str, readiness: str) -> dict:
        if readiness not in {"ready_to_test", "needs_preparation"}:
            return {
                "preferred_tool": "noop_outcome",
                "fallback_tools": [],
                "artifact_requirements": [],
                "budget_profile": "minimal",
            }
        if candidate_class == "authorization":
            fallback = ["astf_top10_suite", "auth_test_access"]
            if family_id in {"property_level_authorization", "mass_assignment"}:
                fallback = ["astf_top10_suite", "property_mutation_test"]
            return {
                "preferred_tool": "akto_authz_scan",
                "fallback_tools": fallback,
                "artifact_requirements": ["http_trace", "replay_pack", "raw_report"],
                "budget_profile": "balanced",
            }
        if candidate_class == "injection":
            return {
                "preferred_tool": "schemathesis_negative_test",
                "fallback_tools": ["cats_fuzz_test", "astf_top10_suite", "injection_test"],
                "artifact_requirements": ["http_trace", "raw_report"],
                "budget_profile": "balanced",
            }
        if family_id in {"invalid_transition", "repeated_sensitive_action", "cross_role_workflow_abuse"}:
            return {
                "preferred_tool": "restler_fuzz",
                "fallback_tools": ["schemathesis_stateful_test", "logic_test"],
                "artifact_requirements": ["http_trace", "replay_pack", "raw_report"],
                "budget_profile": "stateful",
            }
        if family_id in {"improper_assets_management", "documentation_inventory_leak"}:
            return {
                "preferred_tool": "akto_inventory_discovery",
                "fallback_tools": ["astf_top10_suite", "version_diff_test"],
                "artifact_requirements": ["raw_report"],
                "budget_profile": "minimal",
            }
        return {
            "preferred_tool": "schemathesis_stateful_test",
            "fallback_tools": ["restler_fuzz", "akto_authz_scan", "logic_test"],
            "artifact_requirements": ["http_trace", "replay_pack", "raw_report"],
            "budget_profile": "balanced",
        }

    def _required_capabilities(self, candidate_class: str, family_id: str, endpoint) -> list[str]:
        if candidate_class == "authorization":
            required = ["has_auth_profiles"]
            if family_id == "object_authorization":
                required.append("has_object_candidates")
            return required
        if candidate_class == "injection":
            return ["has_api_surface", "has_input_shape"]
        if family_id in {"excessive_data_exposure", "resource_abuse_rate_limit", "security_misconfiguration", "improper_assets_management", "documentation_inventory_leak"}:
            return ["has_api_surface"]
        return ["has_api_surface", "has_workflow_hints"]

    def _prerequisites(self, candidate_class: str, family_id: str, endpoint) -> dict:
        auth_required = bool(getattr(endpoint, "auth_required", False))
        object_like = bool(getattr(endpoint, "path_params", None) or "{" in str(endpoint.path or ""))
        if candidate_class == "authorization":
            if family_id == "authentication_weakness":
                return {
                    "requires_auth_context": False,
                    "requires_object_id": False,
                    "requires_valid_baseline": True,
                    "requires_success_path": True,
                    "requires_workflow_state": False,
                    "requires_creator_candidate": False,
                    "requires_list_candidate": False,
                }
            return {
                "requires_auth_context": True,
                "requires_object_id": bool(family_id == "object_authorization" and object_like),
                "requires_valid_baseline": bool(family_id in {"property_level_authorization", "mass_assignment"}),
                "requires_success_path": bool(family_id in {"property_level_authorization", "mass_assignment"}),
                "requires_workflow_state": False,
                "requires_creator_candidate": False,
                "requires_list_candidate": False,
            }
        if candidate_class == "injection":
            return {
                "requires_auth_context": auth_required,
                "requires_object_id": False,
                "requires_valid_baseline": True,
                "requires_success_path": False,
                "requires_workflow_state": False,
                "requires_creator_candidate": False,
                "requires_list_candidate": False,
            }
        if family_id == "excessive_data_exposure":
            return {
                "requires_auth_context": auth_required,
                "requires_object_id": bool(object_like and "{id" in str(endpoint.path or "").lower()),
                "requires_valid_baseline": True,
                "requires_success_path": True,
                "requires_workflow_state": False,
                "requires_creator_candidate": False,
                "requires_list_candidate": False,
            }
        if family_id in {"invalid_transition", "repeated_sensitive_action", "cross_role_workflow_abuse"}:
            return {
                "requires_auth_context": auth_required,
                "requires_object_id": object_like,
                "requires_valid_baseline": True,
                "requires_success_path": True,
                "requires_workflow_state": True,
                "requires_creator_candidate": False,
                "requires_list_candidate": False,
            }
        return {
            "requires_auth_context": auth_required,
            "requires_object_id": False,
            "requires_valid_baseline": False,
            "requires_success_path": False,
            "requires_workflow_state": False,
            "requires_creator_candidate": False,
            "requires_list_candidate": False,
        }

    def _preparation_options(self, candidate_class: str, family_id: str, endpoint, capabilities: dict[str, bool], synthesized_context: SynthesizedSecurityContext | None = None) -> list[str]:
        readiness = self._readiness(candidate_class, family_id, endpoint, capabilities, synthesized_context)
        if readiness != "needs_preparation":
            return []
        if candidate_class == "authorization":
            if self._is_auth_bootstrap_endpoint(endpoint.path, synthesized_context):
                return ["auto_provision"]
            if family_id == "authentication_weakness":
                if capabilities.get("has_register_endpoint") and capabilities.get("has_login_endpoint"):
                    return ["auto_provision"]
                return ["auth_probe_entrypoints"]
            if not capabilities.get("has_auth_profiles"):
                if capabilities.get("has_register_endpoint") and capabilities.get("has_login_endpoint"):
                    return ["auto_provision"]
                return ["auth_probe_entrypoints"]
            if family_id == "object_authorization":
                return ["create_test_object"]
            return ["capture_authenticated_traffic"]
        if candidate_class == "injection":
            return ["input_shape_probe", "capture_authenticated_traffic"]
        if family_id in {"excessive_data_exposure", "resource_abuse_rate_limit", "security_misconfiguration", "improper_assets_management", "documentation_inventory_leak"}:
            return []
        return ["workflow_probe", "capture_authenticated_traffic"]

    def _test_strategy(self, candidate_class: str, family_id: str, readiness: str, preparation_options: list[str]) -> str:
        if candidate_class == "authorization":
            if readiness == "ready_to_test":
                if family_id in {"property_level_authorization", "mass_assignment"}:
                    return "property_mutation_probe"
                return "cross_role_replay"
            if "auth_probe_entrypoints" in preparation_options:
                return "discover_auth_bootstrap_then_provision"
            if "auto_provision" in preparation_options:
                return "provision_then_replay"
            if "create_test_object" in preparation_options:
                return "prepare_object_then_replay"
            return "bounded_stop"
        if candidate_class == "injection":
            return "direct_input_probe" if readiness == "ready_to_test" else ("shape_probe_then_test" if readiness == "needs_preparation" else "bounded_stop")
        if family_id == "excessive_data_exposure":
            return "response_field_exposure_probe"
        if family_id == "resource_abuse_rate_limit":
            return "bounded_rate_probe"
        if family_id == "security_misconfiguration":
            return "bounded_config_probe"
        if family_id in {"improper_assets_management", "documentation_inventory_leak"}:
            return "version_diff_probe"
        if family_id == "url_fetch_or_ssrf":
            return "bounded_stop"
        return "workflow_sequence_probe" if readiness == "ready_to_test" else ("workflow_probe_then_test" if readiness == "needs_preparation" else "bounded_stop")

    def _strategy_family(self, candidate_class: str, family_id: str, test_strategy: str) -> str:
        strategy = str(test_strategy or "").strip().lower()
        if candidate_class == "injection":
            if "shape" in strategy or "baseline" in strategy:
                return "baseline_refinement"
            if "reflection" in strategy:
                return "reflection_probe"
            if "path" in strategy:
                return "path_probe"
            return "payload_probe"
        if candidate_class == "authorization":
            if "bootstrap" in strategy or family_id == "authentication_weakness":
                return "auth_bootstrap"
            if "object" in strategy:
                return "object_materialization"
            return "access_replay"
        if family_id == "excessive_data_exposure":
            return "success_path_exposure"
        if family_id in {"invalid_transition", "repeated_sensitive_action", "cross_role_workflow_abuse"}:
            return "workflow_state"
        return strategy or family_id or candidate_class

    def _context_hints(self, candidate_class: str, family_candidate: dict, endpoint, features: dict[str, bool], synthesized_context: SynthesizedSecurityContext | None = None, openapi_spec_text: str | None = None) -> dict:
        class_hint = self._class_hint(candidate_class, endpoint, synthesized_context)
        family_candidates = self.family_resolver.resolve(endpoint, features)
        spec_summary = self.baseline_synthesis.endpoint_support_summary(openapi_spec_text, endpoint.path, endpoint.method)
        resource_family = self.family_inference.infer(
            path=endpoint.path,
            method=endpoint.method,
            tags=getattr(endpoint, "tags", []) or [],
            operation_id=str(getattr(endpoint, "operation_id", "") or ""),
            summary=str(getattr(endpoint, "summary", "") or ""),
            body_fields=getattr(endpoint, "body_fields", []) or [],
            query_params=getattr(endpoint, "query_params", []) or [],
        )
        context = {
            "family_score": float(family_candidate.get("score") or 0.0),
            "default_vuln_type": str(family_candidate.get("default_vuln_type") or ""),
            "recommended_tools": list(family_candidate.get("recommended_tools") or []),
            "resource_family": resource_family,
            "auth_required": bool(getattr(endpoint, "auth_required", False)),
            "spec_baseline_available": bool(spec_summary.get("has_spec_baseline")),
            "baseline_valid": bool(spec_summary.get("baseline_valid", spec_summary.get("has_spec_baseline"))),
            "baseline_source": str(spec_summary.get("baseline_source") or ""),
            "missing_required_fields": list(spec_summary.get("missing_required_fields") or []),
            "spec_confidence": float(spec_summary.get("spec_confidence") or 0.0),
            "spec_success_path_feasibility": float(spec_summary.get("success_path_feasibility") or 0.0),
            "spec_creator_candidates": list(spec_summary.get("creator_candidates") or []),
            "spec_list_candidates": list(spec_summary.get("list_candidates") or []),
            "candidate_families": [
                {
                    "family_id": item["family_id"],
                    "score": float(item["score"]),
                    "recommended_tool": item["recommended_tool"],
                }
                for item in family_candidates[:4]
            ],
            "endpoint_features": dict(features),
        }
        if class_hint is None:
            return context
        hinted_targets = self._hinted_targets(candidate_class, synthesized_context)
        if endpoint.path not in hinted_targets and not self._is_auth_bootstrap_endpoint(endpoint.path, synthesized_context):
            return context
        bootstrap = self._bootstrap_candidates(candidate_class, synthesized_context)
        context.update(
            {
                "class_hint_confidence": float(class_hint.confidence or 0.0),
                "priority_hint": float(class_hint.priority_hint or 0.0),
                "likely_subtypes": list(class_hint.likely_subtypes or []),
                "missing_prerequisites": list(class_hint.missing_prerequisites or []),
                "bootstrap_candidates": bootstrap,
                "preparation_suggestions": list(class_hint.preparation_suggestions or []),
            }
        )
        return context

    def _class_hint(self, candidate_class: str, endpoint, synthesized_context: SynthesizedSecurityContext | None = None):
        if synthesized_context is None:
            return None
        return getattr(synthesized_context, candidate_class, None)

    def _hinted_targets(self, candidate_class: str, synthesized_context: SynthesizedSecurityContext | None = None) -> set[str]:
        class_hint = getattr(synthesized_context, candidate_class, None) if synthesized_context is not None else None
        if class_hint is None:
            return set()
        return {str(item or "").strip() for item in (class_hint.candidate_targets or []) if str(item or "").strip()}

    def _bootstrap_candidates(self, candidate_class: str, synthesized_context: SynthesizedSecurityContext | None = None) -> dict:
        class_hint = getattr(synthesized_context, candidate_class, None) if synthesized_context is not None else None
        if class_hint is None:
            return {}
        bootstrap = getattr(class_hint, "candidate_bootstrap_endpoints", None)
        if bootstrap is None:
            return {}
        return bootstrap.model_dump(mode="json")

    def _is_hinted_target(self, candidate_class: str, endpoint_path: str, synthesized_context: SynthesizedSecurityContext | None = None) -> bool:
        return str(endpoint_path or "").strip() in self._hinted_targets(candidate_class, synthesized_context)

    def _is_auth_bootstrap_endpoint(self, endpoint_path: str, synthesized_context: SynthesizedSecurityContext | None = None) -> bool:
        normalized_path = str(endpoint_path or "").strip().lower()
        if any(marker in normalized_path for marker in ("login", "signin", "sign-in", "signup", "register", "password", "otp", "token")):
            return True
        if synthesized_context is None:
            return False
        auth = synthesized_context.authorization
        bootstrap_sets = [
            *(auth.candidate_bootstrap_endpoints.register or []),
            *(auth.candidate_bootstrap_endpoints.login or []),
            *(auth.candidate_bootstrap_endpoints.profile or []),
        ]
        normalized = {str(item or "").strip() for item in bootstrap_sets if str(item or "").strip()}
        return str(endpoint_path or "").strip() in normalized

    def _role_names(self, roles: list[dict]) -> tuple[str, str]:
        names = []
        for item in roles:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("role") or "").strip()
            if name:
                names.append(name)
        if len(names) >= 2:
            return names[0], names[1]
        if len(names) == 1:
            return names[0], "user_b"
        return "user_a", "user_b"

    def _requires_object_id_enrichment(self, candidate_class: str, family_id: str, endpoint) -> bool:
        if candidate_class != "authorization" or family_id != "object_authorization":
            return False
        return self._selected_object_id(endpoint) is None

    def _selected_object_id(self, endpoint) -> str | None:
        candidates = self._object_id_candidates(endpoint)
        return candidates[0] if candidates else None

    def _object_id_candidates(self, endpoint) -> list[str]:
        candidates = [str(item).strip() for item in (getattr(endpoint, "object_id_candidates", []) or []) if str(item).strip()]
        controlled = self.CONTROLLED_AUTH_OBJECTS.get(endpoint.path, {})
        for item in controlled.get("object_id_candidates", []):
            value = str(item).strip()
            if value:
                candidates.append(value)
        unique = []
        seen = set()
        for item in candidates:
            if item in seen or self._is_guessed_object_id(item):
                continue
            seen.add(item)
            unique.append(item)
        return unique

    def _object_param_name(self, endpoint) -> str:
        controlled = self.CONTROLLED_AUTH_OBJECTS.get(endpoint.path, {})
        return str(controlled.get("object_param_name") or getattr(endpoint, "object_param_name", "") or "")

    def _is_guessed_object_id(self, value: str) -> bool:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return True
        return normalized in {"1", "123", "test", "sample", "example", "demo", "foo", "bar"}

    def _authorization_priority_adjustment(self, endpoint) -> int:
        path = str(endpoint.path or "").strip().lower()
        segments = [item for item in path.split("/") if item]
        query_params = {str(item or "").strip().lower() for item in (endpoint.query_params or []) if str(item or "").strip()}
        adjustment = 0
        if any(marker in path for marker in self.AUTH_HIGH_PRIORITY_SUBSTRINGS):
            adjustment += 18
        if any(token in segments for token in self.AUTH_COLLECTION_HINTS) and str(endpoint.method or "").upper() == "GET":
            adjustment += 8
        if query_params.intersection({"limit", "offset", "page", "size"}):
            adjustment += 8
        if self._looks_admin_or_management(path):
            adjustment += 8
        if getattr(endpoint, "auth_required", False) and (getattr(endpoint, "path_params", None) or "{" in path):
            adjustment += 12
        if any(marker in path for marker in ("/vehicle/", "/video", "/post", "/report", "/merchant", "/mechanic")):
            adjustment += 6
        if self._is_self_scoped_authorization_target(endpoint):
            adjustment -= 22
        if path.endswith("/dashboard") or path.endswith("/me") or path.endswith("/profile") or path.endswith("/account"):
            adjustment -= 8
        return adjustment

    def _is_self_scoped_authorization_target(self, endpoint) -> bool:
        path = str(endpoint.path or "").strip().lower()
        segments = [item for item in path.split("/") if item]
        if any(segment in self.AUTH_LOW_PRIORITY_SEGMENTS for segment in segments):
            return True
        return any(marker in path for marker in ("/user/dashboard", "/dashboard", "/me", "/profile")) or path.endswith("/account")

    def _looks_admin_or_management(self, path: str) -> bool:
        value = str(path or "").strip().lower()
        return any(token in value for token in ("/admin", "/management", "/moderation", "/internal", "/staff", "/reports", "/config"))

    def _is_authish_path(self, path: str) -> bool:
        value = str(path or "").strip().lower()
        return any(token in value for token in ("auth", "login", "signup", "signin", "register", "password", "otp", "token"))

    def _business_logic_priority_adjustment(self, subtype: str, endpoint) -> int:
        path = str(endpoint.path or "").strip().lower()
        if subtype == "rate_abuse":
            return 14
        if subtype == "excessive_data_exposure":
            boost = 12
            if any(token in path for token in ("vehicle", "video", "report", "order", "account", "user", "customer")):
                boost += 6
            return boost
        if subtype == "security_misconfiguration":
            return 10
        if subtype in {"improper_assets_management", "documentation_inventory_leak"}:
            return 8
        if any(token in path for token in self.WORKFLOW_HIGH_PRIORITY_SUBSTRINGS):
            return 14
        if any(token in path for token in ("approve", "return", "cancel", "checkout", "redeem", "order", "status", "pay")):
            return 10
        return 0
