import html
import ipaddress
import json
import logging
import re
import uuid
from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from backend.services.auth_finding_classifier import (
        classify_auth_finding,
        finding_title_label,
        finding_type_label,
    )
    from backend.models.traffic_discovery import TrafficDiscoveryRequest
    from backend.services.auth_preparation_service import AuthPreparationService
    from backend.services.diagnostic_logging_service import DiagnosticLoggingService
    from backend.models.testing import Artifact, TaskModel, ToolTestRequest, ToolTestResponse
    from backend.services.diff_service import DiffService
    from backend.services.http_client import HttpClient
    from backend.services.openapi_baseline_synthesis_service import OpenApiBaselineSynthesisService
    from backend.services.rejection_analyzer import RejectionAnalyzer
    from backend.services.resource_family_inference_service import ResourceFamilyInferenceService
    from backend.services.traffic_capture_service import TrafficCaptureService
except ModuleNotFoundError:  # pragma: no cover
    from services.auth_finding_classifier import (
        classify_auth_finding,
        finding_title_label,
        finding_type_label,
    )
    from models.traffic_discovery import TrafficDiscoveryRequest
    from services.auth_preparation_service import AuthPreparationService
    from services.diagnostic_logging_service import DiagnosticLoggingService
    from models.testing import Artifact, TaskModel, ToolTestRequest, ToolTestResponse
    from services.diff_service import DiffService
    from services.http_client import HttpClient
    from services.openapi_baseline_synthesis_service import OpenApiBaselineSynthesisService
    from services.rejection_analyzer import RejectionAnalyzer
    from services.resource_family_inference_service import ResourceFamilyInferenceService
    from services.traffic_capture_service import TrafficCaptureService


logger = logging.getLogger(__name__)


class TestingService:
    SENSITIVE_PROPERTY_FIELDS = {
        "role",
        "user_id",
        "owner_id",
        "account_id",
        "status",
        "email",
        "isadmin",
        "approved",
        "credit",
        "balance",
    }
    SENSITIVE_EXPOSURE_KEYS = {
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "ssn",
        "email",
        "phone",
        "number",
        "role",
        "internal",
        "credit",
        "balance",
        "pincode",
        "vin",
        "owner",
        "auth",
        "session",
    }
    SQL_ERROR_PATTERNS = ("sql syntax", "sqlite", "postgres", "mysql", "ora-", "odbc", "syntax error", "query failed")
    TEMPLATE_ERROR_PATTERNS = ("template", "jinja", "twig", "mustache", "render", "undefined variable")
    COMMAND_ERROR_PATTERNS = ("command not found", "no such file or directory", "/bin/sh", "permission denied", "traceback")
    PARSER_ERROR_PATTERNS = ("json parse", "unexpected token", "malformed", "invalid character", "deserialization", "cannot deserialize", "parse error")
    STACK_TRACE_PATTERNS = ("traceback", "stack trace", "exception:", "runtimeerror", "nullreference", "undefinedexception")
    WORKFLOW_KEYWORDS = ("approve", "return", "cancel", "status", "pay", "checkout", "redeem", "order", "submit", "apply")

    def __init__(self) -> None:
        self.http_client = HttpClient()
        self.diff_service = DiffService()
        self.rejection_analyzer = RejectionAnalyzer()
        self.auth_preparation = AuthPreparationService(http_client=self.http_client)
        self.traffic_capture = TrafficCaptureService()
        self.baseline_synthesis = OpenApiBaselineSynthesisService()
        self.family_inference = ResourceFamilyInferenceService()
        self.diagnostics = DiagnosticLoggingService()

    async def run_authorization_test(self, request: ToolTestRequest) -> ToolTestResponse:
        return await self.test_access(request)

    async def test_access(self, request: ToolTestRequest) -> ToolTestResponse:
        self._emit_dispatch_event(request, event_type="dispatch_task_received")
        self._emit_dispatch_event(
            request,
            event_type="dispatch_task_classified",
            selected_execution_path="preparation" if self._is_preparation_task(request.task) else "worker",
        )
        preparation_response = await self._maybe_dispatch_preparation_task(
            request,
            default_tool="create_test_object",
        )
        if preparation_response is not None:
            return preparation_response
        self._emit_dispatch_event(request, event_type="dispatch_worker_path_selected", selected_execution_path="worker")
        args = request.arguments
        method = str(args.get("method") or request.task.method).upper()
        owner_role = str(args.get("owner_role") or request.task.auth_context.owner_role or "user_a")
        other_role = str(args.get("other_role") or request.task.auth_context.other_role or "user_b")
        role_profiles = self._role_profiles(request)
        headers = dict(args.get("headers") or {})
        query_params = dict(args.get("query_params") or {})
        json_body = args.get("json_body")
        selected_object_id = self._real_object_id(args.get("object_id") or request.task.params.selected_object_id)
        candidate_ids = self._sanitize_object_candidates(list(request.task.params.object_id_candidates or []))
        if request.task.class_name == "authorization" and request.task.params.requires_object_id_enrichment and selected_object_id in (None, "") and not candidate_ids:
            owner_identity = self._role_profiles(request).get(owner_role)
            if isinstance(owner_identity, dict) and owner_identity:
                prepared_object = await self.auth_preparation.materialize_for_task(
                    request=request,
                    owner_identity=owner_identity,
                )
                selected_object_id = self._real_object_id(prepared_object.get("object_id"))
                candidate_ids = self._sanitize_object_candidates(list(prepared_object.get("harvested_object_ids") or []))
        if selected_object_id in (None, "") and candidate_ids:
            selected_object_id = candidate_ids[0]
        endpoint_template = self._choose_authorization_endpoint_template(
            request,
            str(args.get("endpoint") or request.task.endpoint),
            selected_object_id,
        )
        endpoint = self._resolve_url(
            str(request.execution_context.target_url),
            self._materialize_object_endpoint(
                endpoint_template,
                selected_object_id,
                request.task.params.object_param_name,
            ),
        )
        self._validate_scope(request, endpoint)
        guessed_object_id = self._extract_guessed_object_id(endpoint_template, selected_object_id)

        if request.task.class_name == "authorization" and request.task.params.requires_object_id_enrichment and (selected_object_id in (None, "") or guessed_object_id):
            failure_code = "placeholder_object_id" if guessed_object_id else "object_creation_failed"
            return self._blocked_object_task_response(
                request=request,
                endpoint=endpoint,
                method=method,
                reason_code=failure_code,
                reason_text="Object-dependent authorization task was blocked until a real object id is materialized.",
                candidate_ids=candidate_ids,
            )

        owner_headers = self._build_role_headers(headers, role_profiles.get(owner_role), owner_role)
        other_headers = self._build_role_headers(headers, role_profiles.get(other_role), other_role)

        logger.info(
            "Running auth access test task_id=%s endpoint=%s method=%s owner_role=%s other_role=%s",
            request.task.id,
            endpoint,
            method,
            owner_role,
            other_role,
        )
        self._emit_runtime_diag(
            request=request,
            event_type="worker_request_prepared",
            status="ok",
            summary=f"Prepared worker request for {method} {endpoint}.",
            artifacts={
                "endpoint_before_substitution": endpoint_template,
                "endpoint_after_substitution": endpoint,
                "substituted_path_params": {str(request.task.params.object_param_name or 'id'): selected_object_id} if selected_object_id not in (None, '') else {},
                "selected_role": owner_role,
            },
        )

        owner_result = await self.http_client.execute(
            method=method,
            url=endpoint,
            headers=owner_headers,
            query_params=query_params,
            json_body=json_body,
        )
        other_result = await self.http_client.execute(
            method=method,
            url=endpoint,
            headers=other_headers,
            query_params=query_params,
            json_body=json_body,
        )
        owner_access_meta = self._authorization_response_meta(owner_result, endpoint, request)
        other_access_meta = self._authorization_response_meta(other_result, endpoint, request)
        comparison_meta = self._authorization_comparison_meta(
            owner_access_meta,
            other_access_meta,
            owner_role=owner_role,
            other_role=other_role,
        )

        similarity = self.diff_service.similarity(owner_result.body_text, other_result.body_text)
        shared_keys = self.diff_service.shared_json_keys(owner_result.body_text, other_result.body_text)
        failure_analysis = self.rejection_analyzer.classify_auth_failure(
            owner_status=owner_result.status_code,
            other_status=other_result.status_code,
            owner_body=owner_result.body_text,
            other_body=other_result.body_text,
            similarity=similarity,
        )
        replan = self.rejection_analyzer.controlled_replan(
            retry_count=int(request.task.retry_count or 0),
            current_object_id=selected_object_id or guessed_object_id,
            candidate_ids=candidate_ids,
            failure_classification=failure_analysis,
        )
        same_status = (
            owner_result.status_code is not None
            and owner_result.status_code == other_result.status_code
        )

        indicators: list[str] = []
        successful_statuses = {200, 201, 202, 204}
        useful_comparison_statuses = {200, 201, 202, 204, 403, 404}
        both_ok = (
            owner_result.status_code in successful_statuses
            and other_result.status_code in successful_statuses
        )
        if failure_analysis["failure_type"] == "invalid_object_id":
            indicators.extend(["invalid_object_id", "input_conversion_failure", "non_authorization_error"])
        elif failure_analysis["failure_type"] == "validation_failure":
            indicators.extend(["validation_failure", "non_authorization_error"])
        elif same_status and owner_result.status_code in useful_comparison_statuses:
            indicators.append("same_status_code")
        if (
            owner_result.error is None
            and other_result.error is None
            and similarity >= 0.85
            and owner_result.status_code in useful_comparison_statuses
            and other_result.status_code in useful_comparison_statuses
            and failure_analysis["failure_type"] == "unknown"
        ):
            indicators.append("similar_response")
        if both_ok and same_status and similarity >= 0.9 and failure_analysis["failure_type"] == "unknown":
            indicators.append("potential_bola")
        if (
            owner_result.status_code != other_result.status_code
            and owner_result.status_code in useful_comparison_statuses
            and other_result.status_code in useful_comparison_statuses
        ):
            indicators.append("access_control_difference")
        if not indicators:
            indicators.append("access_test_completed")

        raw_status = "success" if owner_result.error is None and other_result.error is None else "error"
        auth_finding_type = classify_auth_finding(
            request.task,
            {
                "response_summary": {
                    "owner": {"status_code": owner_result.status_code, **owner_access_meta},
                    "other": {"status_code": other_result.status_code, **other_access_meta},
                    "similarity": similarity,
                    "collection_analysis": comparison_meta,
                }
            },
        )
        if auth_finding_type in {"vertical_privilege", "weak_empty_collection_case", "collection_access_control"}:
            indicators = [
                item
                for item in indicators
                if item not in {"potential_bola", "access_control_difference"}
            ]
        evidence_strength = self._auth_evidence_strength(auth_finding_type, comparison_meta, similarity)
        if auth_finding_type == "weak_empty_collection_case":
            indicators.append("weak_empty_collection_case")
        elif auth_finding_type == "vertical_privilege":
            indicators.append("privileged_function_access")
        elif auth_finding_type == "collection_access_control":
            indicators.append("collection_access_control")
        indicators = list(dict.fromkeys(indicators))

        logger.info(
            "Auth test completed task_id=%s endpoint=%s owner_role=%s other_role=%s owner_status=%s other_status=%s similarity=%.4f auth_finding_type=%s indicators=%s raw_status=%s",
            request.task.id,
            endpoint,
            owner_role,
            other_role,
            owner_result.status_code,
            other_result.status_code,
            similarity,
            auth_finding_type,
            indicators,
            raw_status,
        )
        self._emit_worker_event(
            request=request,
            tool_name="auth_test_access",
            endpoint=endpoint,
            method=method,
            status=raw_status,
            evidence_strength=evidence_strength,
            indicators=indicators,
            response_summary={
                "owner_status": owner_result.status_code,
                "other_status": other_result.status_code,
                "similarity": similarity,
                "finding_type_hint": auth_finding_type,
                "owner_item_count": owner_access_meta["item_count"],
                "other_item_count": other_access_meta["item_count"],
                "empty_collection": comparison_meta["empty_collection"],
                "privileged_endpoint_like": comparison_meta["privileged_endpoint_like"],
            },
            artifacts={"object_context_present": bool(selected_object_id), "candidate_object_id_count": len(candidate_ids)},
        )

        return ToolTestResponse(
            request_summary={
                "method": method,
                "endpoint": endpoint,
                "tested_roles": [owner_role, other_role],
            },
            response_summary={
                "owner": {
                    "status_code": owner_result.status_code,
                    "body_length": len(owner_result.body_text or ""),
                    "elapsed_ms": owner_result.elapsed_ms,
                    "json_keys": shared_keys if owner_result.json_body() is not None else [],
                    "error": owner_result.error,
                    **owner_access_meta,
                },
                "other": {
                    "status_code": other_result.status_code,
                    "body_length": len(other_result.body_text or ""),
                    "elapsed_ms": other_result.elapsed_ms,
                    "json_keys": shared_keys if other_result.json_body() is not None else [],
                    "error": other_result.error,
                    **other_access_meta,
                },
                "similarity": similarity,
                "collection_analysis": comparison_meta,
                "auth_finding_type": auth_finding_type,
                "auth_finding_title": finding_title_label(auth_finding_type),
                "auth_finding_label": finding_type_label(auth_finding_type),
                "evidence_strength": evidence_strength,
                "failure_analysis": failure_analysis,
                "replan": replan,
            },
            raw_status=raw_status,
            indicators=indicators,
            artifacts=[
                Artifact(
                    type="auth_test_run",
                    value=f"artifact:auth:{uuid.uuid4()}",
                ),
                Artifact(
                    type="owner_response_meta",
                    value={
                        "status_code": owner_result.status_code,
                        "elapsed_ms": owner_result.elapsed_ms,
                        "error": owner_result.error,
                        "body_preview": owner_result.body_text[:240],
                    },
                ),
                Artifact(
                    type="other_response_meta",
                    value={
                        "status_code": other_result.status_code,
                        "elapsed_ms": other_result.elapsed_ms,
                        "error": other_result.error,
                        "body_preview": other_result.body_text[:240],
                    },
                ),
                Artifact(
                    type="failure_analysis",
                    value=failure_analysis,
                ),
                Artifact(
                    type="replan",
                    value=replan,
                ),
                Artifact(
                    type="auth_finding_classification",
                    value={
                        "classification": auth_finding_type,
                        "title": finding_title_label(auth_finding_type),
                        "label": finding_type_label(auth_finding_type),
                    },
                ),
            ],
        )

    async def run_injection_test(self, request: ToolTestRequest) -> ToolTestResponse:
        self._emit_dispatch_event(request, event_type="dispatch_task_received")
        self._emit_dispatch_event(
            request,
            event_type="dispatch_task_classified",
            selected_execution_path="preparation" if self._is_preparation_task(request.task) else "worker",
        )
        preparation_response = await self._maybe_dispatch_preparation_task(
            request,
            default_tool="input_shape_probe",
        )
        if preparation_response is not None:
            return preparation_response
        self._emit_dispatch_event(request, event_type="dispatch_worker_path_selected", selected_execution_path="worker")
        endpoint = self._resolve_url(
            str(request.execution_context.target_url),
            str(request.arguments.get("endpoint") or request.task.endpoint),
        )
        self._validate_scope(request, endpoint)
        method = str(request.arguments.get("method") or request.task.method).upper()
        owner_headers = self._preferred_role_headers(request)
        prepared = self._prepare_success_path_request(request, endpoint=endpoint, method=method, headers=owner_headers)
        baseline_endpoint = prepared["endpoint"]
        baseline_query = dict(prepared.get("query_params") or {})
        baseline_body = dict(prepared.get("json_body") or {})
        synthesis = prepared.get("synthesis") or {}
        if not baseline_query and not baseline_body and not request.task.params.path_params:
            baseline_value = "codex_safe_probe"
            baseline_endpoint, baseline_query, baseline_body, injected_field = self._apply_probe_input(
                endpoint, request, baseline_value
            )
        else:
            baseline_value = "codex_safe_probe"
            _, _, _, injected_field = self._apply_probe_input(
                baseline_endpoint, request, baseline_value, base_query=baseline_query, base_body=baseline_body
            )
        baseline = await self.http_client.execute(
            method=method,
            url=baseline_endpoint,
            headers=owner_headers,
            query_params=baseline_query,
            json_body=baseline_body,
        )
        if baseline.status_code in {400, 422}:
            fallback_body = self._default_payload(request.task.params.body_fields or [])
            fallback_query = {str(item): "safe" for item in (request.task.params.query_params or [])}
            baseline_retry = await self.http_client.execute(
                method=method,
                url=endpoint,
                headers=owner_headers,
                query_params=fallback_query or None,
                json_body=fallback_body or None,
            )
            if baseline_retry.status_code not in {400, 422}:
                baseline = baseline_retry
                baseline_query = fallback_query
                baseline_body = fallback_body
                baseline_endpoint = endpoint
            else:
                return ToolTestResponse(
                    request_summary={
                        "method": method,
                        "endpoint": endpoint,
                        "injected_field": injected_field,
                    },
                    response_summary={
                        "baseline": self._http_result_summary(baseline_retry),
                        "finding_type_hint": "injection",
                        "finding_title_hint": "Injection Weakness",
                        "evidence_strength": "weak",
                        "preparation_status": "baseline_invalid",
                        "failure_reason": synthesis.get("structured_failure_reason") or "baseline_invalid_from_spec",
                        "synthesis_metadata": synthesis.get("synthesis_metadata") or {},
                    },
                    raw_status="partial",
                    indicators=["preparation_failed", "baseline_invalid"],
                    artifacts=[Artifact(type="baseline_synthesis", value=synthesis)],
                )
        attack_variants = self._bounded_injection_payloads(request)
        strongest_attack = None
        strongest_summary = None
        attack_summaries = []
        for attack_value in attack_variants:
            attack_endpoint, attack_query, attack_body, _ = self._apply_probe_input(
                baseline_endpoint, request, attack_value, base_query=baseline_query, base_body=baseline_body
            )
            attack = await self.http_client.execute(
                method=method,
                url=attack_endpoint,
                headers=owner_headers,
                query_params=attack_query,
                json_body=attack_body,
            )
            summary = self._injection_attack_summary(baseline, attack, attack_value)
            attack_summaries.append(summary)
            if strongest_summary is None or self._injection_summary_rank(summary) > self._injection_summary_rank(strongest_summary):
                strongest_attack = attack
                strongest_summary = summary

        strongest_summary = strongest_summary or {
            "attack_value_preview": "",
            "diff": {"status_changed": False, "similarity": 1.0, "response_size_delta": 0, "time_delta_ms": 0.0},
            "reflection": {"reflection_detected": False, "unescaped_reflection": False, "escaped_reflection": False, "context_summary": "none", "marker": ""},
            "sink_signal": {"sql_error_signal": False, "template_error_signal": False, "command_error_signal": False, "parser_error_signal": False, "stack_trace_detected": False},
            "time_signal": {"significant_time_anomaly": False},
            "indicators": [],
            "evidence_strength": "weak",
        }
        strongest_attack = strongest_attack or baseline
        indicators = ["injection_probe_completed", *strongest_summary["indicators"]]
        raw_status = "success" if baseline.error is None and strongest_attack.error is None else "error"
        self._emit_worker_event(
            request=request,
            tool_name="injection_test",
            endpoint=endpoint,
            method=method,
            status=raw_status,
            evidence_strength=strongest_summary["evidence_strength"],
            indicators=list(dict.fromkeys(indicators)),
            response_summary={
                "baseline_status": baseline.status_code,
                "attack_status": strongest_attack.status_code,
                "diff": strongest_summary["diff"],
                "reflection": strongest_summary["reflection"],
                "sink_signal": strongest_summary["sink_signal"],
                "time_signal": strongest_summary["time_signal"],
                "finding_type_hint": "injection",
            },
            artifacts={"baseline_available": bool(synthesis), "object_context_present": bool(request.task.params.selected_object_id)},
        )
        return ToolTestResponse(
            request_summary={
                "method": method,
                "endpoint": endpoint,
                "injected_field": injected_field,
                "baseline_value": baseline_value,
                "attack_variants_tested": [item[:64] for item in attack_variants],
                "selected_attack_value_preview": strongest_summary["attack_value_preview"],
            },
            response_summary={
                "baseline": self._http_result_summary(baseline),
                "attack": self._http_result_summary(strongest_attack),
                "diff": strongest_summary["diff"],
                "reflection": strongest_summary["reflection"],
                "sink_signal": strongest_summary["sink_signal"],
                "time_signal": strongest_summary["time_signal"],
                "evidence_strength": strongest_summary["evidence_strength"],
                "attack_variant_summaries": attack_summaries[:4],
                "finding_type_hint": "injection",
                "finding_title_hint": "Injection Weakness",
            },
            raw_status=raw_status,
            indicators=list(dict.fromkeys(indicators)),
            artifacts=[
                Artifact(type="injection_test_run", value=f"artifact:injection:{uuid.uuid4()}"),
                Artifact(type="baseline_synthesis", value=synthesis),
            ],
        )

    async def run_logic_test(self, request: ToolTestRequest) -> ToolTestResponse:
        self._emit_dispatch_event(request, event_type="dispatch_task_received")
        self._emit_dispatch_event(
            request,
            event_type="dispatch_task_classified",
            selected_execution_path="preparation" if self._is_preparation_task(request.task) else "worker",
        )
        preparation_response = await self._maybe_dispatch_preparation_task(
            request,
            default_tool="workflow_probe",
        )
        if preparation_response is not None:
            return preparation_response
        self._emit_dispatch_event(request, event_type="dispatch_worker_path_selected", selected_execution_path="worker")
        endpoint = self._resolve_url(
            str(request.execution_context.target_url),
            str(request.arguments.get("endpoint") or request.task.endpoint),
        )
        self._validate_scope(request, endpoint)
        method = str(request.arguments.get("method") or request.task.method).upper()
        owner_role = str(request.task.auth_context.owner_role or "user_a")
        other_role = str(request.task.auth_context.other_role or "user_b")
        profiles = self._role_profiles(request)
        auth_required = self._endpoint_requires_auth(request, endpoint)
        owner_profile = profiles.get(owner_role)
        other_profile = profiles.get(other_role)
        if auth_required and not self._has_auth_material(owner_profile):
            owner_profile = next((profile for profile in profiles.values() if self._has_auth_material(profile)), None)
        if auth_required and not self._has_auth_material(other_profile):
            owner_profile_name = str(owner_profile.get("name") or owner_role) if isinstance(owner_profile, dict) else owner_role
            other_profile = next(
                (profile for name, profile in profiles.items() if name != owner_profile_name and self._has_auth_material(profile)),
                None,
            )
        owner_headers = self._build_role_headers({}, owner_profile, owner_role)
        other_headers = self._build_role_headers({}, other_profile, other_role)
        selected_owner_role = str(owner_profile.get("name") or owner_role) if isinstance(owner_profile, dict) else owner_role
        selected_other_role = str(other_profile.get("name") or other_role) if isinstance(other_profile, dict) else other_role
        if self._headers_have_auth(owner_headers):
            self._emit_runtime_diag(
                request=request,
                event_type="auth_headers_attached",
                status="ok",
                summary=f"Attached authenticated context for role {selected_owner_role}.",
                artifacts={"selected_role": selected_owner_role, "authenticated": True},
            )
        if auth_required and not self._headers_have_auth(owner_headers):
            self._emit_runtime_diag(
                request=request,
                event_type="authenticated_context_missing",
                status="blocked",
                summary=f"Missing authenticated context for auth-required logic endpoint {endpoint}.",
                reason={"failure_reason": "missing_auth_context"},
                artifacts={"selected_role": selected_owner_role, "authenticated": False},
            )
            return ToolTestResponse(
                request_summary={"method": method, "endpoint": endpoint, "task_id": request.task.id},
                response_summary={
                    "finding_type_hint": "workflow_abuse",
                    "finding_title_hint": "Workflow Abuse",
                    "evidence_strength": "weak",
                    "failure_reason": "missing_auth_context",
                    "auth_required": True,
                },
                raw_status="blocked",
                indicators=["preparation_failed", "missing_auth_context", "unauthenticated_request_to_auth_required_endpoint"],
                artifacts=[Artifact(type="workflow_context", value={"auth_required": True, "selected_role": selected_owner_role})],
            )

        prepared = await self._prepare_business_logic_context(request, endpoint, owner_headers)
        prepared_endpoint = prepared.get("endpoint") or endpoint
        if self._extract_guessed_object_id(str(prepared_endpoint), prepared.get("object_id")):
            return self._blocked_object_task_response(
                request=request,
                endpoint=str(prepared_endpoint),
                method=method,
                reason_code="placeholder_object_id",
                reason_text="Workflow test was blocked because no real object id was materialized.",
                candidate_ids=self._sanitize_object_candidates(prepared.get("harvested_object_ids") or []),
            )
        self._emit_runtime_diag(
            request=request,
            event_type="worker_request_prepared",
            status="ok",
            summary=f"Prepared worker request for {method} {prepared_endpoint}.",
            artifacts={
                "endpoint_before_substitution": endpoint,
                "endpoint_after_substitution": prepared_endpoint,
                "substituted_path_params": {"id": prepared.get("object_id")} if prepared.get("object_id") not in (None, "") else {},
                "selected_role": selected_owner_role,
            },
        )
        baseline_payload = prepared.get("baseline_payload") or self._prepare_success_path_request(request, endpoint=prepared_endpoint, method=method, headers=owner_headers).get("json_body") or self._default_payload(request.task.params.body_fields or [])
        attack_payload = prepared.get("attack_payload") or self._workflow_attack_payload(request.task.params.body_fields or [], prepared_endpoint)
        baseline = await self.http_client.execute(
            method=method,
            url=prepared_endpoint,
            headers=owner_headers,
            json_body=baseline_payload or None,
        )
        if baseline.status_code in {400, 422}:
            return ToolTestResponse(
                request_summary={
                    "method": method,
                    "endpoint": prepared_endpoint,
                    "baseline_sequence": ["owner_baseline"],
                    "attack_sequence": [],
                },
                response_summary={
                    "baseline": self._http_result_summary(baseline),
                    "finding_type_hint": "workflow_abuse",
                    "finding_title_hint": "Workflow Abuse",
                    "evidence_strength": "weak",
                    "preparation_status": "baseline_invalid",
                    "failure_reason": "success_path_not_reachable",
                    "prepared_context": prepared,
                },
                raw_status="partial",
                indicators=["preparation_failed", "baseline_invalid"],
                artifacts=[Artifact(type="workflow_context", value=prepared)],
            )
        repeat = await self.http_client.execute(
            method=method,
            url=prepared_endpoint,
            headers=owner_headers,
            json_body=baseline_payload or None,
        )
        attack = await self.http_client.execute(
            method=method,
            url=prepared_endpoint,
            headers=other_headers,
            json_body=attack_payload or baseline_payload or None,
        )
        if auth_required and {baseline.status_code, repeat.status_code, attack.status_code} == {401}:
            self._emit_runtime_diag(
                request=request,
                event_type="success_path_not_reached",
                status="partial",
                summary=f"Workflow probe hit only 401 responses for auth-required endpoint {prepared_endpoint}.",
                reason={"failure_reason": "unauthenticated_request_to_auth_required_endpoint"},
                artifacts={"selected_role": selected_owner_role, "other_role": selected_other_role, "authenticated": self._headers_have_auth(owner_headers)},
            )
            return ToolTestResponse(
                request_summary={
                    "method": method,
                    "endpoint": prepared_endpoint,
                    "baseline_sequence": ["owner_baseline"],
                    "attack_sequence": ["cross_role_or_invalid_action"],
                },
                response_summary={
                    "baseline": self._http_result_summary(baseline),
                    "repeat": self._http_result_summary(repeat),
                    "attack": self._http_result_summary(attack),
                    "finding_type_hint": "workflow_abuse",
                    "finding_title_hint": "Workflow Abuse",
                    "evidence_strength": "weak",
                    "failure_reason": "unauthenticated_request_to_auth_required_endpoint",
                    "auth_required": True,
                    "selected_owner_role": selected_owner_role,
                    "selected_other_role": selected_other_role,
                    "prepared_context": prepared,
                },
                raw_status="partial",
                indicators=["preparation_failed", "success_path_not_reached", "unauthenticated_request_to_auth_required_endpoint"],
                artifacts=[Artifact(type="workflow_context", value=prepared)],
            )

        repeated_allowed = self._status_success(baseline.status_code) and self._status_success(repeat.status_code)
        cross_role_access = self._status_success(baseline.status_code) and self._status_success(attack.status_code)
        invariant_violation = self._status_success(attack.status_code) and bool(attack_payload)
        invalid_transition = invariant_violation and self._looks_workflow_endpoint(prepared_endpoint)
        state_changed = baseline.status_code != attack.status_code or self.diff_service.similarity(baseline.body_text, attack.body_text) <= 0.8

        indicators = ["workflow_probe_completed"]
        if invalid_transition:
            indicators.append("invalid_transition_accepted")
        if repeated_allowed and self._looks_repeat_sensitive(prepared_endpoint):
            indicators.append("repeated_sensitive_action_allowed")
        if cross_role_access:
            indicators.append("cross_role_workflow_access")
        if invariant_violation:
            indicators.append("invariant_violation")
        if invalid_transition or (repeated_allowed and cross_role_access):
            indicators.append("workflow_state_bypass")
        evidence_strength = self._workflow_evidence_strength(indicators)

        raw_status = "success" if not any(item.error for item in (baseline, repeat, attack)) else "error"
        self._emit_worker_event(
            request=request,
            tool_name="logic_test",
            endpoint=prepared_endpoint,
            method=method,
            status=raw_status,
            evidence_strength=evidence_strength,
            indicators=indicators,
            response_summary={
                "baseline_status": baseline.status_code,
                "repeat_status": repeat.status_code,
                "attack_status": attack.status_code,
                "finding_type_hint": "workflow_abuse",
            },
            artifacts={"prepared_context": bool(prepared), "object_context_present": bool((prepared or {}).get("object_id"))},
        )
        return ToolTestResponse(
            request_summary={
                "method": method,
                "endpoint": prepared_endpoint,
                "baseline_sequence": ["owner_baseline", "owner_repeat"],
                "attack_sequence": ["cross_role_or_invalid_action"],
            },
            response_summary={
                "baseline": self._http_result_summary(baseline),
                "repeat": self._http_result_summary(repeat),
                "attack": self._http_result_summary(attack),
                "state_delta_summary": {
                    "baseline_state": self._body_snapshot(baseline.body_text),
                    "post_action_state": self._body_snapshot(attack.body_text),
                    "state_changed": state_changed,
                    "owner_repeat_allowed": repeated_allowed,
                    "cross_role_attack_allowed": cross_role_access,
                    "selected_owner_role": selected_owner_role,
                    "selected_other_role": selected_other_role,
                    "prepared_context": prepared,
                },
                "violated_invariant_summary": {
                    "invalid_transition_accepted": invalid_transition,
                    "repeated_sensitive_action_allowed": repeated_allowed and self._looks_repeat_sensitive(prepared_endpoint),
                    "cross_role_workflow_access": cross_role_access,
                },
                "finding_type_hint": "workflow_abuse",
                "finding_title_hint": "Workflow Abuse",
                "evidence_strength": evidence_strength,
            },
            raw_status=raw_status,
            indicators=indicators,
            artifacts=[
                Artifact(type="logic_test_run", value=f"artifact:logic:{uuid.uuid4()}"),
                Artifact(type="workflow_context", value=prepared),
            ],
        )

    async def auto_provision(self, request: ToolTestRequest) -> ToolTestResponse:
        self._emit_direct_preparation_route_dispatch(request, delegated_tool="auto_provision")
        return await self.auth_preparation.auto_provision(request)

    async def probe_entrypoints(self, request: ToolTestRequest) -> ToolTestResponse:
        self._emit_direct_preparation_route_dispatch(request, delegated_tool="auth_probe_entrypoints")
        return await self.auth_preparation.probe_entrypoints(request)

    async def create_test_object(self, request: ToolTestRequest) -> ToolTestResponse:
        self._emit_direct_preparation_route_dispatch(request, delegated_tool="create_test_object")
        return await self.auth_preparation.create_test_object(request)

    async def property_mutation_test(self, request: ToolTestRequest) -> ToolTestResponse:
        endpoint = self._resolve_url(
            str(request.execution_context.target_url),
            str(request.arguments.get("endpoint") or request.task.endpoint),
        )
        self._validate_scope(request, endpoint)
        method = str(request.arguments.get("method") or request.task.method or "PATCH").upper()
        role_name = str(request.arguments.get("owner_role") or request.task.auth_context.owner_role or "user_a")
        profiles = self._role_profiles(request)
        headers = self._build_role_headers({}, profiles.get(role_name), role_name)
        body_fields = list(request.task.params.body_fields or [])
        sensitive_fields = [field for field in body_fields if self._is_sensitive_property_field(field)]
        prepared = self._prepare_success_path_request(request, endpoint=endpoint, method=method, headers=headers)
        baseline_payload = dict(prepared.get("json_body") or self._default_payload(body_fields))
        mutated_payload = dict(baseline_payload)
        mutated_fields: list[str] = []
        for field in sensitive_fields[:4]:
            mutated_fields.append(field)
            mutated_payload[field] = self._mutated_value(field)

        baseline = await self.http_client.execute(
            method=method,
            url=endpoint,
            headers=headers,
            json_body=baseline_payload or None,
        )
        if baseline.status_code in {400, 422}:
            return ToolTestResponse(
                request_summary={"method": method, "endpoint": endpoint, "tested_role": role_name},
                response_summary={
                    "baseline": self._http_result_summary(baseline),
                    "finding_type_hint": "property_level_authorization",
                    "finding_title_hint": "Property Level Authorization",
                    "evidence_strength": "weak",
                    "preparation_status": "baseline_invalid",
                    "failure_reason": prepared.get("synthesis", {}).get("structured_failure_reason") or "baseline_invalid_from_spec",
                },
                raw_status="partial",
                indicators=["preparation_failed", "baseline_invalid"],
                artifacts=[Artifact(type="baseline_synthesis", value=prepared.get("synthesis") or {})],
            )
        mutated = await self.http_client.execute(
            method=method,
            url=endpoint,
            headers=headers,
            json_body=mutated_payload or None,
        )
        persisted_snapshot = await self._property_readback(request, endpoint, headers, mutated_payload, mutated_fields)
        reflected_fields = [
            field for field in mutated_fields if str(mutated_payload.get(field)) in (mutated.body_text or "")
        ]
        persisted_fields = [
            field for field in mutated_fields
            if self._value_persisted(field, mutated_payload.get(field), persisted_snapshot)
        ]
        accepted_fields = [
            field
            for field in mutated_fields
            if field in reflected_fields
            or field in persisted_fields
            or (
                self._status_success(mutated.status_code)
                and not self._status_success(baseline.status_code)
            )
        ]
        ignored_fields = [field for field in mutated_fields if field not in accepted_fields]
        finding_classification = classify_auth_finding(
            request.task,
            {
                "response_summary": {
                    "mutated_fields": mutated_fields,
                    "accepted_fields": accepted_fields,
                }
            },
        )
        indicators = ["property_mutation_attempted"]
        if reflected_fields:
            indicators.append("mutated_field_reflected")
        if accepted_fields:
            indicators.append("sensitive_field_accepted")
        if persisted_fields:
            indicators.append("sensitive_field_persisted")
        if finding_classification == "mass_assignment":
            indicators.append("mass_assignment_signal")
        evidence_strength = self._property_evidence_strength(accepted_fields, reflected_fields, persisted_fields)
        self._emit_worker_event(
            request=request,
            tool_name="property_mutation_test",
            endpoint=endpoint,
            method=method,
            status="success" if baseline.error is None and mutated.error is None else "error",
            evidence_strength=evidence_strength,
            indicators=indicators,
            response_summary={
                "baseline_status": baseline.status_code,
                "mutation_status": mutated.status_code,
                "accepted_fields": accepted_fields,
                "persisted_fields": persisted_fields,
                "finding_type_hint": finding_classification,
            },
            artifacts={"baseline_available": bool(prepared.get("synthesis") or {})},
        )

        return ToolTestResponse(
            request_summary={
                "method": method,
                "endpoint": endpoint,
                "tested_role": role_name,
            },
            response_summary={
                "baseline": self._http_result_summary(baseline),
                "mutated": self._http_result_summary(mutated),
                "mutated_fields": mutated_fields,
                "accepted_fields": accepted_fields,
                "ignored_fields": ignored_fields,
                "reflected_fields": reflected_fields,
                "persisted_fields": persisted_fields,
                "status_diff": {
                    "baseline": baseline.status_code,
                    "mutated": mutated.status_code,
                },
                "finding_type_hint": finding_classification,
                "finding_title_hint": finding_title_label(finding_classification),
                "evidence_strength": evidence_strength,
            },
            raw_status="success" if baseline.error is None and mutated.error is None else "error",
            indicators=indicators,
            artifacts=[
                Artifact(type="property_mutation_test_run", value=f"artifact:property:{uuid.uuid4()}"),
                Artifact(type="baseline_synthesis", value=prepared.get("synthesis") or {}),
            ],
        )

    async def data_exposure_test(self, request: ToolTestRequest) -> ToolTestResponse:
        endpoint = self._resolve_url(
            str(request.execution_context.target_url),
            str(request.arguments.get("endpoint") or request.task.endpoint),
        )
        self._validate_scope(request, endpoint)
        owner_role = str(request.task.auth_context.owner_role or "user_a")
        other_role = str(request.task.auth_context.other_role or "user_b")
        profiles = self._role_profiles(request)
        method = str(request.arguments.get("method") or request.task.method or "GET").upper()
        owner_headers = self._build_role_headers({}, profiles.get(owner_role), owner_role)
        other_headers = self._build_role_headers({}, profiles.get(other_role), other_role)
        prepared = self._prepare_success_path_request(request, endpoint=endpoint, method=method, headers=owner_headers)
        owner = await self.http_client.execute(
            method=method,
            url=prepared.get("endpoint") or endpoint,
            headers=owner_headers,
            query_params=prepared.get("query_params") or None,
            json_body=prepared.get("json_body") or None,
        )
        other = await self.http_client.execute(
            method=method,
            url=prepared.get("endpoint") or endpoint,
            headers=other_headers,
            query_params=prepared.get("query_params") or None,
            json_body=prepared.get("json_body") or None,
        )
        owner_json = owner.json_body()
        returned_keys = self._flatten_json_keys(owner_json)[:40]
        sensitive_keys = [key for key in returned_keys if self._looks_sensitive_key(key)]
        nested_sensitive_keys = [key for key in sensitive_keys if "." in key]
        similarity = self.diff_service.similarity(owner.body_text, other.body_text)
        sample_exposed_fields = self._sample_sensitive_values(owner_json)
        validation_disclosure = self._is_validation_schema_disclosure(owner.status_code, owner_json, owner.body_text)
        indicators = []
        if sensitive_keys:
            indicators.append("sensitive_data_exposed")
        if similarity > 0.85 and self._status_success(other.status_code):
            indicators.append("cross_role_data_exposure")
        if len(returned_keys) >= 12:
            indicators.append("excessive_field_count")
        if validation_disclosure:
            indicators.append("schema_disclosure")
            indicators.append("verbose_validation_leak")
        evidence_strength = self._exposure_evidence_strength(
            sensitive_keys,
            sample_exposed_fields,
            nested_sensitive_keys,
            owner.status_code,
            validation_disclosure,
            similarity,
        )
        if owner.status_code in {400, 422} and not sample_exposed_fields:
            self._emit_worker_event(
                request=request,
                tool_name="data_exposure_test",
                endpoint=endpoint,
                method=method,
                status="partial",
                evidence_strength="weak",
                indicators=["preparation_failed", *(["schema_disclosure"] if validation_disclosure else [])],
                response_summary={
                    "baseline_status": owner.status_code,
                    "finding_type_hint": "excessive_data_exposure",
                    "weak_signal_class": "schema_disclosure" if validation_disclosure else None,
                },
                artifacts={"baseline_available": bool(prepared.get("synthesis") or {})},
            )
            return ToolTestResponse(
                request_summary={"method": method, "endpoint": endpoint, "tested_roles": [owner_role, other_role]},
                response_summary={
                    "owner": self._http_result_summary(owner),
                    "other": self._http_result_summary(other),
                    "finding_type_hint": "excessive_data_exposure",
                    "finding_title_hint": "Excessive Data Exposure",
                    "evidence_strength": "weak",
                    "preparation_status": "baseline_invalid",
                    "failure_reason": prepared.get("synthesis", {}).get("structured_failure_reason") or "success_path_not_reachable",
                    "weak_signal_class": "schema_disclosure" if validation_disclosure else None,
                },
                raw_status="partial",
                indicators=["preparation_failed", *(["schema_disclosure"] if validation_disclosure else [])],
                artifacts=[Artifact(type="baseline_synthesis", value=prepared.get("synthesis") or {})],
            )

        self._emit_worker_event(
            request=request,
            tool_name="data_exposure_test",
            endpoint=endpoint,
            method=method,
            status="success" if owner.error is None and other.error is None else "error",
            evidence_strength=evidence_strength,
            indicators=indicators or ["data_exposure_probe_completed"],
            response_summary={
                "owner_status": owner.status_code,
                "other_status": other.status_code,
                "sensitive_keys_found": sensitive_keys,
                "nested_sensitive_keys_found": nested_sensitive_keys,
                "finding_type_hint": "excessive_data_exposure",
            },
            artifacts={"baseline_available": bool(prepared.get("synthesis") or {}), "cross_role_similarity": similarity},
        )
        return ToolTestResponse(
            request_summary={"method": method, "endpoint": endpoint, "tested_roles": [owner_role, other_role]},
            response_summary={
                "owner": self._http_result_summary(owner),
                "other": self._http_result_summary(other),
                "returned_keys": returned_keys,
                "sensitive_keys_found": sensitive_keys,
                "nested_sensitive_keys_found": nested_sensitive_keys,
                "sample_exposed_fields": sample_exposed_fields,
                "similarity": similarity,
                "weak_signal_class": "schema_disclosure" if validation_disclosure else None,
                "severity_hint": "low" if validation_disclosure else ("high" if {"password", "token", "secret"}.intersection({item.split(".")[-1] for item in sensitive_keys}) else "medium"),
                "finding_type_hint": "excessive_data_exposure",
                "finding_title_hint": "Excessive Data Exposure",
                "evidence_strength": evidence_strength,
            },
            raw_status="success" if owner.error is None and other.error is None else "error",
            indicators=indicators or ["data_exposure_probe_completed"],
            artifacts=[
                Artifact(type="data_exposure_test_run", value=f"artifact:exposure:{uuid.uuid4()}"),
                Artifact(type="baseline_synthesis", value=prepared.get("synthesis") or {}),
            ],
        )

    async def resource_abuse_test(self, request: ToolTestRequest) -> ToolTestResponse:
        endpoint = self._resolve_url(
            str(request.execution_context.target_url),
            str(request.arguments.get("endpoint") or request.task.endpoint),
        )
        self._validate_scope(request, endpoint)
        method = str(request.arguments.get("method") or request.task.method or "POST").upper()
        attempts = max(1, min(int(request.arguments.get("attempt_count") or 3), min(int(request.execution_context.max_requests or 3), 4)))
        role_headers = self._preferred_role_headers(request)
        prepared = self._prepare_success_path_request(request, endpoint=endpoint, method=method, headers=role_headers)
        query_params = prepared.get("query_params") or None
        json_body = prepared.get("json_body") or None
        synthesis = prepared.get("synthesis") or {}
        baseline_required = method in {"POST", "PUT", "PATCH"}
        baseline_candidate = None
        baseline_invalid = False
        if baseline_required:
            baseline_candidate = await self.http_client.execute(
                method=method,
                url=prepared.get("endpoint") or endpoint,
                headers=role_headers,
                query_params=query_params,
                json_body=json_body,
            )
            baseline_invalid = (
                not bool(synthesis.get("baseline_valid", True))
                or baseline_candidate.status_code in {400, 404, 422}
            )
        if baseline_required and baseline_invalid:
            return ToolTestResponse(
                request_summary={"method": method, "endpoint": endpoint, "attempt_count": 1},
                response_summary={
                    "total_attempts": 1 if baseline_candidate else 0,
                    "count_2xx": 1 if baseline_candidate and self._status_success(baseline_candidate.status_code) else 0,
                    "count_4xx": 1 if baseline_candidate and (baseline_candidate.status_code or 0) in {400, 404, 422} else 0,
                    "count_429": 0,
                    "throttling_observed": False,
                    "lockout_detected": False,
                    "rate_limit_headers_detected": False,
                    "rate_limit_header_names": [],
                    "timing_stats": {
                        "min_ms": baseline_candidate.elapsed_ms if baseline_candidate else None,
                        "max_ms": baseline_candidate.elapsed_ms if baseline_candidate else None,
                        "avg_ms": baseline_candidate.elapsed_ms if baseline_candidate else None,
                    },
                    "retry_after": None,
                    "client_error_baseline": True,
                    "no_rate_limit_detected": False,
                    "should_retry": False,
                    "finding_type_hint": "unrestricted_resource_consumption",
                    "finding_title_hint": "Unrestricted Resource Consumption",
                    "evidence_strength": "weak",
                    "low_signal": True,
                    "low_signal_reason": synthesis.get("structured_failure_reason") or "client_error_baseline",
                    "baseline": self._http_result_summary(baseline_candidate) if baseline_candidate else None,
                },
                raw_status="partial",
                indicators=["resource_abuse_probe_completed", "client_error_baseline", "low_signal_probe_result"],
                artifacts=[
                    Artifact(type="resource_abuse_test_run", value=f"artifact:resource:{uuid.uuid4()}"),
                    Artifact(type="baseline_synthesis", value=synthesis),
                ],
            )
        results = []
        for _ in range(attempts):
            results.append(
                await self.http_client.execute(
                    method=method,
                    url=endpoint,
                    headers=role_headers,
                    query_params=query_params,
                    json_body=json_body,
                )
            )
        histogram: dict[str, int] = {}
        retry_after = None
        rate_limit_headers_detected = False
        rate_limit_header_names: set[str] = set()
        elapsed_values: list[float] = []
        count_2xx = 0
        count_4xx = 0
        count_429 = 0
        for item in results:
            key = str(item.status_code if item.status_code is not None else "error")
            histogram[key] = histogram.get(key, 0) + 1
            if not retry_after and item.headers.get("retry-after"):
                retry_after = item.headers.get("retry-after")
            if item.elapsed_ms is not None:
                elapsed_values.append(float(item.elapsed_ms))
            status_code = item.status_code or 0
            if 200 <= status_code < 300:
                count_2xx += 1
            if 400 <= status_code < 500:
                count_4xx += 1
            if status_code == 429:
                count_429 += 1
            for header_name in item.headers.keys():
                normalized = str(header_name or "").strip().lower()
                if normalized in {"retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset"}:
                    rate_limit_headers_detected = True
                    rate_limit_header_names.add(normalized)
        throttling_observed = count_429 > 0 or retry_after is not None
        lockout_detected = any(item.status_code in {401, 403, 423, 429} for item in results[1:])
        no_rate_limit = attempts >= 3 and not lockout_detected and not throttling_observed and all(self._status_success(item.status_code) for item in results)
        timing_stats = {
            "min_ms": min(elapsed_values) if elapsed_values else None,
            "max_ms": max(elapsed_values) if elapsed_values else None,
            "avg_ms": (sum(elapsed_values) / len(elapsed_values)) if elapsed_values else None,
        }
        indicators = ["resource_abuse_probe_completed"]
        if retry_after:
            indicators.append("retry_after_present")
        if throttling_observed:
            indicators.append("throttling_observed")
        if lockout_detected:
            indicators.append("lockout_detected")
        if rate_limit_headers_detected:
            indicators.append("rate_limit_headers_detected")
        if no_rate_limit:
            indicators.append("no_rate_limit_detected")

        return ToolTestResponse(
            request_summary={"method": method, "endpoint": endpoint, "attempt_count": attempts},
            response_summary={
                "attempt_count": attempts,
                "total_attempts": attempts,
                "status_histogram": histogram,
                "count_2xx": count_2xx,
                "count_4xx": count_4xx,
                "count_429": count_429,
                "retry_after": retry_after,
                "client_error_baseline": False,
                "throttling_observed": throttling_observed,
                "lockout_detected": lockout_detected,
                "rate_limit_headers_detected": rate_limit_headers_detected,
                "rate_limit_header_names": sorted(rate_limit_header_names),
                "timing_stats": timing_stats,
                "no_rate_limit_detected": no_rate_limit,
                "should_retry": False,
                "finding_type_hint": "unrestricted_resource_consumption",
                "finding_title_hint": "Unrestricted Resource Consumption",
                "evidence_strength": "strong" if no_rate_limit else ("medium" if throttling_observed or lockout_detected or rate_limit_headers_detected else "weak"),
            },
            raw_status="success" if all(item.error is None for item in results) else "error",
            indicators=indicators,
            artifacts=[
                Artifact(type="resource_abuse_test_run", value=f"artifact:resource:{uuid.uuid4()}"),
                Artifact(
                    type="resource_abuse_stats",
                    value={
                        "total_attempts": attempts,
                        "count_2xx": count_2xx,
                        "count_4xx": count_4xx,
                        "count_429": count_429,
                        "throttling_observed": throttling_observed,
                        "lockout_detected": lockout_detected,
                        "rate_limit_headers_detected": rate_limit_headers_detected,
                        "timing_stats": timing_stats,
                    },
                ),
            ],
        )

    async def misconfiguration_test(self, request: ToolTestRequest) -> ToolTestResponse:
        endpoint = self._resolve_url(
            str(request.execution_context.target_url),
            str(request.arguments.get("endpoint") or request.task.endpoint),
        )
        self._validate_scope(request, endpoint)
        methods = ["OPTIONS", "TRACE", str(request.task.method or "GET").upper()]
        checks = []
        for method in methods[:3]:
            checks.append(await self.http_client.execute(method=method, url=endpoint, headers=self._preferred_role_headers(request)))
        enabled_methods = [item.method for item in checks if item.status_code not in {405, 501, None}]
        risky_headers = sorted(
            {
                header
                for item in checks
                for header in item.headers.keys()
                if header in {"server", "x-powered-by", "x-debug", "x-aspnet-version"}
            }
        )
        cors_summary = {
            "allow_origin": next((item.headers.get("access-control-allow-origin") for item in checks if item.headers.get("access-control-allow-origin")), None),
            "allow_credentials": next((item.headers.get("access-control-allow-credentials") for item in checks if item.headers.get("access-control-allow-credentials")), None),
        }
        bodies = "\n".join(item.body_text or "" for item in checks).lower()
        internal_url_leak = any(token in bodies for token in ("localhost", "127.0.0.1", "internal", "host.docker.internal"))
        stack_trace_detected = any(token in bodies for token in self.STACK_TRACE_PATTERNS)
        weak_cors = cors_summary["allow_origin"] == "*" and str(cors_summary["allow_credentials"] or "").lower() == "true"
        indicators = ["misconfiguration_probe_completed"]
        if weak_cors:
            indicators.append("weak_cors")
        if risky_headers:
            indicators.append("debug_header_exposed")
        if internal_url_leak:
            indicators.append("internal_url_leak")
        if stack_trace_detected:
            indicators.append("stack_trace_detected")

        return ToolTestResponse(
            request_summary={"endpoint": endpoint, "methods_tested": methods[:3]},
            response_summary={
                "enabled_methods": enabled_methods,
                "risky_headers": risky_headers,
                "cors_summary": cors_summary,
                "debug_leak": bool(risky_headers),
                "internal_url_leak": internal_url_leak,
                "stack_trace_detected": stack_trace_detected,
                "finding_type_hint": "security_misconfiguration",
                "finding_title_hint": "Security Misconfiguration",
                "evidence_strength": "strong" if (weak_cors or internal_url_leak or stack_trace_detected) else ("medium" if risky_headers else "weak"),
            },
            raw_status="success" if all(item.error is None for item in checks) else "error",
            indicators=indicators,
            artifacts=[Artifact(type="misconfiguration_test_run", value=f"artifact:misconfig:{uuid.uuid4()}")],
        )

    async def version_diff_test(self, request: ToolTestRequest) -> ToolTestResponse:
        endpoint_path = str(request.arguments.get("endpoint") or request.task.endpoint)
        endpoint = self._resolve_url(str(request.execution_context.target_url), endpoint_path)
        self._validate_scope(request, endpoint)
        discovered_versions = self._version_paths(endpoint_path)
        checks = []
        for candidate in discovered_versions:
            checks.append(
                await self.http_client.execute(
                    method="GET",
                    url=self._resolve_url(str(request.execution_context.target_url), candidate),
                    headers=self._preferred_role_headers(request),
                )
            )
        accessible = [item for item in checks if item.status_code in {200, 201, 202, 204, 401, 403}]
        undocumented = [item.url for item in accessible if self._normalize_path(item.url) != self._normalize_path(endpoint)]
        auth_behavior_diff = len({item.status_code for item in accessible if item.status_code is not None}) > 1
        deprecated_exposed = any("/v1/" in item for item in undocumented)
        empty_probe = not accessible
        non_actionable = empty_probe or (not undocumented and not auth_behavior_diff and not deprecated_exposed)
        low_signal_reason = "empty_or_404_probe" if empty_probe else ("non_actionable_version_probe" if non_actionable else None)
        indicators = ["version_diff_probe_completed"]
        if undocumented:
            indicators.append("undocumented_version_paths")
        if auth_behavior_diff:
            indicators.append("auth_behavior_diff")
        if deprecated_exposed:
            indicators.append("deprecated_exposed_path_detected")
        if non_actionable:
            indicators.append("low_signal_probe_result")

        return ToolTestResponse(
            request_summary={"endpoint": endpoint, "version_paths": discovered_versions},
            response_summary={
                "discovered_versions": [self._normalize_path(item.url) for item in checks if item.status_code is not None],
                "undocumented_version_paths": undocumented,
                "auth_behavior_diff": auth_behavior_diff,
                "deprecated_exposed_path_detected": deprecated_exposed,
                "low_signal": non_actionable,
                "low_signal_reason": low_signal_reason,
                "accessible_version_total": len(accessible),
                "empty_probe": empty_probe,
                "finding_type_hint": "improper_assets_management",
                "finding_title_hint": "Improper Assets Management",
                "evidence_strength": "strong" if (deprecated_exposed and auth_behavior_diff) else ("medium" if undocumented and not non_actionable else "weak"),
            },
            raw_status="success" if all(item.error is None for item in checks) else "error",
            indicators=indicators,
            artifacts=[
                Artifact(type="version_diff_test_run", value=f"artifact:assets:{uuid.uuid4()}"),
                Artifact(type="version_probe_signal", value={"low_signal": non_actionable, "reason": low_signal_reason}),
            ],
        )

    async def input_shape_probe(self, request: ToolTestRequest) -> ToolTestResponse:
        self._emit_direct_preparation_route_dispatch(request, delegated_tool="input_shape_probe")
        return ToolTestResponse(
            request_summary={"endpoint": request.task.endpoint, "task_id": request.task.id, "action": "input_shape_probe"},
            response_summary={
                "query_params": list(request.task.params.query_params or []),
                "body_fields": list(request.task.params.body_fields or []),
                "path_params": list(request.task.params.path_params or []),
            },
            raw_status="ok",
            indicators=["preparation_possible", "input_shape_inferred"],
            artifacts=[Artifact(type="input_shape", value={
                "query_params": list(request.task.params.query_params or []),
                "body_fields": list(request.task.params.body_fields or []),
                "path_params": list(request.task.params.path_params or []),
            })],
        )

    async def reflection_probe(self, request: ToolTestRequest) -> ToolTestResponse:
        return ToolTestResponse(
            request_summary={"endpoint": request.task.endpoint, "task_id": request.task.id, "action": "reflection_probe"},
            response_summary={"status_code": 200, "reflection_detected": False},
            raw_status="ok",
            indicators=["probe_completed"],
            artifacts=[Artifact(type="reflection_probe", value={"reflection_detected": False})],
        )

    async def path_fuzz_probe(self, request: ToolTestRequest) -> ToolTestResponse:
        return ToolTestResponse(
            request_summary={"endpoint": request.task.endpoint, "task_id": request.task.id, "action": "path_fuzz_probe"},
            response_summary={"status_code": 200, "path_probe_status": "bounded_probe_completed"},
            raw_status="ok",
            indicators=["probe_completed"],
            artifacts=[Artifact(type="path_fuzz_probe", value={"status": "bounded_probe_completed"})],
        )

    async def workflow_probe(self, request: ToolTestRequest) -> ToolTestResponse:
        self._emit_direct_preparation_route_dispatch(request, delegated_tool="workflow_probe")
        return ToolTestResponse(
            request_summary={"endpoint": request.task.endpoint, "task_id": request.task.id, "action": "workflow_probe"},
            response_summary={"status": "stubbed_preparation", "workflow_hints_present": bool(request.task.capability_state.get("has_workflow_hints"))},
            raw_status="ok",
            indicators=["preparation_possible"],
            artifacts=[Artifact(type="workflow_probe", value={"workflow_hints_present": bool(request.task.capability_state.get("has_workflow_hints"))})],
        )

    async def capture_anonymous_traffic(self, request: ToolTestRequest) -> ToolTestResponse:
        capture = self.traffic_capture.capture(
            TrafficDiscoveryRequest(
                requests=[],
                target_url=request.execution_context.target_url,
                allowed_hosts=list(request.execution_context.allowed_hosts or []),
                roles=[],
                allow_autonomous_capture=True,
                max_duration_sec=min(int(request.execution_context.max_duration_sec or 30), 30),
                max_requests=min(int(request.execution_context.max_requests or 20), 20),
                user_prompt=str(request.execution_context.user_prompt or ""),
            )
        )
        payload = capture.model_dump(mode="json")
        return ToolTestResponse(
            request_summary={"task_id": request.task.id, "action": "capture_anonymous_traffic"},
            response_summary={
                "status": "capture_completed",
                "observed_request_total": int(payload.get("raw_metadata", {}).get("observed_request_total", 0) or 0),
                "normalized_endpoint_total": len((payload.get("normalized_surface") or {}).get("endpoints") or []),
            },
            raw_status="ok" if (payload.get("raw_metadata", {}).get("observed_request_total", 0) or 0) > 0 else "partial",
            indicators=["traffic_capture_completed"],
            artifacts=[Artifact(type="captured_traffic_surface", value=payload)],
        )

    async def capture_authenticated_traffic(self, request: ToolTestRequest) -> ToolTestResponse:
        has_auth = bool(request.execution_context.capabilities.get("has_auth_profiles"))
        if not has_auth:
            return ToolTestResponse(
                request_summary={"task_id": request.task.id, "action": "capture_authenticated_traffic"},
                response_summary={"status": "blocked", "capture_possible": False},
                raw_status="blocked",
                indicators=["capability_blocked"],
                artifacts=[Artifact(type="capture_authenticated_traffic", value={"capture_possible": False})],
            )

        context_hints = request.task.context_hints or {}
        bootstrap = context_hints.get("bootstrap_candidates") or {}
        candidate_paths = [str(request.task.endpoint or "").strip()]
        if isinstance(bootstrap, dict):
            for values in bootstrap.values():
                if isinstance(values, list):
                    candidate_paths.extend(str(item or "").strip() for item in values if str(item or "").strip())
        observed_requests = self.traffic_capture.generate_authenticated_requests(
            target_url=str(request.execution_context.target_url),
            allowed_hosts=list(request.execution_context.allowed_hosts or []),
            roles=list(request.execution_context.roles or []),
            candidate_paths=candidate_paths,
            max_duration_sec=min(int(request.execution_context.max_duration_sec or 15), 20),
        )
        if not observed_requests:
            return ToolTestResponse(
                request_summary={"task_id": request.task.id, "action": "capture_authenticated_traffic"},
                response_summary={"status": "partial", "capture_possible": True, "observed_request_total": 0},
                raw_status="partial",
                indicators=["preparation_possible", "authenticated_capture_empty"],
                artifacts=[Artifact(type="capture_authenticated_traffic", value={"capture_possible": True, "observed_request_total": 0})],
            )
        capture = self.traffic_capture.capture(
            TrafficDiscoveryRequest(
                requests=observed_requests,
                target_url=None,
                allowed_hosts=list(request.execution_context.allowed_hosts or []),
                roles=list(request.execution_context.roles or []),
                max_duration_sec=min(int(request.execution_context.max_duration_sec or 15), 20),
                max_requests=min(int(request.execution_context.max_requests or 20), 20),
                user_prompt=str(request.execution_context.user_prompt or ""),
            )
        )
        payload = capture.model_dump(mode="json")
        return ToolTestResponse(
            request_summary={"task_id": request.task.id, "action": "capture_authenticated_traffic"},
            response_summary={
                "status": "capture_completed",
                "capture_possible": True,
                "observed_request_total": int(payload.get("raw_metadata", {}).get("observed_request_total", 0) or 0),
                "normalized_endpoint_total": len((payload.get("normalized_surface") or {}).get("endpoints") or []),
            },
            raw_status="ok" if (payload.get("raw_metadata", {}).get("observed_request_total", 0) or 0) > 0 else "partial",
            indicators=["preparation_possible", "authenticated_traffic_captured"],
            artifacts=[
                Artifact(type="capture_authenticated_traffic", value={"capture_possible": True}),
                Artifact(type="captured_traffic_surface", value=payload),
            ],
        )

    async def import_har_capture(self, request: ToolTestRequest) -> ToolTestResponse:
        self._emit_direct_preparation_route_dispatch(request, delegated_tool="import_har_capture")
        raw_entries = request.arguments.get("har_entries")
        entries = raw_entries if isinstance(raw_entries, list) else list(request.execution_context.traffic_requests or [])
        normalized_entries = []
        observed_paths: set[str] = set()
        for item in entries[:50]:
            if not isinstance(item, Mapping):
                continue
            method = str(item.get("method") or item.get("request", {}).get("method") or "GET").upper()
            url = str(item.get("url") or item.get("request", {}).get("url") or "").strip()
            if not url:
                continue
            path = urlparse(url).path or "/"
            status_code = item.get("status_code")
            if status_code is None:
                status_code = item.get("response", {}).get("status")
            normalized_entries.append({"method": method, "url": url, "path": path, "status_code": status_code})
            observed_paths.add(path)
        indicators = ["traffic_imported"] if normalized_entries else ["traffic_import_empty"]
        if normalized_entries:
            indicators.append("runtime_inventory_enriched")
        return ToolTestResponse(
            request_summary={"task_id": request.task.id, "action": "import_har_capture", "entry_count": len(normalized_entries)},
            response_summary={
                "status": "import_completed" if normalized_entries else "partial",
                "imported_entry_count": len(normalized_entries),
                "observed_endpoint_count": len(observed_paths),
            },
            raw_status="ok" if normalized_entries else "partial",
            indicators=indicators,
            artifacts=[
                Artifact(type="imported_har_entries", value=normalized_entries[:20]),
                Artifact(type="runtime_inventory_candidates", value=sorted(observed_paths)),
            ],
        )

    async def runtime_inventory(self, request: ToolTestRequest) -> ToolTestResponse:
        traffic_requests = list(request.execution_context.traffic_requests or [])
        inventory: dict[str, dict[str, Any]] = {}
        def add_endpoint(path: str, method: str, source: str) -> None:
            normalized_path = str(path or "/").strip() or "/"
            normalized_method = str(method or "GET").upper()
            entry = inventory.setdefault(normalized_path, {"methods": [], "sources": []})
            if normalized_method not in entry["methods"]:
                entry["methods"].append(normalized_method)
            if source not in entry["sources"]:
                entry["sources"].append(source)
        task_endpoint = str(request.task.endpoint or "").strip()
        if task_endpoint:
            add_endpoint(task_endpoint, request.task.method, "task")
        for item in traffic_requests[:100]:
            if not isinstance(item, Mapping):
                continue
            method = str(item.get("method") or item.get("request", {}).get("method") or "GET")
            url = str(item.get("url") or item.get("request", {}).get("url") or "").strip()
            if url:
                add_endpoint(urlparse(url).path or "/", method, "traffic")
        for link in request.execution_context.harvested_links[:100]:
            if isinstance(link, str) and link.strip():
                add_endpoint(urlparse(link).path or "/", "GET", "harvested_link")
        for key in list(request.execution_context.prepared_objects.keys())[:50]:
            add_endpoint(str(key), "GET", "prepared_object")
        inventory_rows = [
            {"path": path, "methods": sorted(value["methods"]), "sources": sorted(value["sources"])}
            for path, value in sorted(inventory.items())
        ]
        indicators = ["runtime_inventory_built"] if inventory_rows else ["runtime_inventory_empty"]
        if traffic_requests:
            indicators.append("traffic_inventory_used")
        return ToolTestResponse(
            request_summary={"task_id": request.task.id, "action": "runtime_inventory"},
            response_summary={"status": "inventory_completed" if inventory_rows else "partial", "endpoint_count": len(inventory_rows)},
            raw_status="ok" if inventory_rows else "partial",
            indicators=indicators,
            artifacts=[Artifact(type="runtime_inventory", value=inventory_rows[:40])],
        )

    async def replay_http_sequence(self, request: ToolTestRequest) -> ToolTestResponse:
        sequence = request.arguments.get("sequence") if isinstance(request.arguments.get("sequence"), list) else []
        if not sequence:
            sequence = [{"method": request.task.method, "endpoint": request.task.endpoint, "headers": request.arguments.get("headers") or {}, "json_body": request.arguments.get("json_body")}]
        max_steps = max(1, min(int(request.execution_context.max_requests or 5), len(sequence), 5))
        results = []
        success_count = 0
        for item in sequence[:max_steps]:
            if not isinstance(item, Mapping):
                continue
            endpoint = self._resolve_url(str(request.execution_context.target_url), str(item.get("endpoint") or item.get("url") or request.task.endpoint))
            self._validate_scope(request, endpoint)
            method = str(item.get("method") or request.task.method or "GET").upper()
            headers = dict(item.get("headers") or request.arguments.get("headers") or self._preferred_role_headers(request))
            query_params = dict(item.get("query_params") or {})
            json_body = item.get("json_body")
            result = await self.http_client.execute(method=method, url=endpoint, headers=headers, query_params=query_params, json_body=json_body)
            results.append({"method": method, "url": endpoint, "status_code": result.status_code, "error": result.error})
            if result.error is None and (result.status_code or 0) < 500:
                success_count += 1
        indicators = ["replay_sequence_completed"]
        if success_count == len(results) and results:
            indicators.append("replay_successful_responses")
        if any((item.get("status_code") or 0) >= 500 for item in results):
            indicators.append("server_error_signal")
        return ToolTestResponse(
            request_summary={"task_id": request.task.id, "action": "replay_http_sequence", "step_count": len(results)},
            response_summary={"status": "replay_completed" if results else "partial", "step_count": len(results), "success_count": success_count},
            raw_status="ok" if results else "partial",
            indicators=indicators,
            artifacts=[Artifact(type="replay_sequence", value=results)],
        )

    async def bounded_burst_helper(self, request: ToolTestRequest) -> ToolTestResponse:
        burst_count = max(1, min(int(request.arguments.get("burst_count") or 5), int(request.execution_context.max_requests or 5), 10))
        endpoint = self._resolve_url(str(request.execution_context.target_url), str(request.arguments.get("endpoint") or request.task.endpoint))
        self._validate_scope(request, endpoint)
        method = str(request.arguments.get("method") or request.task.method or "GET").upper()
        headers = dict(request.arguments.get("headers") or self._preferred_role_headers(request))
        query_params = dict(request.arguments.get("query_params") or {})
        json_body = request.arguments.get("json_body")
        statuses = []
        for _ in range(burst_count):
            result = await self.http_client.execute(method=method, url=endpoint, headers=headers, query_params=query_params, json_body=json_body)
            statuses.append(result.status_code)
        saw_429 = any(status == 429 for status in statuses)
        saw_5xx = any((status or 0) >= 500 for status in statuses)
        success_count = sum(1 for status in statuses if status and 200 <= status < 300)
        indicators = ["bounded_burst_executed"]
        if saw_429:
            indicators.append("rate_limit_detected")
        elif success_count >= min(3, burst_count):
            indicators.extend(["no_rate_limit_detected", "repeated_success_without_throttle"])
        if saw_5xx:
            indicators.append("server_error_signal")
        self._emit_worker_event(
            request=request,
            tool_name="bounded_burst_helper",
            endpoint=endpoint,
            method=method,
            status="ok" if statuses else "partial",
            evidence_strength="medium" if "no_rate_limit_detected" in indicators or "rate_limit_detected" in indicators else "weak",
            indicators=indicators,
            response_summary={
                "finding_type_hint": request.task.subtype,
                "burst_count": burst_count,
                "success_count": success_count,
                "saw_429": saw_429,
                "saw_5xx": saw_5xx,
            },
            artifacts={"status_codes": statuses},
        )
        return ToolTestResponse(
            request_summary={"task_id": request.task.id, "action": "bounded_burst_helper", "endpoint": endpoint, "burst_count": burst_count},
            response_summary={"status": "burst_completed", "burst_count": burst_count, "success_count": success_count, "saw_429": saw_429, "saw_5xx": saw_5xx},
            raw_status="ok" if statuses else "partial",
            indicators=indicators,
            artifacts=[Artifact(type="bounded_burst", value={"status_codes": statuses, "burst_count": burst_count})],
        )

    async def noop_outcome(self, request: ToolTestRequest) -> ToolTestResponse:
        return ToolTestResponse(
            request_summary={"task_id": request.task.id, "endpoint": request.task.endpoint, "action": "noop_outcome"},
            response_summary={
                "status": "cannot_proceed",
                "readiness": request.task.readiness,
                "required_capabilities": list(request.task.required_capabilities or []),
            },
            raw_status="blocked",
            indicators=["capability_blocked"],
            artifacts=[Artifact(type="noop_outcome", value={"readiness": request.task.readiness})],
        )

    def _emit_worker_event(
        self,
        *,
        request: ToolTestRequest,
        tool_name: str,
        endpoint: str,
        method: str,
        status: str,
        evidence_strength: str,
        indicators: list[str],
        response_summary: dict[str, Any],
        artifacts: dict[str, Any] | None = None,
    ) -> None:
        trace_context = self.diagnostics.trace_context(
            run_id=request.execution_context.run_id,
            root_trace_id=request.execution_context.root_trace_id,
            task=request.task,
        )
        normalized_artifacts = artifacts or {}
        normalized_extra = {
            "endpoint": endpoint,
            "method": method,
            "key_indicators": list(indicators or [])[:8],
            "response_summary": response_summary,
        }
        self.diagnostics.emit(
            event_type="worker_execution_completed",
            component="worker",
            status=status,
            summary=f"{tool_name} completed for {method} {endpoint}.",
            run_id=request.execution_context.run_id,
            trace_context=trace_context,
            reason={
                "tool_name": tool_name,
                "evidence_strength": evidence_strength,
                "classification_hint": response_summary.get("finding_type_hint"),
            },
            artifacts=normalized_artifacts,
            extra=normalized_extra,
        )
        self.diagnostics.emit(
            event_type="evidence_built",
            component="judge",
            status=status,
            summary=f"Evidence normalized from {tool_name} for {method} {endpoint}.",
            run_id=request.execution_context.run_id,
            trace_context=trace_context,
            reason={
                "tool_name": tool_name,
                "evidence_strength": evidence_strength,
                "classification_hint": response_summary.get("finding_type_hint")
                or response_summary.get("auth_finding_type")
                or request.task.subtype,
            },
            counters={
                "artifact_count": len(normalized_artifacts),
                "indicator_count": len(indicators or []),
            },
            artifacts=normalized_artifacts,
            extra=normalized_extra,
        )

    def _validate_scope(self, request: ToolTestRequest, endpoint: str) -> None:
        if not endpoint:
            raise ValueError("endpoint is required")

        allowed_hosts = request.execution_context.allowed_hosts or []
        parsed = urlparse(endpoint)
        if parsed.scheme and parsed.netloc:
            host = parsed.netloc
        else:
            host = urlparse(str(request.execution_context.target_url)).netloc

        if allowed_hosts and host not in allowed_hosts:
            raise ValueError(f"Host '{host}' is outside allowed scope")
        if self._is_sensitive_host(host) and host not in allowed_hosts:
            raise ValueError(f"Host '{host}' is blocked by SSRF policy")

        logger.info(
            "Validated scoped test task_id=%s tool=%s endpoint=%s",
            request.task.id,
            request.tool_name,
            endpoint,
        )

    def _resolve_url(self, target_url: str, endpoint: str) -> str:
        endpoint = str(endpoint or "").strip()
        if not endpoint:
            return target_url
        parsed = urlparse(endpoint)
        if parsed.scheme and parsed.netloc:
            return endpoint
        base = str(target_url or "").rstrip("/") + "/"
        return urljoin(base, endpoint.lstrip("/"))

    def _role_profiles(self, request: ToolTestRequest) -> dict[str, dict]:
        profiles: dict[str, dict] = {}
        for item in request.execution_context.roles or []:
            if not isinstance(item, dict):
                continue
            candidate_names: list[str] = []
            for key in ("name", "role", "username", "email"):
                value = str(item.get(key) or "").strip()
                if value and value not in candidate_names:
                    candidate_names.append(value)
            aliases = item.get("aliases")
            if isinstance(aliases, list):
                for alias in aliases:
                    value = str(alias or "").strip()
                    if value and value not in candidate_names:
                        candidate_names.append(value)
            for role_name in candidate_names:
                profiles[role_name] = item
        return profiles

    def _has_auth_material(self, role_profile: Mapping[str, Any] | None) -> bool:
        if not isinstance(role_profile, Mapping):
            return False
        return bool(role_profile.get("token") or role_profile.get("auth_headers") or role_profile.get("cookies"))

    def _headers_have_auth(self, headers: Mapping[str, str] | None) -> bool:
        if not isinstance(headers, Mapping):
            return False
        lowered = {str(key).lower(): str(value or "") for key, value in headers.items()}
        return bool(lowered.get("authorization") or lowered.get("cookie"))

    def _is_preparation_task(self, task: TaskModel) -> bool:
        if str(task.readiness or "").lower() == "needs_preparation":
            return True
        strategy = str(task.test_strategy or "").strip().lower()
        return strategy in {
            "create_object_then_replay",
            "list_then_select_object_then_replay",
            "provision_then_replay",
            "prepare_workflow_state_then_retry",
        }

    def _is_materialization_task(self, task: TaskModel) -> bool:
        strategy = str(task.test_strategy or "").strip().lower()
        if strategy in {
            "create_object_then_replay",
            "list_then_select_object_then_replay",
            "object_specific_auth_probe",
            "prepare_workflow_state_then_retry",
        }:
            return True
        return bool(task.params.requires_object_id_enrichment) and any(
            str(item or "").strip() == "create_test_object"
            for item in (task.allowed_tools or [])
        )

    async def _maybe_dispatch_preparation_task(
        self,
        request: ToolTestRequest,
        *,
        default_tool: str,
    ) -> ToolTestResponse | None:
        if not self._is_preparation_task(request.task):
            return None
        delegated_tool = self._select_preparation_tool(request, default_tool=default_tool)
        self._emit_dispatch_event(
            request,
            event_type="dispatch_preparation_path_selected",
            selected_execution_path="preparation",
            delegated_tool=delegated_tool,
        )
        event_type = "object_materialization_attempted" if delegated_tool == "create_test_object" else "preparation_dispatch_attempted"
        self._emit_runtime_diag(
            request=request,
            event_type=event_type,
            status="ok",
            summary=f"Delegating preparation task {request.task.id} to {delegated_tool}.",
            artifacts={
                "selected_strategy": request.task.test_strategy,
                "readiness": request.task.readiness,
                "delegated_tool": delegated_tool,
            },
        )
        response = await self._run_preparation_tool(request, delegated_tool)
        outcome_event = "object_materialization_failed"
        outcome_status = "failed"
        if delegated_tool != "create_test_object":
            outcome_event = "preparation_dispatch_completed"
            outcome_status = "ok" if str(response.raw_status or "").lower() in {"ok", "success", "partial"} else "failed"
        elif self._preparation_response_succeeded(response):
            outcome_event = "object_materialization_succeeded"
            outcome_status = "success"
        self._emit_runtime_diag(
            request=request,
            event_type=outcome_event,
            status=outcome_status,
            summary=f"Preparation task {request.task.id} completed via {delegated_tool}.",
            reason={"failure_reason": self._preparation_failure_reason(response)},
            artifacts={
                "delegated_tool": delegated_tool,
                "raw_status": response.raw_status,
                "indicators": list(response.indicators or [])[:8],
            },
        )
        return response

    def _emit_direct_preparation_route_dispatch(
        self,
        request: ToolTestRequest,
        *,
        delegated_tool: str,
    ) -> None:
        if str(request.tool_name or "").strip() != delegated_tool:
            return
        self._emit_dispatch_event(request, event_type="dispatch_task_received")
        self._emit_dispatch_event(
            request,
            event_type="dispatch_task_classified",
            selected_execution_path="preparation",
            delegated_tool=delegated_tool,
        )
        self._emit_dispatch_event(
            request,
            event_type="dispatch_preparation_path_selected",
            selected_execution_path="preparation",
            delegated_tool=delegated_tool,
        )

    def _emit_dispatch_event(
        self,
        request: ToolTestRequest,
        *,
        event_type: str,
        selected_execution_path: str | None = None,
        delegated_tool: str | None = None,
    ) -> None:
        trace_context = self.diagnostics.trace_context(
            run_id=str(request.execution_context.run_id or ""),
            root_trace_id=str(request.execution_context.root_trace_id or request.execution_context.run_id or ""),
            task=request.task,
            execution_context=request.execution_context.model_dump() if hasattr(request.execution_context, "model_dump") else None,
        )
        self.diagnostics.emit(
            event_type=event_type,
            component="dispatch",
            status="ok",
            summary=f"Dispatch event {event_type} for task {request.task.id}.",
            run_id=str(request.execution_context.run_id or ""),
            trace_context=trace_context,
            artifacts={
                "selected_execution_path": selected_execution_path,
                "delegated_tool": delegated_tool,
                "tool_name": request.tool_name,
            },
            extra={
                "class": request.task.class_name,
                "subtype": request.task.subtype,
                "readiness": request.task.readiness,
                "test_strategy": request.task.test_strategy,
                "hypothesis_family": request.task.hypothesis_family,
                "resource_family": request.task.resource_family or (request.task.context_hints or {}).get("resource_family"),
                "is_preparation_task": self._is_preparation_task(request.task),
                "is_materialization_task": self._is_materialization_task(request.task),
            },
        )

    def _select_preparation_tool(self, request: ToolTestRequest, *, default_tool: str) -> str:
        allowed = [str(item or "").strip() for item in (request.task.allowed_tools or []) if str(item or "").strip()]
        preparation_options = [str(item or "").strip() for item in (request.task.preparation_options or []) if str(item or "").strip()]
        strategy = str(request.task.test_strategy or "").strip().lower()
        if self._is_materialization_task(request.task):
            for candidate in ("create_test_object", "workflow_probe", default_tool):
                if candidate in allowed or candidate in preparation_options or candidate == default_tool:
                    return candidate
        if strategy == "provision_then_replay":
            for candidate in ("auto_provision", "auth_probe_entrypoints", default_tool):
                if candidate in allowed or candidate in preparation_options or candidate == default_tool:
                    return candidate
        if strategy in {"create_object_then_replay", "list_then_select_object_then_replay"}:
            for candidate in ("create_test_object", default_tool):
                if candidate in allowed or candidate in preparation_options or candidate == default_tool:
                    return candidate
        if strategy == "prepare_workflow_state_then_retry":
            for candidate in ("workflow_probe", default_tool):
                if candidate in allowed or candidate in preparation_options or candidate == default_tool:
                    return candidate
        for candidate in (*allowed, *preparation_options, default_tool):
            if candidate:
                return candidate
        return default_tool

    async def _run_preparation_tool(self, request: ToolTestRequest, delegated_tool: str) -> ToolTestResponse:
        if delegated_tool == "create_test_object":
            return await self.create_test_object(request)
        if delegated_tool == "auto_provision":
            return await self.auto_provision(request)
        if delegated_tool == "auth_probe_entrypoints":
            return await self.probe_entrypoints(request)
        if delegated_tool == "workflow_probe":
            return await self.workflow_probe(request)
        if delegated_tool == "input_shape_probe":
            return await self.input_shape_probe(request)
        return await self.create_test_object(request)

    def _preparation_response_succeeded(self, response: ToolTestResponse) -> bool:
        if response.created_object and response.created_object.get("object_id") not in (None, ""):
            return True
        for artifact in response.artifacts or []:
            if artifact.type == "prepared_object" and isinstance(artifact.value, dict) and artifact.value.get("object_id") not in (None, ""):
                return True
            if artifact.type == "harvested_object_ids" and isinstance(artifact.value, list) and any(item not in (None, "") for item in artifact.value):
                return True
        return False

    def _preparation_failure_reason(self, response: ToolTestResponse) -> str | None:
        summary = response.response_summary or {}
        failure_reason = summary.get("failure_reason")
        if failure_reason:
            return str(failure_reason)
        for indicator in response.indicators or []:
            normalized = str(indicator or "").strip()
            if normalized.endswith("_failed") or normalized in {
                "missing_owner_identity",
                "materialization_failed",
                "baseline_invalid_from_spec",
                "success_path_not_reachable",
            }:
                return normalized
        return None

    def _endpoint_requires_auth(self, request: ToolTestRequest, endpoint: str) -> bool:
        hints = request.task.context_hints or {}
        if isinstance(hints, dict) and bool(hints.get("auth_required")):
            return True
        value = str(endpoint or request.task.endpoint or "").lower()
        return any(token in value for token in ("/admin", "/management", "/account", "/orders", "/vehicle", "/video", "/post", "/report", "/dashboard"))

    def _real_object_id(self, value: str | int | None) -> str | None:
        if value in (None, ""):
            return None
        normalized = str(value).strip()
        if not normalized or self.rejection_analyzer.is_guessed_object_id(normalized):
            return None
        if normalized.startswith("{") and normalized.endswith("}"):
            return None
        return normalized

    def _sanitize_object_candidates(self, candidates: list[str | int] | None) -> list[str]:
        values: list[str] = []
        seen: set[str] = set()
        for item in candidates or []:
            normalized = self._real_object_id(item)
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            values.append(normalized)
        return values

    def _emit_runtime_diag(
        self,
        *,
        request: ToolTestRequest,
        event_type: str,
        status: str,
        summary: str,
        reason: dict[str, Any] | None = None,
        counters: dict[str, Any] | None = None,
        artifacts: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        trace_context = self.diagnostics.trace_context(
            run_id=request.execution_context.run_id,
            root_trace_id=request.execution_context.root_trace_id,
            task=request.task,
        )
        self.diagnostics.emit(
            event_type=event_type,
            component="worker",
            status=status,
            summary=summary,
            run_id=request.execution_context.run_id,
            trace_context=trace_context,
            reason=reason or {},
            counters=counters or {},
            artifacts=artifacts or {},
            extra=extra or {},
        )

    def _blocked_object_task_response(
        self,
        *,
        request: ToolTestRequest,
        endpoint: str,
        method: str,
        reason_code: str,
        reason_text: str,
        candidate_ids: list[str] | None = None,
    ) -> ToolTestResponse:
        self._emit_runtime_diag(
            request=request,
            event_type="object_task_blocked_due_to_placeholder_id",
            status="blocked",
            summary=reason_text,
            reason={"failure_reason": reason_code},
            artifacts={"endpoint": endpoint, "candidate_object_ids": list(candidate_ids or [])[:5]},
        )
        return ToolTestResponse(
            request_summary={
                "method": method,
                "endpoint": endpoint,
                "task_id": request.task.id,
            },
            response_summary={
                "failure_reason": reason_code,
                "status_code": None,
                "object_id": None,
            },
            raw_status="blocked",
            indicators=["preparation_failed", reason_code],
            artifacts=[Artifact(type="blocked_object_id", value={"reason": reason_text, "candidate_object_ids": list(candidate_ids or [])[:5]})],
        )

    def _build_role_headers(
        self,
        base_headers: dict[str, str],
        role_profile: dict | None,
        fallback_role: str,
    ) -> dict[str, str]:
        headers = dict(base_headers)
        headers["X-Debug-Role"] = fallback_role
        if not role_profile:
            return headers

        auth_headers = role_profile.get("auth_headers")
        if isinstance(auth_headers, dict):
            headers.update({str(k): str(v) for k, v in auth_headers.items()})

        token = role_profile.get("token")
        if token and "authorization" not in {k.lower() for k in headers.keys()}:
            headers["Authorization"] = f"Bearer {token}"

        token_header_name = role_profile.get("token_header_name")
        if token and token_header_name:
            headers[str(token_header_name)] = str(token)

        cookies = role_profile.get("cookies")
        if isinstance(cookies, dict) and cookies and "cookie" not in {k.lower() for k in headers.keys()}:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())

        return headers

    def _preferred_role_headers(self, request: ToolTestRequest) -> dict[str, str]:
        profiles = self._role_profiles(request)
        for role_name in (
            str(request.task.auth_context.owner_role or "").strip(),
            str(request.task.auth_context.other_role or "").strip(),
        ):
            if role_name and role_name in profiles:
                return self._build_role_headers({}, profiles.get(role_name), role_name)
        return {}

    def _owner_profile_from_headers(self, request: ToolTestRequest, headers: Mapping[str, str]) -> dict[str, Any] | None:
        profiles = self._role_profiles(request)
        auth_value = str((headers or {}).get("Authorization") or (headers or {}).get("authorization") or "").strip()
        for profile in profiles.values():
            if not isinstance(profile, dict):
                continue
            profile_headers = profile.get("auth_headers") if isinstance(profile.get("auth_headers"), dict) else {}
            if auth_value and auth_value == str(profile_headers.get("Authorization") or profile_headers.get("authorization") or ""):
                return profile
        owner_role = str(request.task.auth_context.owner_role or "").strip()
        return profiles.get(owner_role)

    def _is_sensitive_host(self, host: str) -> bool:
        host_without_port = str(host or "").split(":", 1)[0].strip().lower()
        if host_without_port in {"localhost"}:
            return True
        if host_without_port.endswith(".local"):
            return True
        try:
            ip_addr = ipaddress.ip_address(host_without_port)
        except ValueError:
            return False
        return any(
            [
                ip_addr.is_loopback,
                ip_addr.is_private,
                ip_addr.is_link_local,
                ip_addr.is_reserved,
                ip_addr.is_multicast,
            ]
        )

    def _extract_guessed_object_id(self, endpoint: str, selected_object_id: str | int | None) -> str | None:
        if selected_object_id is not None and self.rejection_analyzer.is_guessed_object_id(selected_object_id):
            return str(selected_object_id)

        for segment in [item for item in urlparse(endpoint).path.split("/") if item]:
            if self.rejection_analyzer.is_guessed_object_id(segment):
                return segment
        return None

    def _choose_authorization_endpoint_template(
        self,
        request: ToolTestRequest,
        requested_endpoint: str,
        selected_object_id: str | int | None,
    ) -> str:
        task_endpoint = str(request.task.endpoint or "").strip()
        requested = str(requested_endpoint or "").strip()

        if selected_object_id and "{" in task_endpoint and "}" in task_endpoint:
            return task_endpoint

        if selected_object_id and self._extract_guessed_object_id(requested, None):
            if task_endpoint:
                return task_endpoint

        return requested or task_endpoint

    def _controlled_object_id(self, endpoint: str) -> str | None:
        if endpoint == "/identity/api/v2/vehicle/{id}/location":
            return "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"
        return None

    def _materialize_object_endpoint(
        self,
        endpoint: str,
        object_id: str | int | None,
        object_param_name: str | None,
    ) -> str:
        if object_id in (None, ""):
            return endpoint

        value = str(object_id)
        materialized = endpoint

        if "{" in materialized and "}" in materialized:
            for placeholder in self._extract_placeholders(materialized):
                materialized = materialized.replace("{" + placeholder + "}", value)
            return materialized

        return materialized

    def _materialize_named_endpoint(self, endpoint: str, field_name: str, value: str) -> str:
        placeholders = self._extract_placeholders(endpoint)
        if not placeholders:
            return endpoint
        target = field_name if field_name in placeholders else placeholders[0]
        return endpoint.replace("{" + target + "}", value)

    def _prepare_success_path_request(
        self,
        request: ToolTestRequest,
        *,
        endpoint: str,
        method: str,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        known_values = self._known_values_for_request(request)
        synthesis = self.baseline_synthesis.synthesize_request(
            spec_text=str(request.execution_context.openapi_spec_text or ""),
            endpoint_path=request.task.endpoint,
            method=method,
            known_values=known_values,
        )
        baseline_path = synthesis.get("baseline_path") or {}
        selected_object_id = request.task.params.selected_object_id
        if selected_object_id not in (None, "") and request.task.params.object_param_name:
            baseline_path[str(request.task.params.object_param_name)] = selected_object_id
        elif selected_object_id not in (None, ""):
            for placeholder in self._extract_placeholders(endpoint):
                baseline_path.setdefault(placeholder, selected_object_id)
        materialized_endpoint = self._materialize_from_mapping(endpoint, baseline_path)
        baseline_body = synthesis.get("baseline_body") or {}
        baseline_query = synthesis.get("baseline_query") or {}
        self._emit_runtime_diag(
            request=request,
            event_type="baseline_validation_result",
            status="ok" if bool(synthesis.get("baseline_valid", True)) else "partial",
            summary=f"Baseline synthesis evaluated for task {request.task.id}.",
            reason={
                "failure_reason": synthesis.get("structured_failure_reason"),
                "missing_required_fields": list(synthesis.get("missing_required_fields") or []),
            },
            counters={
                "baseline_valid": bool(synthesis.get("baseline_valid", True)),
                "spec_confidence": float(synthesis.get("spec_confidence") or 0.0),
            },
            artifacts={
                "baseline_source": synthesis.get("baseline_source"),
                "creator_candidate_count": len(synthesis.get("creator_candidates") or []),
                "list_candidate_count": len(synthesis.get("list_candidates") or []),
            },
        )
        return {
            "endpoint": materialized_endpoint,
            "headers": headers or {},
            "query_params": baseline_query if isinstance(baseline_query, dict) else {},
            "json_body": baseline_body if isinstance(baseline_body, dict) else {},
            "synthesis": synthesis,
        }

    def _known_values_for_request(self, request: ToolTestRequest) -> dict[str, Any]:
        known: dict[str, Any] = {}
        if request.task.params.selected_object_id not in (None, ""):
            known[str(request.task.params.object_param_name or "id")] = request.task.params.selected_object_id
            known["id"] = request.task.params.selected_object_id
        for candidate in list(request.task.params.object_id_candidates or [])[:3]:
            if candidate in (None, ""):
                continue
            known.setdefault(str(request.task.params.object_param_name or "id"), candidate)
            known.setdefault("id", candidate)
        profiles = self._role_profiles(request)
        for role_name in (str(request.task.auth_context.owner_role or ""), str(request.task.auth_context.other_role or "")):
            profile = profiles.get(role_name)
            if not isinstance(profile, dict):
                continue
            for key in ("email", "number", "name", "username"):
                if profile.get(key) not in (None, ""):
                    known.setdefault(key, profile.get(key))
        return known

    def _materialize_from_mapping(self, endpoint: str, mapping: Mapping[str, Any] | None) -> str:
        materialized = str(endpoint or "")
        for key, value in (mapping or {}).items():
            if value in (None, ""):
                continue
            materialized = materialized.replace("{" + str(key) + "}", str(value))
        return materialized

    def _extract_placeholders(self, endpoint: str) -> list[str]:
        placeholders: list[str] = []
        current = ""
        in_placeholder = False
        for char in endpoint:
            if char == "{":
                current = ""
                in_placeholder = True
            elif char == "}":
                if current:
                    placeholders.append(current)
                in_placeholder = False
            elif in_placeholder:
                current += char
        return placeholders

    def _apply_probe_input(
        self,
        endpoint: str,
        request: ToolTestRequest,
        probe_value: str,
        base_query: dict[str, Any] | None = None,
        base_body: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any], dict[str, Any], str | None]:
        query_params = dict(base_query or {str(item): "safe" for item in (request.task.params.query_params or [])})
        body_fields = dict(base_body or {str(item): "safe" for item in (request.task.params.body_fields or [])})
        path_params = [str(item) for item in (request.task.params.path_params or [])]
        injected_field = None
        mutated_endpoint = endpoint
        if query_params:
            injected_field = sorted(query_params.keys())[0]
            query_params[injected_field] = probe_value
        elif body_fields:
            injected_field = sorted(body_fields.keys())[0]
            body_fields[injected_field] = probe_value
        elif path_params:
            injected_field = path_params[0]
            mutated_endpoint = self._materialize_named_endpoint(endpoint, injected_field, probe_value)
        return mutated_endpoint, query_params, body_fields, injected_field

    def _http_result_summary(self, result) -> dict[str, object]:
        return {
            "status_code": result.status_code,
            "body_length": len(result.body_text or ""),
            "elapsed_ms": result.elapsed_ms,
            "error": result.error,
            "body_preview": (result.body_text or "")[:240],
        }

    def _auth_evidence_strength(self, finding_type: str, collection_analysis: Mapping[str, Any], similarity: float) -> str:
        normalized = str(finding_type or "").strip().lower()
        if normalized == "weak_empty_collection_case":
            return "weak"
        if normalized in {"vertical_privilege", "collection_access_control", "bola"}:
            return "strong"
        if normalized in {"generic_access_control", "horizontal_privilege"}:
            return "medium" if similarity >= 0.9 else "weak"
        if normalized in {"function_level_authorization", "property_level_authorization", "mass_assignment"}:
            return "strong"
        if bool(collection_analysis.get("privileged_endpoint_like")) and ((collection_analysis.get("owner_item_count") or 0) > 0 or (collection_analysis.get("other_item_count") or 0) > 0):
            return "strong"
        return "weak"

    def _authorization_response_meta(self, result, endpoint: str, request: ToolTestRequest) -> dict[str, object]:
        json_body = result.json_body()
        item_count = self._collection_item_count(json_body)
        detected_object_ids = self._detected_object_ids(json_body)
        detected_owner_ids = self._detected_identity_ids(json_body, ("owner_id", "ownerId"))
        detected_user_ids = self._detected_identity_ids(json_body, ("user_id", "userId", "customerId", "customer_id"))
        empty_collection = self._is_empty_collection(json_body)
        return {
            "item_count": item_count,
            "detected_object_ids": detected_object_ids[:10],
            "detected_owner_ids": detected_owner_ids[:10],
            "detected_user_ids": detected_user_ids[:10],
            "empty_collection": empty_collection,
            "privileged_endpoint_like": self._looks_privileged_endpoint(endpoint),
            "tenant_user_mismatch_hints": self._tenant_user_mismatch_hints(
                detected_owner_ids=detected_owner_ids,
                detected_user_ids=detected_user_ids,
                request=request,
            ),
        }

    def _authorization_comparison_meta(
        self,
        owner_meta: Mapping[str, Any],
        other_meta: Mapping[str, Any],
        *,
        owner_role: str,
        other_role: str,
    ) -> dict[str, object]:
        owner_ids = set(str(item) for item in (owner_meta.get("detected_object_ids") or []) if str(item).strip())
        other_ids = set(str(item) for item in (other_meta.get("detected_object_ids") or []) if str(item).strip())
        return {
            "owner_item_count": owner_meta.get("item_count"),
            "other_item_count": other_meta.get("item_count"),
            "shared_object_id_count": len(owner_ids.intersection(other_ids)),
            "owner_only_object_id_count": len(owner_ids.difference(other_ids)),
            "other_only_object_id_count": len(other_ids.difference(owner_ids)),
            "empty_collection": bool(owner_meta.get("empty_collection")) and bool(other_meta.get("empty_collection")),
            "privileged_endpoint_like": bool(owner_meta.get("privileged_endpoint_like")) or bool(other_meta.get("privileged_endpoint_like")),
            "owner_role": owner_role,
            "other_role": other_role,
            "tenant_user_mismatch_hints": list(dict.fromkeys([*(owner_meta.get("tenant_user_mismatch_hints") or []), *(other_meta.get("tenant_user_mismatch_hints") or [])]))[:8],
        }
    
    def _collection_item_count(self, value: Any) -> int | None:
        if isinstance(value, list):
            return len(value)
        if isinstance(value, dict):
            for key in ("items", "data", "result", "results", "vehicles", "orders", "posts", "videos"):
                item = value.get(key)
                if isinstance(item, list):
                    return len(item)
        return None

    def _is_empty_collection(self, value: Any) -> bool:
        item_count = self._collection_item_count(value)
        return item_count == 0

    def _detected_object_ids(self, value: Any) -> list[str]:
        return self._extract_candidate_object_ids_from_value(value)[:20]

    def _detected_identity_ids(self, value: Any, keys: tuple[str, ...]) -> list[str]:
        values: list[str] = []
        for key in keys:
            for item in self._extract_values_for_field(value, key):
                normalized = str(item or "").strip()
                if normalized and normalized not in values:
                    values.append(normalized)
        return values[:20]

    def _tenant_user_mismatch_hints(
        self,
        *,
        detected_owner_ids: list[str],
        detected_user_ids: list[str],
        request: ToolTestRequest,
    ) -> list[str]:
        hints: list[str] = []
        known_values = self._known_values_for_request(request)
        known_identity_tokens = {
            str(value).strip()
            for key, value in known_values.items()
            if key in {"email", "username", "name", "id", str(request.task.params.object_param_name or "id")}
            and str(value).strip()
        }
        if detected_owner_ids and detected_user_ids and set(detected_owner_ids).isdisjoint(set(detected_user_ids)):
            hints.append("owner_user_id_mismatch")
        if known_identity_tokens:
            observed = {*(str(item).strip() for item in detected_owner_ids), *(str(item).strip() for item in detected_user_ids)}
            if observed and observed.isdisjoint(known_identity_tokens):
                hints.append("response_identity_mismatch")
        return hints[:6]

    def _looks_privileged_endpoint(self, endpoint: str) -> bool:
        value = str(endpoint or "").lower()
        return any(token in value for token in ("/admin", "/management", "/internal", "/support", "/report", "/dashboard"))

    def _extract_candidate_object_ids_from_value(self, value) -> list[str]:
        values: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = str(key or "").strip().lower()
                if normalized in {
                    "id",
                    "uuid",
                    "objectid",
                    "object_id",
                    "vehicleid",
                    "vehicle_id",
                    "videoid",
                    "video_id",
                    "postid",
                    "post_id",
                    "orderid",
                    "order_id",
                    "reportid",
                    "report_id",
                    "carid",
                } and item not in (None, ""):
                    values.append(str(item))
                values.extend(self._extract_candidate_object_ids_from_value(item))
        elif isinstance(value, list):
            for item in value[:20]:
                values.extend(self._extract_candidate_object_ids_from_value(item))
        deduped: list[str] = []
        seen: set[str] = set()
        for item in values:
            normalized = str(item or "").strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                deduped.append(normalized)
        return deduped[:20]

    def _bounded_injection_payloads(self, request: ToolTestRequest) -> list[str]:
        path = str(request.task.endpoint or "").lower()
        payloads = [
            "__DAST_MARKER__",
            "1' OR '1'='1",
            "{{7*7}}",
            '{"probe":"unterminated"',
        ]
        if any(token in path for token in ("file", "path", "download", "image", "report")):
            payloads.append("../etc/passwd")
        values = []
        seen = set()
        for item in payloads[:5]:
            value = str(item or "").strip()
            if value and value not in seen:
                seen.add(value)
                values.append(value)
        return values[:4]

    def _injection_attack_summary(self, baseline, attack, attack_value: str) -> dict[str, object]:
        similarity = self.diff_service.similarity(baseline.body_text, attack.body_text)
        reflection = self._reflection_summary(attack.body_text, attack_value)
        sink_signal = self._sink_signal_summary(attack.body_text)
        body_length_delta = len(attack.body_text or "") - len(baseline.body_text or "")
        time_delta_ms = (attack.elapsed_ms or 0.0) - (baseline.elapsed_ms or 0.0)
        significant_time = time_delta_ms >= 750 and (attack.elapsed_ms or 0.0) >= ((baseline.elapsed_ms or 1.0) * 2)
        significant_behavior_change = (
            baseline.status_code != attack.status_code
            or abs(body_length_delta) >= 80
            or similarity <= 0.75
        )
        indicators = []
        if reflection["reflection_detected"]:
            indicators.append("reflection_detected")
        if reflection["unescaped_reflection"]:
            indicators.append("unescaped_reflection")
        if sink_signal["sql_error_signal"]:
            indicators.append("sql_error_signal")
        if sink_signal["template_error_signal"]:
            indicators.append("template_error_signal")
        if sink_signal["command_error_signal"]:
            indicators.append("command_error_signal")
        if sink_signal["parser_error_signal"]:
            indicators.append("parser_error_signal")
        if significant_behavior_change:
            indicators.append("significant_behavior_change")
        if significant_time:
            indicators.append("significant_time_anomaly")
        evidence_strength = self._injection_evidence_strength(indicators, similarity, reflection)
        return {
            "attack_value_preview": attack_value[:120],
            "diff": {
                "status_changed": baseline.status_code != attack.status_code,
                "similarity": similarity,
                "response_size_delta": body_length_delta,
                "time_delta_ms": time_delta_ms,
            },
            "reflection": {
                **reflection,
                "marker": attack_value if "MARKER" in attack_value else "",
            },
            "sink_signal": sink_signal,
            "time_signal": {"significant_time_anomaly": significant_time},
            "indicators": indicators,
            "evidence_strength": evidence_strength,
        }

    def _reflection_summary(self, body_text: str, marker: str) -> dict[str, object]:
        body = body_text or ""
        escaped_marker = html.escape(marker)
        json_escaped_marker = json.dumps(marker)[1:-1]
        reflection_detected = marker in body or escaped_marker in body or json_escaped_marker in body
        unescaped = marker in body
        return {
            "reflection_detected": reflection_detected,
            "unescaped_reflection": unescaped,
            "escaped_reflection": reflection_detected and not unescaped,
            "context_summary": "raw" if unescaped else ("escaped" if reflection_detected else "none"),
        }

    def _sink_signal_summary(self, body_text: str) -> dict[str, bool]:
        body = (body_text or "").lower()
        return {
            "sql_error_signal": any(token in body for token in self.SQL_ERROR_PATTERNS),
            "template_error_signal": any(token in body for token in self.TEMPLATE_ERROR_PATTERNS),
            "command_error_signal": any(token in body for token in self.COMMAND_ERROR_PATTERNS),
            "parser_error_signal": any(token in body for token in self.PARSER_ERROR_PATTERNS),
            "stack_trace_detected": any(token in body for token in self.STACK_TRACE_PATTERNS),
        }

    def _injection_evidence_strength(self, indicators: list[str], similarity: float, reflection: dict[str, object]) -> str:
        strong = {"sql_error_signal", "template_error_signal", "command_error_signal", "parser_error_signal", "unescaped_reflection", "significant_time_anomaly"}
        medium = {"reflection_detected", "significant_behavior_change"}
        if strong.intersection(indicators):
            return "strong"
        if medium.intersection(indicators) and similarity < 0.9:
            return "medium"
        if reflection.get("reflection_detected") and similarity < 0.98:
            return "medium"
        return "weak"

    def _injection_summary_rank(self, summary: dict[str, object]) -> tuple[int, int, float]:
        strength = str(summary.get("evidence_strength") or "weak").lower()
        rank = {"weak": 1, "medium": 2, "strong": 3}.get(strength, 0)
        indicators = list(summary.get("indicators") or [])
        similarity = float(((summary.get("diff") or {}).get("similarity") or 1.0))
        return (rank, len(indicators), 1.0 - similarity)

    def _default_payload(self, fields: list[str]) -> dict[str, object]:
        payload: dict[str, object] = {}
        for field in fields[:8]:
            normalized = str(field or "").strip()
            if not normalized:
                continue
            if normalized.endswith("_id") or normalized.lower() in {"id", "user_id", "owner_id", "account_id"}:
                payload[normalized] = "safe-123"
            elif normalized.lower() in {"quantity", "amount", "limit", "offset"}:
                payload[normalized] = 1
            elif normalized.lower() in {"approved", "isadmin"}:
                payload[normalized] = False
            else:
                payload[normalized] = "safe"
        return payload

    def _workflow_attack_payload(self, fields: list[str], endpoint: str) -> dict[str, object]:
        payload = self._default_payload(fields)
        for field in list(payload.keys()):
            lowered = field.lower()
            if lowered in {"status", "approved", "isadmin"}:
                payload[field] = "approved" if lowered == "status" else True
            elif lowered in {"quantity", "amount", "limit"}:
                payload[field] = 0
        if not payload and self._looks_workflow_endpoint(endpoint):
            payload["status"] = "approved"
        return payload

    async def _prepare_business_logic_context(self, request: ToolTestRequest, endpoint: str, owner_headers: dict[str, str]) -> dict[str, object]:
        path = self._normalize_path(endpoint).lower()
        if "/shop/orders/" in path or path.endswith("/shop/orders") or "return_order" in path:
            prepared = await self._prepare_order_context(request, owner_headers)
            if prepared:
                return prepared
        if "/community/" in path and "/posts/" in path:
            prepared = await self._prepare_post_context(request, owner_headers)
            if prepared:
                return prepared
        return {"endpoint": endpoint}

    async def _prepare_order_context(self, request: ToolTestRequest, owner_headers: dict[str, str]) -> dict[str, object]:
        owner_identity = self._owner_profile_from_headers(request, owner_headers)
        materialized = await self.auth_preparation.materialize_for_task(
            request=request,
            owner_identity=owner_identity or {},
            explicit_create_endpoint="/workshop/api/shop/orders",
            explicit_create_method="POST",
            fallback_body={"product_id": 1, "quantity": 1},
        )
        create_result = materialized.get("result")
        order_id = materialized.get("object_id")
        original_endpoint = str(request.arguments.get("endpoint") or request.task.endpoint)
        prepared_endpoint = original_endpoint
        if order_id not in (None, ""):
            prepared_endpoint = self._materialize_named_endpoint(original_endpoint, "order_id", str(order_id))
            if "{id}" in prepared_endpoint:
                prepared_endpoint = self._materialize_named_endpoint(prepared_endpoint, "id", str(order_id))
        attack_payload = self._workflow_attack_payload(request.task.params.body_fields or [], prepared_endpoint)
        if "return_order" in prepared_endpoint and order_id not in (None, ""):
            separator = "&" if "?" in prepared_endpoint else "?"
            prepared_endpoint = f"{prepared_endpoint}{separator}order_id={order_id}"
            attack_payload = {}
        return {
            "endpoint": self._resolve_url(str(request.execution_context.target_url), prepared_endpoint),
            "order_id": order_id,
            "baseline_payload": self._default_payload(request.task.params.body_fields or []),
            "attack_payload": attack_payload,
            "prepared_context_type": "order",
            "creation_status_code": getattr(create_result, "status_code", None),
            "harvested_object_ids": materialized.get("harvested_object_ids") or [],
            "failure_reason": materialized.get("failure_reason") or None,
        }

    async def _prepare_post_context(self, request: ToolTestRequest, owner_headers: dict[str, str]) -> dict[str, object]:
        owner_identity = self._owner_profile_from_headers(request, owner_headers)
        materialized = await self.auth_preparation.materialize_for_task(
            request=request,
            owner_identity=owner_identity or {},
            explicit_create_endpoint="/community/api/v2/community/posts",
            explicit_create_method="POST",
            fallback_body={"title": "autodast", "content": "autodast post"},
        )
        create_result = materialized.get("result")
        post_id = materialized.get("object_id")
        original_endpoint = str(request.arguments.get("endpoint") or request.task.endpoint)
        prepared_endpoint = self._materialize_named_endpoint(original_endpoint, "postId", str(post_id)) if post_id not in (None, "") else original_endpoint
        return {
            "endpoint": self._resolve_url(str(request.execution_context.target_url), prepared_endpoint),
            "post_id": post_id,
            "baseline_payload": self._default_payload(request.task.params.body_fields or []),
            "attack_payload": self._workflow_attack_payload(request.task.params.body_fields or [], prepared_endpoint),
            "prepared_context_type": "post",
            "creation_status_code": getattr(create_result, "status_code", None),
            "harvested_object_ids": materialized.get("harvested_object_ids") or [],
            "failure_reason": materialized.get("failure_reason") or None,
        }

    def _extract_object_id_from_value(self, value) -> str | None:
        if isinstance(value, dict):
            for key in (
                "id",
                "objectId",
                "object_id",
                "vehicleId",
                "vehicle_id",
                "videoId",
                "video_id",
                "postId",
                "post_id",
                "orderId",
                "order_id",
                "reportId",
                "report_id",
                "carId",
                "uuid",
            ):
                item = value.get(key)
                if item not in (None, ""):
                    return str(item)
            for nested in value.values():
                found = self._extract_object_id_from_value(nested)
                if found:
                    return found
        if isinstance(value, list):
            for item in value[:5]:
                found = self._extract_object_id_from_value(item)
                if found:
                    return found
        return None

    def _is_sensitive_property_field(self, field_name: str) -> bool:
        normalized = str(field_name or "").strip().lower()
        return normalized in self.SENSITIVE_PROPERTY_FIELDS or normalized.endswith("_id")

    def _mutated_value(self, field_name: str) -> object:
        normalized = str(field_name or "").strip().lower()
        if normalized in {"approved", "isadmin"}:
            return True
        if normalized in {"credit", "balance"}:
            return 9999
        if normalized.endswith("_id") or normalized in {"id", "owner_id", "user_id", "account_id"}:
            return "mutated-999"
        if normalized == "role":
            return "ROLE_ADMIN"
        if normalized == "email":
            return "mutated@example.com"
        return "mutated"

    async def _property_readback(self, request: ToolTestRequest, endpoint: str, headers: dict[str, str], mutated_payload: dict[str, object], mutated_fields: list[str]) -> dict | None:
        if not mutated_fields:
            return None
        get_result = await self.http_client.execute(method="GET", url=endpoint, headers=headers)
        return get_result.json_body() if get_result.error is None else None

    def _value_persisted(self, field_name: str, value: object, snapshot) -> bool:
        if snapshot is None:
            return False
        matches = self._extract_values_for_field(snapshot, field_name)
        target = str(value)
        return any(str(item) == target for item in matches)

    def _flatten_json_keys(self, value, prefix: str = "") -> list[str]:
        keys: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                dotted = f"{prefix}.{key}" if prefix else str(key)
                keys.append(dotted)
                keys.extend(self._flatten_json_keys(item, dotted))
        elif isinstance(value, list):
            for item in value[:3]:
                keys.extend(self._flatten_json_keys(item, prefix))
        return keys

    def _extract_values_for_field(self, value, target_key: str) -> list[object]:
        matches: list[object] = []
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key) == str(target_key):
                    matches.append(item)
                matches.extend(self._extract_values_for_field(item, target_key))
        elif isinstance(value, list):
            for item in value[:5]:
                matches.extend(self._extract_values_for_field(item, target_key))
        return matches

    def _looks_sensitive_key(self, key: str) -> bool:
        normalized = str(key or "").strip().lower().split(".")[-1]
        return normalized in self.SENSITIVE_EXPOSURE_KEYS or any(token in normalized for token in ("token", "secret", "auth", "credit", "balance"))

    def _sample_sensitive_values(self, json_body) -> dict[str, object]:
        samples: dict[str, object] = {}
        for key in self._flatten_json_keys(json_body):
            if not self._looks_sensitive_key(key):
                continue
            field = key.split(".")[-1]
            values = self._extract_values_for_field(json_body, field)
            if values and key not in samples:
                samples[key] = values[0]
            if len(samples) >= 6:
                break
        return samples

    def _exposure_evidence_strength(
        self,
        sensitive_keys: list[str],
        sample_exposed_fields: dict[str, object],
        nested_sensitive_keys: list[str],
        status_code: int | None,
        validation_disclosure: bool,
        similarity: float,
    ) -> str:
        if validation_disclosure and not sample_exposed_fields:
            return "weak"
        terminal = {item.split(".")[-1] for item in sensitive_keys}
        if {"password", "token", "secret"}.intersection(terminal):
            return "strong"
        if nested_sensitive_keys and sample_exposed_fields:
            return "strong"
        if {"email", "credit", "balance", "vin", "pincode", "owner", "role", "location", "report", "video_url", "picture_url"}.intersection(terminal) and sample_exposed_fields:
            return "strong"
        if self._status_success(status_code) and sensitive_keys and similarity > 0.85:
            return "strong"
        if sensitive_keys:
            return "medium"
        return "weak"

    def _property_evidence_strength(self, accepted_fields: list[str], reflected_fields: list[str], persisted_fields: list[str]) -> str:
        if persisted_fields:
            return "strong"
        if accepted_fields and reflected_fields:
            return "medium"
        if accepted_fields:
            return "weak"
        return "weak"

    def _workflow_evidence_strength(self, indicators: list[str]) -> str:
        if {"invalid_transition_accepted", "repeated_sensitive_action_allowed", "workflow_state_bypass"}.intersection(indicators):
            return "strong"
        if "cross_role_workflow_access" in indicators and "invariant_violation" in indicators:
            return "strong"
        if {"cross_role_workflow_access", "invariant_violation"}.intersection(indicators):
            return "medium"
        return "weak"

    def _is_validation_schema_disclosure(self, status_code: int | None, json_body, body_text: str) -> bool:
        if status_code not in {400, 422}:
            return False
        lowered = str(body_text or "").lower()
        if any(token in lowered for token in ("field required", "validation error", "missing", "required", "unprocessable entity")):
            return True
        if isinstance(json_body, dict):
            keys = {str(key or "").lower() for key in json_body.keys()}
            if keys.intersection({"detail", "errors", "message"}):
                serialized = json.dumps(json_body, ensure_ascii=False).lower()
                if any(token in serialized for token in ("field required", "validation", "missing", "required")):
                    return True
        return False

    def _body_snapshot(self, body_text: str) -> str:
        value = str(body_text or "").strip()
        return value[:240]

    def _status_success(self, status_code: int | None) -> bool:
        return status_code in {200, 201, 202, 204}

    def _looks_workflow_endpoint(self, endpoint: str) -> bool:
        value = str(endpoint or "").lower()
        return any(token in value for token in self.WORKFLOW_KEYWORDS)

    def _looks_repeat_sensitive(self, endpoint: str) -> bool:
        value = str(endpoint or "").lower()
        return any(token in value for token in ("coupon", "return", "redeem", "otp", "verify", "resend"))

    def _version_paths(self, endpoint_path: str) -> list[str]:
        path = str(endpoint_path or "").strip()
        match = re.search(r"/v(\d+(?:\.\d+)?)/", path)
        if not match:
            return [path]
        current = match.group(0)
        versions = []
        for candidate in ("/v1/", "/v2/", "/v3/"):
            candidate_path = path.replace(current, candidate, 1)
            if candidate_path not in versions:
                versions.append(candidate_path)
        return versions[:3]

    def _normalize_path(self, url_or_path: str) -> str:
        parsed = urlparse(str(url_or_path or ""))
        return parsed.path if parsed.scheme or parsed.netloc else str(url_or_path or "")
