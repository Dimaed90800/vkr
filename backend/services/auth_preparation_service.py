import ipaddress
import json
import os
import re
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen

try:
    from backend.models.testing import Artifact, ToolTestRequest, ToolTestResponse
    from backend.services.diagnostic_logging_service import DiagnosticLoggingService
    from backend.services.http_client import HttpClient, HttpExecutionResult
    from backend.services.openapi_baseline_synthesis_service import OpenApiBaselineSynthesisService
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import Artifact, ToolTestRequest, ToolTestResponse
    from services.diagnostic_logging_service import DiagnosticLoggingService
    from services.http_client import HttpClient, HttpExecutionResult
    from services.openapi_baseline_synthesis_service import OpenApiBaselineSynthesisService


class AuthPreparationService:
    DEFAULT_AUTH_PROBE_SUFFIXES = [
        "/auth/login",
        "/auth/register",
        "/login",
        "/register",
        "/signup",
        "/signin",
    ]
    COMMON_REGISTER_ENDPOINTS = [
        "/identity/api/auth/signup",
        "/api/register",
        "/register",
        "/signup",
    ]
    COMMON_LOGIN_ENDPOINTS = [
        "/identity/api/auth/login",
        "/api/login",
        "/login",
        "/signin",
    ]
    CRAPI_AUTH_ENDPOINTS = {
        "register": ["/identity/api/auth/signup"],
        "login": ["/identity/api/auth/login"],
    }

    def __init__(self, http_client: HttpClient | None = None) -> None:
        self.http_client = http_client or HttpClient()
        self.playwright_runner_url = str(os.getenv("PLAYWRIGHT_RUNNER_URL") or "").strip()
        self.baseline_synthesis = OpenApiBaselineSynthesisService()
        self.diagnostics = DiagnosticLoggingService()
        self._openapi_cache: dict[str, str] = {}

    async def probe_entrypoints(self, request: ToolTestRequest) -> ToolTestResponse:
        args = dict(request.arguments or {})
        methods = [str(item or "").upper() for item in (args.get("methods") or ["GET", "POST"]) if str(item or "").strip()]
        methods = [item for item in methods if item in {"GET", "POST"}] or ["GET", "POST"]
        base_paths = [str(item or "").strip() for item in (args.get("base_paths") or []) if str(item or "").strip()]
        if not base_paths:
            base_paths = self._default_probe_base_paths(request)
        candidate_suffixes = [str(item or "").strip() for item in (args.get("candidate_suffixes") or self.DEFAULT_AUTH_PROBE_SUFFIXES) if str(item or "").strip()]
        max_budget = max(1, min(int(request.execution_context.max_requests or 20), 20))

        discovered_auth_endpoints: list[dict[str, Any]] = []
        attempts = 0
        for base_path in base_paths:
            normalized_base = "/" + "/".join(part for part in str(base_path).split("/") if part)
            for suffix in candidate_suffixes:
                suffix_path = "/" + "/".join(part for part in str(suffix).split("/") if part)
                probe_path = self._join_paths(normalized_base, suffix_path)
                for method in methods:
                    if attempts >= max_budget:
                        break
                    attempts += 1
                    request_url = self._resolve_url(str(request.execution_context.target_url), probe_path)
                    self._validate_scope(request, request_url)
                    result = await self.http_client.execute(
                        method=method,
                        url=request_url,
                        headers={"Accept": "application/json"},
                    )
                    if self._looks_like_auth_endpoint(result):
                        endpoint_type = self._endpoint_type_from_path(probe_path)
                        if endpoint_type:
                            item = {"type": endpoint_type, "path": probe_path, "method": method}
                            if item not in discovered_auth_endpoints:
                                discovered_auth_endpoints.append(item)
                if attempts >= max_budget:
                    break
            if attempts >= max_budget:
                break

        raw_status = "success" if discovered_auth_endpoints else ("partial" if attempts > 0 else "failed")
        indicators = ["auth_endpoint_detected"] if discovered_auth_endpoints else ["auth_entrypoint_probe_empty"]
        return ToolTestResponse(
            request_summary={
                "action": "auth_probe_entrypoints",
                "base_paths": base_paths,
                "candidate_suffixes": candidate_suffixes,
                "methods": methods,
                "attempt_total": attempts,
            },
            response_summary={
                "discovered_auth_endpoint_total": len(discovered_auth_endpoints),
            },
            raw_status=raw_status,
            indicators=indicators,
            artifacts=[
                Artifact(type="discovered_auth_endpoints", value=discovered_auth_endpoints),
            ],
        )

    async def auto_provision(self, request: ToolTestRequest) -> ToolTestResponse:
        args = dict(request.arguments or {})
        identity_count = max(1, min(int(args.get("identity_count") or 2), 2))
        register_method = str(args.get("register_method") or "POST").upper()
        login_method = str(args.get("login_method") or "POST").upper()
        register_operations = self._best_auth_operations(
            request=request,
            endpoint_type="register",
            explicit_endpoint=args.get("register_endpoint"),
            explicit_method=register_method,
        )
        login_operations = self._best_auth_operations(
            request=request,
            endpoint_type="login",
            explicit_endpoint=args.get("login_endpoint"),
            explicit_method=login_method,
        )
        openapi_spec_text = self._spec_text_for_request(request)
        openapi_context = {
            "has_openapi_url": bool(str(request.execution_context.openapi_url or "").strip()),
            "has_openapi_spec_text": bool(str(request.execution_context.openapi_spec_text or "").strip()),
            "has_resolved_openapi_spec_text": bool(str(openapi_spec_text or "").strip()),
        }
        if openapi_context["has_openapi_spec_text"]:
            openapi_context["source_of_openapi_context"] = "execution_context.openapi_spec_text"
        elif openapi_context["has_openapi_url"] and openapi_context["has_resolved_openapi_spec_text"]:
            openapi_context["source_of_openapi_context"] = "execution_context.openapi_url"
        elif openapi_context["has_openapi_url"]:
            openapi_context["source_of_openapi_context"] = "execution_context.openapi_url_unreadable"
        else:
            openapi_context["source_of_openapi_context"] = "missing"
        self._emit_prep_event(
            request=request,
            event_type="auth_openapi_context_received" if openapi_context["has_resolved_openapi_spec_text"] else "auth_openapi_context_missing",
            status="ok" if openapi_context["has_resolved_openapi_spec_text"] else "partial",
            summary="Auth preparation inspected OpenAPI context.",
            artifacts=openapi_context,
        )
        register_endpoints = [str(item.get("path") or "") for item in register_operations if str(item.get("path") or "")]
        login_endpoints = [str(item.get("path") or "") for item in login_operations if str(item.get("path") or "")]
        identities = [self._build_identity_seed(request, index) for index in range(identity_count)]

        self._emit_prep_event(
            request=request,
            event_type="auth_provision_start",
            status="ok",
            summary="Starting auth auto-provision bootstrap.",
            counters={"identity_count": identity_count},
            artifacts={
                **openapi_context,
                "register_endpoint_candidates": self._operation_log_items(register_operations[:5]),
                "login_endpoint_candidates": self._operation_log_items(login_operations[:5]),
            },
        )
        register_attempts: list[dict[str, Any]] = []
        login_attempts: list[dict[str, Any]] = []
        provisioned: list[dict[str, Any]] = []
        register_success_total = 0
        login_success_total = 0
        usable_identity_total = 0
        failure_reasons: list[str] = []

        register_endpoint_used = ""
        login_endpoint_used = ""
        registration_available = bool(register_operations)
        login_available = bool(login_operations)
        registration_unavailable_reason = None if registration_available else "no_register_endpoint"
        login_unavailable_reason = None if login_available else "no_login_endpoint"
        if registration_unavailable_reason:
            failure_reasons.append(registration_unavailable_reason)
        if login_unavailable_reason:
            failure_reasons.append(login_unavailable_reason)

        for identity in identities:
            if registration_available:
                register_result, register_endpoint_used = await self._attempt_registration(
                    request=request,
                    identity=identity,
                    endpoint_type="register",
                    operations=register_operations,
                )
                if self._is_success(register_result.status_code):
                    register_success_total += 1
                    registration_identity = self._authenticated_identity_from_result(
                        identity,
                        register_result,
                        fallback_cookies={},
                    )
                    self._emit_prep_event(
                        request=request,
                        event_type="auth_provision_identity_created",
                        status="success",
                        summary=f"Created auth identity {identity['name']}.",
                        artifacts={
                            "identity_name": identity["name"],
                            "role": identity.get("role"),
                            "aliases": identity.get("aliases") or [],
                            "endpoint": register_endpoint_used,
                            "status_code": register_result.status_code,
                        },
                    )
                else:
                    registration_identity = dict(identity)
                    if register_result.error or register_result.status_code is not None:
                        failure_reasons.append("registration_failed")
            else:
                register_result = HttpExecutionResult(
                    method=register_method,
                    url="",
                    status_code=None,
                    headers={},
                    body_text="",
                    elapsed_ms=None,
                    error="no_register_endpoint",
                )
                registration_identity = dict(identity)
            register_attempts.append(
                {
                    "identity_name": identity["name"],
                    "endpoint": register_endpoint_used,
                    "status_code": register_result.status_code,
                    "error": register_result.error,
                }
            )

            if login_available:
                login_result, login_endpoint_used, authenticated_identity = await self._attempt_login(
                    request=request,
                    identity=identity,
                    endpoint_type="login",
                    operations=login_operations,
                    fallback_cookies=self._extract_cookies(register_result.headers),
                )
            else:
                login_result = HttpExecutionResult(
                    method=login_method,
                    url="",
                    status_code=None,
                    headers={},
                    body_text="",
                    elapsed_ms=None,
                    error="no_login_endpoint",
                )
                authenticated_identity = registration_identity
            login_attempts.append(
                {
                    "identity_name": identity["name"],
                    "endpoint": login_endpoint_used,
                    "status_code": login_result.status_code,
                    "error": login_result.error,
                }
            )
            login_succeeded = self._is_success(login_result.status_code)
            if login_succeeded and self._has_auth_material(authenticated_identity):
                login_success_total += 1
                self._emit_prep_event(
                    request=request,
                    event_type="auth_provision_login_success",
                    status="success",
                    summary=f"Authenticated provisioned identity {identity['name']}.",
                    artifacts={
                        "identity_name": identity["name"],
                        "role": authenticated_identity.get("role"),
                        "aliases": authenticated_identity.get("aliases") or [],
                        "endpoint": login_endpoint_used,
                        "status_code": login_result.status_code,
                        "auth_material": self._auth_material_summary(authenticated_identity),
                    },
                )
            elif login_succeeded and not self._has_auth_material(authenticated_identity):
                failure_reasons.append("token_missing")
            elif login_available and (login_result.error or login_result.status_code is not None):
                failure_reasons.append("login_failed")

            if not self._has_auth_material(authenticated_identity) and self._has_auth_material(registration_identity):
                authenticated_identity = registration_identity

            if self._has_auth_material(authenticated_identity):
                authenticated_identity = self._normalize_provisioned_identity(authenticated_identity, identity)
                provisioned.append(authenticated_identity)
                usable_identity_total += 1

        raw_status = self._aggregate_status(
            expected_total=identity_count,
            register_success_total=register_success_total,
            login_success_total=usable_identity_total,
        )
        indicators = []
        if usable_identity_total >= 2:
            indicators.append("auto_provision_success")
        elif provisioned:
            indicators.append("auto_provision_partial")
        else:
            indicators.append("auto_provision_failed")
        if not registration_available:
            indicators.append("no_register_endpoint")
        if not login_available:
            indicators.append("no_login_endpoint")
        for reason in dict.fromkeys(failure_reasons):
            if reason and reason not in indicators:
                indicators.append(reason)
        if self.playwright_runner_url:
            indicators.append("playwright_runner_available")
        finish_status = "success" if usable_identity_total >= identity_count else "partial" if usable_identity_total else "failed"
        finish_event = "auth_provision_finish" if usable_identity_total else "auth_provision_failed"
        self._emit_prep_event(
            request=request,
            event_type=finish_event,
            status=finish_status,
            summary=f"Auth auto-provision finished with {usable_identity_total}/{identity_count} usable identities.",
            reason={"failure_reasons": list(dict.fromkeys(failure_reasons))},
            counters={
                "identity_count": identity_count,
                "usable_identity_total": usable_identity_total,
                "login_success_total": login_success_total,
                "register_success_total": register_success_total,
            },
            artifacts={
                "provisioned_roles": [
                    {
                        "name": item.get("name"),
                        "role": item.get("role"),
                        "aliases": item.get("aliases") or [],
                        "auth_material": self._auth_material_summary(item),
                    }
                    for item in provisioned
                ],
            },
        )

        return ToolTestResponse(
            request_summary={
                "action": "auto_provision",
                "register_endpoint": register_endpoint_used,
                "login_endpoint": login_endpoint_used,
                "register_method": register_method,
                "login_method": login_method,
                "identity_count": identity_count,
            },
            response_summary={
                "provisioned_identity_total": len(provisioned),
                "login_success_total": login_success_total,
                "register_success_total": register_success_total,
                "usable_identity_total": usable_identity_total,
                "registration_available": registration_available,
                "login_available": login_available,
                "registration_unavailable_reason": registration_unavailable_reason,
                "login_unavailable_reason": login_unavailable_reason,
                "failure_reasons": list(dict.fromkeys(failure_reasons)),
                "register_endpoint_candidates": self._operation_log_items(register_operations[:5]),
                "login_endpoint_candidates": self._operation_log_items(login_operations[:5]),
            },
            raw_status=raw_status,
            indicators=indicators,
            identities=provisioned,
            artifacts=[
                Artifact(type="provisioned_identities", value=provisioned),
                Artifact(type="auth_profiles", value=provisioned),
                Artifact(
                    type="preparation_context",
                    value={
                        "register_attempts": register_attempts,
                        "login_attempts": login_attempts,
                    },
                ),
                Artifact(
                    type="playwright_runner_hint",
                    value={"available": bool(self.playwright_runner_url), "url": self.playwright_runner_url or None},
                ),
            ],
        )

    async def create_test_object(self, request: ToolTestRequest) -> ToolTestResponse:
        args = dict(request.arguments or {})
        owner_identity = self._owner_identity(request, args.get("owner_identity"))
        create_method = str(args.get("create_method") or "POST").upper()
        create_endpoint = str(args.get("create_endpoint") or "").strip()
        fallback_body = args.get("fallback_body")
        self._emit_prep_event(
            request=request,
            event_type="object_materialization_start",
            status="ok",
            summary="Starting object materialization.",
            artifacts={
                "create_endpoint": create_endpoint,
                "create_method": create_method,
                "resource_family": self._object_type(request.task.endpoint),
            },
        )

        if not owner_identity:
            self._emit_prep_event(
                request=request,
                event_type="object_materialization_failed",
                status="failed",
                summary="Object materialization failed because no owner identity was available.",
                reason={"failure_reason": "missing_owner_identity"},
            )
            self._emit_prep_event(
                request=request,
                event_type="object_materialization_finish",
                status="failed",
                summary="Object materialization finished without a reusable owner identity.",
                reason={"failure_reason": "missing_owner_identity"},
            )
            return ToolTestResponse(
                request_summary={
                    "action": "create_test_object",
                    "create_endpoint": create_endpoint,
                    "create_method": create_method,
                },
                response_summary={"status_code": None, "object_id": None},
                raw_status="failed",
                indicators=["create_test_object_failed", "missing_owner_identity"],
                artifacts=[Artifact(type="prepared_object", value={"object_id": None})],
            )

        materialized = await self.materialize_for_task(
            request=request,
            owner_identity=owner_identity,
            explicit_create_endpoint=create_endpoint or None,
            explicit_create_method=create_method,
            fallback_body=fallback_body if isinstance(fallback_body, dict) else None,
        )
        create_endpoint = str(materialized.get("create_endpoint") or create_endpoint)
        request_url = str(materialized.get("request_url") or self._resolve_url(str(request.execution_context.target_url), create_endpoint))
        result = materialized.get("result")
        object_id = materialized.get("object_id")
        harvested_ids = list(materialized.get("harvested_object_ids") or [])
        harvested_links = list(materialized.get("harvested_links") or [])
        failure_reason = str(materialized.get("failure_reason") or "")
        self._emit_prep_event(
            request=request,
            event_type="object_materialization_finish",
            status="success" if object_id else "partial" if getattr(result, "status_code", None) else "failed",
            summary=f"Object materialization finished for family={materialized.get('resource_family') or ''}.",
            reason={"failure_reason": failure_reason or None},
            counters={
                "harvested_object_id_count": len(harvested_ids),
                "harvested_link_count": len(harvested_links),
                "total_materialized_objects": 1 if object_id else 0,
            },
            artifacts={
                "resource_family": materialized.get("resource_family"),
                "create_endpoint": create_endpoint,
                "harvested_object_ids": harvested_ids[:5],
                "harvested_links": harvested_links[:5],
            },
        )
        self._emit_prep_event(
            request=request,
            event_type="prep_object_materialization_result",
            status="success" if object_id else "partial" if getattr(result, "status_code", None) else "failed",
            summary=f"Object materialization legacy result for family={materialized.get('resource_family') or ''}.",
            reason={"failure_reason": failure_reason or None},
            counters={
                "harvested_object_id_count": len(harvested_ids),
                "harvested_link_count": len(harvested_links),
                "total_materialized_objects": 1 if object_id else 0,
            },
            artifacts={
                "resource_family": materialized.get("resource_family"),
                "create_endpoint": create_endpoint,
                "harvested_object_ids": harvested_ids[:5],
                "harvested_links": harvested_links[:5],
            },
        )

        raw_status = "success" if self._is_success(getattr(result, "status_code", None)) and object_id else ("partial" if self._is_success(getattr(result, "status_code", None)) else "failed")
        indicators = ["test_object_created"] if object_id else ["create_test_object_failed"]
        if failure_reason:
            indicators.append(failure_reason)
        created_object = {
            "object_id": object_id,
            "object_type": str(materialized.get("object_type") or self._object_type(request.task.endpoint)),
            "owner_identity_name": str(owner_identity.get("name") or "owner"),
            "resource_family": str(materialized.get("resource_family") or ""),
            "creator_identity": {
                "name": str(owner_identity.get("name") or "owner"),
                "email": str(owner_identity.get("email") or ""),
                "username": str(owner_identity.get("username") or ""),
            },
            "replay_ready_endpoint": materialized.get("replay_ready_endpoint"),
            "replay_path_params": materialized.get("replay_path_params") or {},
        } if object_id not in (None, "") else None

        return ToolTestResponse(
            request_summary={
                "action": "create_test_object",
                "create_endpoint": request_url,
                "create_method": create_method,
                "owner_identity_name": str(owner_identity.get("name") or "owner"),
            },
            response_summary={
                "status_code": getattr(result, "status_code", None),
                "object_id": object_id,
                "object_type": str(materialized.get("object_type") or self._object_type(request.task.endpoint)),
                "resource_family": str(materialized.get("resource_family") or ""),
                "harvested_object_ids": harvested_ids,
                "harvested_links": harvested_links,
                "creator_identity": created_object["creator_identity"] if created_object else None,
                "replay_ready_endpoint": materialized.get("replay_ready_endpoint"),
                "replay_path_params": materialized.get("replay_path_params") or {},
                "failure_reason": failure_reason or None,
            },
            raw_status=raw_status,
            indicators=indicators,
            created_object=created_object,
            artifacts=[
                Artifact(type="prepared_object", value=created_object or {"object_id": None, "object_type": str(materialized.get("object_type") or self._object_type(request.task.endpoint))}),
                Artifact(type="harvested_object_ids", value=harvested_ids),
                Artifact(type="harvested_links", value=harvested_links),
                Artifact(
                    type="workflow_context",
                    value={
                        "resource_family": str(materialized.get("resource_family") or ""),
                        "object_id": object_id,
                        "create_endpoint": request_url,
                        "replay_ready_endpoint": materialized.get("replay_ready_endpoint"),
                        "replay_path_params": materialized.get("replay_path_params") or {},
                    },
                ),
                Artifact(
                    type="creation_evidence",
                    value={
                        "status_code": getattr(result, "status_code", None),
                        "location": getattr(result, "headers", {}).get("location") if result else None,
                        "body_preview": (getattr(result, "body_text", "") or "")[:240],
                        "synthesis": materialized.get("synthesis_metadata") or {},
                        "failure_reason": failure_reason or None,
                    },
                ),
            ],
        )

    async def materialize_for_task(
        self,
        *,
        request: ToolTestRequest,
        owner_identity: dict[str, Any],
        explicit_create_endpoint: str | None = None,
        explicit_create_method: str = "POST",
        fallback_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        target_endpoint = str(request.task.endpoint or "")
        spec_text = self._spec_text_for_request(request)
        support = self.baseline_synthesis.endpoint_support_summary(
            spec_text,
            target_endpoint,
            request.task.method,
        )
        self._emit_prep_event(
            request=request,
            event_type="object_materialization_start",
            status="ok",
            summary="Starting deterministic object materialization path.",
            artifacts={
                "target_endpoint": target_endpoint,
                "target_method": request.task.method,
                "resource_family": support.get("resource_family") or self._object_type(target_endpoint),
            },
        )
        self._emit_prep_event(
            request=request,
            event_type="prep_baseline_synthesized",
            status="ok",
            summary="Generated spec-driven baseline/materialization support.",
            artifacts={
                "resource_family": support.get("resource_family"),
                "creator_candidates": support.get("creator_candidates") or [],
                "list_candidates": support.get("list_candidates") or [],
                "success_path_feasibility": support.get("success_path_feasibility"),
            },
        )
        resource_family = str(support.get("resource_family") or self._object_type(target_endpoint))
        replay_path_params = self._replay_path_params(request, target_endpoint, None)
        reused = self._reuse_materialized_context(request, resource_family)
        if reused["object_id"]:
            replay_path_params = self._replay_path_params(request, target_endpoint, reused["object_id"])
            self._emit_prep_event(
                request=request,
                event_type="object_materialization_attempted",
                status="ok",
                summary=f"Attempting object materialization for family={resource_family} using reusable context.",
                artifacts={
                    "resource_family": resource_family,
                    "strategy": "reuse_harvested",
                    "candidate_paths": [],
                    "selected_candidate": reused["source"],
                },
            )
            self._emit_prep_event(
                request=request,
                event_type="object_materialization_id_harvested",
                status="success",
                summary=f"Object materialization reused existing object id for family={resource_family}.",
                counters={"total_materialized_objects": 1, "total_harvested_ids": len(reused['harvested_object_ids'])},
                artifacts={"resource_family": resource_family, "object_id": reused["object_id"], "source": reused["source"]},
            )
            self._emit_prep_event(
                request=request,
                event_type="object_materialization_finish",
                status="success",
                summary=f"Object materialization reused existing object id for family={resource_family}.",
                counters={"total_materialized_objects": 1, "total_harvested_ids": len(reused['harvested_object_ids'])},
                artifacts={"resource_family": resource_family, "object_id": reused["object_id"], "source": reused["source"]},
            )
            self._emit_prep_event(
                request=request,
                event_type="object_materialization_succeeded",
                status="success",
                summary=f"Object materialization reused existing object id for family={resource_family}.",
                counters={"total_materialized_objects": 1, "total_harvested_ids": len(reused['harvested_object_ids'])},
                artifacts={"resource_family": resource_family, "object_id": reused["object_id"], "source": reused["source"]},
            )
            return {
                "result": HttpExecutionResult(method="GET", url="", status_code=200, headers={}, body_text="", elapsed_ms=None, error=None),
                "request_url": "",
                "create_endpoint": "",
                "object_id": reused["object_id"],
                "harvested_object_ids": reused["harvested_object_ids"],
                "harvested_links": reused["harvested_links"],
                "resource_family": resource_family,
                "object_type": self._object_type(target_endpoint),
                "replay_ready_endpoint": self._replay_ready_endpoint(request, target_endpoint, replay_path_params),
                "replay_path_params": replay_path_params,
                "synthesis_metadata": {"source": reused["source"]},
                "failure_reason": "",
                "source": reused["source"],
            }
        create_candidates = []
        if explicit_create_endpoint:
            create_candidates.append({"path": explicit_create_endpoint, "method": str(explicit_create_method or "POST").upper()})
        create_candidates.extend(support.get("creator_candidates") or [])
        inferred_create_endpoint = ""
        if not create_candidates:
            inferred_create_endpoint = self._infer_create_endpoint(target_endpoint)
            if inferred_create_endpoint:
                create_candidates.append({"path": inferred_create_endpoint, "method": str(explicit_create_method or "POST").upper()})
        list_candidates = list(support.get("list_candidates") or [])
        if not list_candidates:
            inferred_list_endpoint = self._infer_list_endpoint(target_endpoint)
            if inferred_list_endpoint:
                list_candidates.append({"path": inferred_list_endpoint, "method": "GET"})

        if list_candidates:
            self._emit_prep_event(
                request=request,
                event_type="object_materialization_attempted",
                status="ok",
                summary=f"Attempting list-based object materialization for family={resource_family}.",
                artifacts={
                    "resource_family": resource_family,
                    "strategy": "list_then_select",
                    "candidate_paths": [str(item.get('path') or '') for item in list_candidates[:3]],
                    "selected_candidate": str((list_candidates[0] or {}).get('path') or '') if list_candidates else "",
                },
            )
            harvested_from_list = await self._harvest_from_list_candidates(
                request=request,
                owner_identity=owner_identity,
                list_candidates=list_candidates,
                resource_family=resource_family,
            )
            if harvested_from_list["object_id"]:
                self._emit_prep_event(
                    request=request,
                    event_type="object_materialization_list_success",
                    status="success",
                    summary=f"List-based object materialization succeeded for family={resource_family}.",
                    counters={"total_materialized_objects": 1, "total_harvested_ids": len(harvested_from_list['harvested_object_ids'])},
                    artifacts={"resource_family": resource_family, "object_id": harvested_from_list["object_id"], "source": "harvested_from_list"},
                )
                self._emit_prep_event(
                    request=request,
                    event_type="object_materialization_finish",
                    status="success",
                    summary=f"List-based object materialization finished for family={resource_family}.",
                    counters={"total_materialized_objects": 1, "total_harvested_ids": len(harvested_from_list['harvested_object_ids'])},
                    artifacts={"resource_family": resource_family, "object_id": harvested_from_list["object_id"], "source": "harvested_from_list"},
                )
                self._emit_prep_event(
                    request=request,
                    event_type="object_materialization_succeeded",
                    status="success",
                    summary=f"List-based object materialization succeeded for family={resource_family}.",
                    counters={"total_materialized_objects": 1, "total_harvested_ids": len(harvested_from_list['harvested_object_ids'])},
                    artifacts={"resource_family": resource_family, "object_id": harvested_from_list["object_id"], "source": "harvested_from_list"},
                )
                return {
                    "result": HttpExecutionResult(method="GET", url="", status_code=200, headers={}, body_text="", elapsed_ms=None, error=None),
                    "request_url": "",
                    "create_endpoint": "",
                    "object_id": harvested_from_list["object_id"],
                    "harvested_object_ids": harvested_from_list["harvested_object_ids"],
                    "harvested_links": harvested_from_list["harvested_links"],
                    "resource_family": resource_family,
                    "object_type": self._object_type(target_endpoint),
                    "replay_ready_endpoint": self._replay_ready_endpoint(
                        request,
                        target_endpoint,
                        self._replay_path_params(request, target_endpoint, harvested_from_list["object_id"]),
                    ),
                    "replay_path_params": self._replay_path_params(request, target_endpoint, harvested_from_list["object_id"]),
                    "synthesis_metadata": {"source": "harvested_from_list"},
                    "failure_reason": "",
                    "source": "harvested_from_list",
                }

        headers = self._identity_headers(owner_identity)
        last_result = HttpExecutionResult(method=explicit_create_method, url="", status_code=None, headers={}, body_text="", elapsed_ms=None, error="object_creation_not_attempted")
        failure_reason = "materialization_failed"
        synthesis_metadata: dict[str, Any] = {}
        request_url = ""
        self._emit_prep_event(
            request=request,
            event_type="object_materialization_attempted",
            status="ok",
            summary=f"Attempting create-based object materialization for family={resource_family}.",
            artifacts={
                "resource_family": resource_family,
                "strategy": "create_then_harvest",
                "candidate_paths": [str(item.get('path') or '') for item in create_candidates[:3]],
                "selected_candidate": str((create_candidates[0] or {}).get('path') or '') if create_candidates else "",
            },
        )
        for candidate in create_candidates[:3]:
            candidate_path = str(candidate.get("path") or "").strip()
            candidate_method = str(candidate.get("method") or explicit_create_method or "POST").upper()
            self._emit_prep_event(
                request=request,
                event_type="object_materialization_creator_selected",
                status="ok",
                summary=f"Selected creator candidate {candidate_method} {candidate_path}.",
                artifacts={"resource_family": resource_family, "candidate_path": candidate_path, "candidate_method": candidate_method},
            )
            self._emit_prep_event(
                request=request,
                event_type="creator_candidate_selected",
                status="ok",
                summary=f"Selected creator candidate {candidate_method} {candidate_path}.",
                artifacts={"resource_family": resource_family, "candidate_path": candidate_path, "candidate_method": candidate_method},
            )
            synthesis = self.baseline_synthesis.synthesize_request(
                spec_text=str(request.execution_context.openapi_spec_text or ""),
                endpoint_path=candidate_path,
                method=candidate_method,
                known_values={
                    "email": owner_identity.get("email"),
                    "ownerName": owner_identity.get("name"),
                    "name": owner_identity.get("name"),
                },
            )
            body = fallback_body if isinstance(fallback_body, dict) else synthesis.get("baseline_body")
            query_params = synthesis.get("baseline_query") or None
            materialized_path = self._materialize_from_values(candidate_path, synthesis.get("baseline_path") or {})
            request_url = self._resolve_url(str(request.execution_context.target_url), materialized_path)
            self._validate_scope(request, request_url)
            last_result = await self.http_client.execute(
                method=candidate_method,
                url=request_url,
                headers=headers,
                query_params=query_params,
                json_body=body or None,
            )
            synthesis_metadata = synthesis.get("synthesis_metadata") or {}
            harvested = self.baseline_synthesis.harvest_response(last_result.json_body(), last_result.headers)
            harvested = self._merge_harvested_candidates(harvested, last_result.json_body())
            object_id = self._extract_object_id(last_result)
            if object_id is None and self._looks_like_vehicle_create(candidate_path):
                object_id = await self._fetch_latest_vehicle_id(request, owner_identity)
                if object_id and object_id not in harvested["harvested_object_ids"]:
                    harvested["harvested_object_ids"].insert(0, object_id)
            if object_id is None and self._is_success(last_result.status_code):
                harvested_from_list = await self._harvest_from_list_candidates(
                    request=request,
                    owner_identity=owner_identity,
                    list_candidates=list_candidates,
                    resource_family=resource_family,
                )
                if harvested_from_list["object_id"]:
                    object_id = harvested_from_list["object_id"]
                    for harvested_id in harvested_from_list["harvested_object_ids"]:
                        if harvested_id not in harvested["harvested_object_ids"]:
                            harvested["harvested_object_ids"].append(harvested_id)
                    for harvested_link in harvested_from_list["harvested_links"]:
                        if harvested_link not in harvested["harvested_links"]:
                            harvested["harvested_links"].append(harvested_link)
            if self._is_success(last_result.status_code) and object_id:
                replay_path_params = self._replay_path_params(request, target_endpoint, object_id)
                self._emit_prep_event(
                    request=request,
                    event_type="object_materialization_id_harvested",
                    status="success",
                    summary=f"Materialized object id for family={resource_family}.",
                    counters={"harvested_object_id_count": len(harvested["harvested_object_ids"])},
                    artifacts={"resource_family": resource_family, "harvested_object_ids": harvested["harvested_object_ids"][:5]},
                )
                self._emit_prep_event(
                    request=request,
                    event_type="harvested_object_id_propagated",
                    status="success",
                    summary=f"Materialized object id for family={resource_family}.",
                    counters={"harvested_object_id_count": len(harvested["harvested_object_ids"])},
                    artifacts={"resource_family": resource_family, "harvested_object_ids": harvested["harvested_object_ids"][:5]},
                )
                self._emit_prep_event(
                    request=request,
                    event_type="object_materialization_create_success",
                    status="success",
                    summary=f"Create-based object materialization succeeded for family={resource_family}.",
                    counters={"total_materialized_objects": 1, "total_harvested_ids": len(harvested['harvested_object_ids'])},
                    artifacts={"resource_family": resource_family, "object_id": object_id, "source": "harvested_from_create"},
                )
                self._emit_prep_event(
                    request=request,
                    event_type="object_materialization_finish",
                    status="success",
                    summary=f"Object materialization finished for family={resource_family}.",
                    counters={"total_materialized_objects": 1, "total_harvested_ids": len(harvested['harvested_object_ids'])},
                    artifacts={"resource_family": resource_family, "object_id": object_id, "source": "harvested_from_create"},
                )
                self._emit_prep_event(
                    request=request,
                    event_type="object_materialization_succeeded",
                    status="success",
                    summary=f"Object materialization succeeded for family={resource_family}.",
                    counters={"total_materialized_objects": 1, "total_harvested_ids": len(harvested['harvested_object_ids'])},
                    artifacts={"resource_family": resource_family, "object_id": object_id, "source": "harvested_from_create"},
                )
                return {
                    "result": last_result,
                    "request_url": request_url,
                    "create_endpoint": candidate_path,
                    "object_id": object_id,
                    "harvested_object_ids": harvested["harvested_object_ids"],
                    "harvested_links": harvested["harvested_links"],
                    "resource_family": resource_family,
                    "object_type": self._object_type(target_endpoint),
                    "replay_ready_endpoint": self._replay_ready_endpoint(request, target_endpoint, replay_path_params),
                    "replay_path_params": replay_path_params,
                    "synthesis_metadata": synthesis_metadata,
                    "failure_reason": "",
                    "source": "harvested_from_create",
                }
            if last_result.status_code in {400, 422}:
                failure_reason = self._stable_materialization_failure(synthesis.get("structured_failure_reason") or "success_path_not_reachable")
            elif not self._is_success(last_result.status_code):
                failure_reason = "create_failed" if create_candidates else "no_creator_candidate"
            elif self._is_success(last_result.status_code):
                failure_reason = "id_not_harvested" if list_candidates else "no_list_candidate"

        harvested = self.baseline_synthesis.harvest_response(last_result.json_body(), last_result.headers)
        harvested = self._merge_harvested_candidates(harvested, last_result.json_body())
        if not create_candidates and not list_candidates:
            failure_reason = "object_not_reusable"
        elif not create_candidates:
            failure_reason = "no_creator_candidate"
        elif self._is_success(last_result.status_code) and not harvested["harvested_object_ids"]:
            failure_reason = "id_not_harvested" if list_candidates else "no_list_candidate"
        self._emit_prep_event(
            request=request,
            event_type="object_materialization_failed",
            status="failed",
            summary=f"Object materialization failed for family={resource_family}.",
            reason={"failure_reason": failure_reason},
            artifacts={
                "resource_family": resource_family,
                "strategy": "create_then_harvest" if create_candidates else "list_then_select" if list_candidates else "reuse_harvested",
                "create_endpoint": create_candidates[0]['path'] if create_candidates else "",
            },
        )
        self._emit_prep_event(
            request=request,
            event_type="object_materialization_finish",
            status="failed",
            summary=f"Object materialization finished without reusable object for family={resource_family}.",
            reason={"failure_reason": failure_reason},
            artifacts={
                "resource_family": resource_family,
                "strategy": "create_then_harvest" if create_candidates else "list_then_select" if list_candidates else "reuse_harvested",
                "create_endpoint": create_candidates[0]['path'] if create_candidates else "",
            },
        )
        return {
            "result": last_result,
            "request_url": request_url,
            "create_endpoint": create_candidates[0]["path"] if create_candidates else "",
            "object_id": None,
            "harvested_object_ids": harvested["harvested_object_ids"],
            "harvested_links": harvested["harvested_links"],
            "resource_family": resource_family,
            "object_type": self._object_type(target_endpoint),
            "replay_ready_endpoint": self._replay_ready_endpoint(request, target_endpoint, replay_path_params),
            "replay_path_params": replay_path_params,
            "synthesis_metadata": synthesis_metadata,
            "failure_reason": failure_reason,
            "source": "",
        }

    async def _harvest_from_list_candidates(
        self,
        *,
        request: ToolTestRequest,
        owner_identity: dict[str, Any],
        list_candidates: list[dict[str, str]],
        resource_family: str,
    ) -> dict[str, Any]:
        headers = self._identity_headers(owner_identity)
        harvested_object_ids: list[str] = []
        harvested_links: list[str] = []
        for candidate in list_candidates[:3]:
            candidate_path = str(candidate.get("path") or "").strip()
            candidate_method = str(candidate.get("method") or "GET").upper()
            self._emit_prep_event(
                request=request,
                event_type="list_candidate_selected",
                status="ok",
                summary=f"Selected list candidate {candidate_method} {candidate_path}.",
                artifacts={"resource_family": resource_family, "candidate_path": candidate_path, "candidate_method": candidate_method},
            )
            request_url = self._resolve_url(str(request.execution_context.target_url), candidate_path)
            self._validate_scope(request, request_url)
            result = await self.http_client.execute(
                method=candidate_method,
                url=request_url,
                headers=headers,
            )
            if not self._is_success(result.status_code):
                continue
            harvested = self.baseline_synthesis.harvest_response(result.json_body(), result.headers)
            harvested = self._merge_harvested_candidates(harvested, result.json_body())
            for item in harvested.get("harvested_object_ids") or []:
                value = str(item or "").strip()
                if value and value not in harvested_object_ids:
                    harvested_object_ids.append(value)
            for item in harvested.get("harvested_links") or []:
                value = str(item or "").strip()
                if value and value not in harvested_links:
                    harvested_links.append(value)
            if harvested_object_ids:
                self._emit_prep_event(
                    request=request,
                    event_type="object_materialization_id_harvested",
                    status="success",
                    summary=f"Harvested object ids from list candidate for family={resource_family}.",
                    counters={"harvested_object_id_count": len(harvested_object_ids)},
                    artifacts={"resource_family": resource_family, "harvested_object_ids": harvested_object_ids[:5], "harvested_links": harvested_links[:5]},
                )
                self._emit_prep_event(
                    request=request,
                    event_type="harvested_object_id_propagated",
                    status="success",
                    summary=f"Harvested object ids from list candidate for family={resource_family}.",
                    counters={"harvested_object_id_count": len(harvested_object_ids)},
                    artifacts={"resource_family": resource_family, "harvested_object_ids": harvested_object_ids[:5], "harvested_links": harvested_links[:5]},
                )
                return {
                    "object_id": harvested_object_ids[0],
                    "harvested_object_ids": harvested_object_ids,
                    "harvested_links": harvested_links,
                }
        return {"object_id": None, "harvested_object_ids": harvested_object_ids, "harvested_links": harvested_links}

    def _emit_prep_event(
        self,
        *,
        request: ToolTestRequest,
        event_type: str,
        status: str,
        summary: str,
        reason: dict[str, Any] | None = None,
        counters: dict[str, Any] | None = None,
        artifacts: dict[str, Any] | None = None,
    ) -> None:
        trace_context = self.diagnostics.trace_context(
            run_id=request.execution_context.run_id,
            root_trace_id=request.execution_context.root_trace_id,
            task=request.task,
        )
        self.diagnostics.emit(
            event_type=event_type,
            component="preparation",
            status=status,
            summary=summary,
            run_id=request.execution_context.run_id,
            trace_context=trace_context,
            reason=reason or {},
            counters=counters or {},
            artifacts=artifacts or {},
        )

    def _endpoint_candidates(self, explicit_endpoint: Any, fallbacks: list[str]) -> list[str]:
        explicit = str(explicit_endpoint or "").strip()
        candidates = [explicit] if explicit else []
        for item in fallbacks:
            if item not in candidates:
                candidates.append(item)
        return candidates

    def _best_auth_endpoint_candidates(
        self,
        *,
        request: ToolTestRequest,
        endpoint_type: str,
        explicit_endpoint: Any = None,
    ) -> list[str]:
        values: list[str] = []
        explicit = str(explicit_endpoint or "").strip()
        if explicit:
            values.append(explicit)
        for source in (
            self._openapi_auth_endpoints(request, endpoint_type),
            self._discovered_endpoints(request, endpoint_type),
            self._backend_known_auth_endpoints(request, endpoint_type),
            self.COMMON_REGISTER_ENDPOINTS if endpoint_type == "register" else self.COMMON_LOGIN_ENDPOINTS,
        ):
            for item in source:
                path = str(item or "").strip()
                if path and path not in values:
                    values.append(path)
        return values

    def _best_auth_operations(
        self,
        *,
        request: ToolTestRequest,
        endpoint_type: str,
        explicit_endpoint: Any = None,
        explicit_method: str = "POST",
    ) -> list[dict[str, Any]]:
        operations: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        openapi_operations = self._openapi_auth_operations(request, endpoint_type)
        for item in openapi_operations:
            key = (str(item.get("path") or ""), str(item.get("method") or "").upper())
            if key not in seen:
                seen.add(key)
                operations.append(item)
        explicit = str(explicit_endpoint or "").strip()
        if explicit:
            item = self._operation_from_path(
                request=request,
                endpoint_type=endpoint_type,
                path=explicit,
                method=str(explicit_method or "POST").upper(),
                source="explicit",
            )
            key = (str(item.get("path") or ""), str(item.get("method") or "").upper())
            if key not in seen:
                seen.add(key)
                operations.append(item)
        # If we have canonical OpenAPI operations, keep auth bootstrap bounded to those.
        if openapi_operations:
            selected = self._compatible_auth_operations(operations, endpoint_type=endpoint_type)[:5]
            if not selected:
                selected = operations[:5]
            for item in selected:
                self._emit_auth_operation_selected(request, endpoint_type=endpoint_type, operation=item)
            return selected
        for path in [
            *self._discovered_endpoints(request, endpoint_type),
            *self._backend_known_auth_endpoints(request, endpoint_type),
            *(self.COMMON_REGISTER_ENDPOINTS if endpoint_type == "register" else self.COMMON_LOGIN_ENDPOINTS),
        ]:
            item = self._operation_from_path(
                request=request,
                endpoint_type=endpoint_type,
                path=path,
                method=str(explicit_method or "POST").upper(),
                source="fallback",
            )
            key = (str(item.get("path") or ""), str(item.get("method") or "").upper())
            if key not in seen:
                seen.add(key)
                operations.append(item)
        selected = self._compatible_auth_operations(operations, endpoint_type=endpoint_type)[:5]
        if not selected:
            selected = operations[:5]
        if selected:
            for item in selected:
                self._emit_auth_operation_selected(request, endpoint_type=endpoint_type, operation=item)
        else:
            self._emit_prep_event(
                request=request,
                event_type="auth_operation_selection_failed",
                status="failed",
                summary=f"Auth operation selection failed for {endpoint_type}.",
                reason={"failure_reason": f"no_{endpoint_type}_operation_selected"},
                artifacts={"endpoint_type": endpoint_type},
            )
        return selected

    def _compatible_auth_operations(
        self,
        operations: list[dict[str, Any]],
        *,
        endpoint_type: str,
    ) -> list[dict[str, Any]]:
        compatible: list[dict[str, Any]] = []
        for item in operations:
            if self._is_auth_operation_compatible(item, endpoint_type=endpoint_type):
                compatible.append(item)
        return compatible

    def _is_auth_operation_compatible(self, operation: Mapping[str, Any], *, endpoint_type: str) -> bool:
        required_fields = [str(item or "").strip() for item in (operation.get("required_body_keys") or []) if str(item or "").strip()]
        body_fields = [str(item or "").strip() for item in (operation.get("request_body_keys") or []) if str(item or "").strip()]
        if endpoint_type == "register":
            if any(not self._is_supported_register_field(item) for item in required_fields):
                return False
            normalized_all = {self._normalize_auth_field_name(item) for item in [*required_fields, *body_fields] if item}
            has_password = any("password" in item for item in normalized_all)
            has_principal = any(item in {"email", "username", "user", "login"} or "email" in item or "username" in item for item in normalized_all)
            return has_password and has_principal
        normalized_required = {self._normalize_auth_field_name(item) for item in required_fields}
        normalized_all = {self._normalize_auth_field_name(item) for item in [*required_fields, *body_fields] if item}
        has_token_only = bool(normalized_required) and all("token" in item for item in normalized_required)
        if has_token_only:
            return False
        has_password = any("password" in item for item in normalized_all)
        has_principal = any(item in {"email", "username", "user", "login"} or "email" in item or "username" in item for item in normalized_all)
        return has_password and has_principal

    def _is_supported_register_field(self, field_name: str) -> bool:
        normalized = self._normalize_auth_field_name(field_name)
        if normalized in {
            "email",
            "username",
            "password",
            "name",
            "firstname",
            "lastname",
            "fullname",
            "role",
            "number",
            "phone",
            "mobile",
        }:
            return True
        return normalized.endswith("_name")

    def _normalize_auth_field_name(self, value: str) -> str:
        return str(value or "").strip().lower().replace("-", "_")

    def _openapi_auth_operations(self, request: ToolTestRequest, endpoint_type: str) -> list[dict[str, Any]]:
        spec_text = str(self._spec_text_for_request(request) or "").strip()
        if not spec_text:
            return []
        document = self.baseline_synthesis._parse_spec_text(spec_text)
        paths = document.get("paths") or {}
        if not isinstance(paths, Mapping):
            return []
        ranked: list[tuple[int, dict[str, Any]]] = []
        for path, path_item in paths.items():
            if not isinstance(path_item, Mapping):
                continue
            path_value = str(path or "").strip()
            if not path_value or self._endpoint_type_from_path(path_value) != endpoint_type:
                continue
            for method, operation in path_item.items():
                method_upper = str(method or "").upper()
                if method_upper not in {"POST", "PUT", "PATCH"} or not isinstance(operation, Mapping):
                    continue
                item = self._operation_from_path(
                    request=request,
                    endpoint_type=endpoint_type,
                    path=path_value,
                    method=method_upper,
                    source="openapi",
                    operation=operation,
                    document=document,
                )
                ranked.append((self._auth_path_score(path_value) + (5 if item.get("request_body_keys") else 0), item))
        ranked.sort(key=lambda pair: (-pair[0], len(str(pair[1].get("path") or ""))))
        return [item for _, item in ranked[:5]]

    def _operation_from_path(
        self,
        *,
        request: ToolTestRequest,
        endpoint_type: str,
        path: str,
        method: str,
        source: str,
        operation: Mapping[str, Any] | None = None,
        document: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        spec_text = self._spec_text_for_request(request)
        operation_obj = operation or self.baseline_synthesis.find_operation(spec_text, path, method)
        document_obj = document or (operation_obj or {}).get("_document") or self.baseline_synthesis._parse_spec_text(spec_text)
        schema: Mapping[str, Any] = {}
        media_type = "application/json"
        required: list[str] = []
        request_body_keys: list[str] = []
        if isinstance(operation_obj, Mapping):
            schema_raw, media = self.baseline_synthesis._request_schema(operation_obj, document_obj, include_media=True)
            schema = schema_raw if isinstance(schema_raw, Mapping) else {}
            media_type = str(media or "application/json")
            required = [str(item) for item in (schema.get("required") or []) if str(item).strip()]
            request_body_keys = self.baseline_synthesis._schema_property_names(schema)
        return {
            "path": str(path or "").strip(),
            "method": str(method or "POST").upper(),
            "content_type": media_type,
            "request_schema": dict(schema),
            "request_body_keys": request_body_keys,
            "required_body_keys": required,
            "source": source,
            "endpoint_type": endpoint_type,
        }

    def _operation_log_items(self, operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "path": item.get("path"),
                "method": item.get("method"),
                "content_type": item.get("content_type"),
                "source": item.get("source"),
                "request_body_keys": list(item.get("request_body_keys") or [])[:12],
                "required_body_keys": list(item.get("required_body_keys") or [])[:12],
            }
            for item in operations or []
        ]

    def _discovered_endpoints(self, request: ToolTestRequest, endpoint_type: str) -> list[str]:
        values: list[str] = []
        for item in request.execution_context.discovered_auth_endpoints or []:
            if not isinstance(item, dict):
                continue
            if str(item.get("type") or "").strip().lower() != str(endpoint_type or "").strip().lower():
                continue
            path = str(item.get("path") or "").strip()
            if path and path not in values:
                values.append(path)
        hints = request.task.context_hints.get("bootstrap_candidates") if isinstance(request.task.context_hints, dict) else {}
        if isinstance(hints, dict):
            key = "register" if endpoint_type == "register" else "login"
            for item in hints.get(key) or []:
                path = str(item or "").strip()
                if path and path not in values:
                    values.append(path)
        return values

    def _openapi_auth_endpoints(self, request: ToolTestRequest, endpoint_type: str) -> list[str]:
        spec_text = str(self._spec_text_for_request(request) or "").strip()
        if not spec_text:
            return []
        document = self.baseline_synthesis._parse_spec_text(spec_text)
        paths = document.get("paths") or {}
        if not isinstance(paths, Mapping):
            return []
        ranked: list[tuple[int, str]] = []
        for path, path_item in paths.items():
            if not isinstance(path_item, Mapping):
                continue
            path_value = str(path or "").strip()
            if not path_value:
                continue
            inferred_type = self._endpoint_type_from_path(path_value)
            if inferred_type != endpoint_type:
                continue
            methods = {str(method or "").upper() for method in path_item.keys()}
            if "POST" not in methods:
                continue
            ranked.append((self._auth_path_score(path_value), path_value))
        ranked.sort(key=lambda item: (-item[0], len(item[1])))
        return [path for _, path in ranked[:5]]

    def _backend_known_auth_endpoints(self, request: ToolTestRequest, endpoint_type: str) -> list[str]:
        target = str(request.execution_context.target_url or "").lower()
        if "crapi" in target:
            return list(self.CRAPI_AUTH_ENDPOINTS.get(endpoint_type) or [])
        return []

    def _auth_path_score(self, path: str) -> int:
        lowered = str(path or "").strip().lower()
        score = 0
        if lowered.startswith("/identity/api/auth/"):
            score += 10
        if "/api/" in lowered:
            score += 3
        if "login" in lowered:
            score += 2
        if "signup" in lowered or "register" in lowered:
            score += 2
        if lowered in {"/signup", "/login"}:
            score -= 4
        return score

    def _build_identity_seed(self, request: ToolTestRequest, index: int) -> dict[str, Any]:
        configured_roles = [
            str(request.task.auth_context.owner_role or "").strip(),
            str(request.task.auth_context.other_role or "").strip(),
        ]
        configured_roles = [item for item in configured_roles if item]
        default_roles = ["user_a", "user_b"]
        role_name = configured_roles[index] if index < len(configured_roles) else default_roles[index] if index < len(default_roles) else f"user_{index}"
        label = role_name.split("_", 1)[-1] if "_" in role_name else role_name
        run_scope = str(request.execution_context.run_id or request.execution_context.root_trace_id or "manual").strip()
        suffix = uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{run_scope}|{request.execution_context.target_url}|{request.task.id}|{role_name}|{index}",
        ).hex[:10]
        username = f"auto_{suffix}_{label}"
        phone_suffix = str(int(suffix[:8], 16)).zfill(7)[-7:]
        aliases = list(dict.fromkeys([role_name, default_roles[index] if index < len(default_roles) else f"user_{index}", username]))
        display_name = role_name
        return {
            "name": display_name,
            "role": role_name,
            "aliases": aliases,
            "username": username,
            "email": f"{username}@example.test",
            "password": f"AutoPass!{suffix[:6]}A1",
            "number": f"555{phone_suffix}",
            "cookies": {},
            "auth_headers": {},
            "token": None,
        }

    async def _attempt_registration(
        self,
        *,
        request: ToolTestRequest,
        identity: dict[str, Any],
        endpoint_type: str,
        operations: list[dict[str, Any]],
    ) -> tuple[HttpExecutionResult, str]:
        last_result = HttpExecutionResult(method="POST", url="", status_code=None, headers={}, body_text="", elapsed_ms=None, error="registration_not_attempted")
        last_endpoint = ""
        for operation in operations:
            endpoint = str(operation.get("path") or "").strip()
            method = str(operation.get("method") or "POST").upper()
            content_type = str(operation.get("content_type") or "application/json").lower()
            if content_type not in {"application/json", "application/x-www-form-urlencoded", "multipart/form-data"}:
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_register_attempt",
                    status="ok",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                )
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_register_result",
                    status="failed",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                    failure_reason="unsupported_content_type",
                )
                continue
            try:
                payload_variants = self._auth_payload_variants(request, identity, operation, endpoint_type=endpoint_type)
            except Exception as exc:
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_register_attempt",
                    status="ok",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                )
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_register_result",
                    status="failed",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                    failure_reason="request_construction_failed",
                    error_detail=type(exc).__name__,
                )
                continue
            if not payload_variants:
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_register_attempt",
                    status="ok",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                )
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_register_result",
                    status="failed",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                    failure_reason="invalid_required_fields",
                )
            for payload in payload_variants:
                request_body_keys = sorted(str(key) for key in payload.keys())
                if not payload:
                    self._emit_auth_attempt_event(
                        request=request,
                        event_type="auth_provision_register_result",
                        status="failed",
                        identity=identity,
                        operation=operation,
                        status_code=None,
                        request_body_keys=[],
                        failure_reason="invalid_required_fields",
                    )
                    continue
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_register_attempt",
                    status="ok",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=request_body_keys,
                )
                try:
                    request_url = self._resolve_url(str(request.execution_context.target_url), endpoint)
                    self._validate_scope(request, request_url)
                    last_endpoint = request_url
                    last_result = await self.http_client.execute(
                        method=method,
                        url=request_url,
                        headers={"Content-Type": content_type},
                        json_body=payload,
                    )
                except Exception as exc:
                    last_result = HttpExecutionResult(
                        method=method,
                        url=last_endpoint,
                        status_code=None,
                        headers={},
                        body_text="",
                        elapsed_ms=None,
                        error=str(exc),
                    )
                    self._emit_auth_attempt_event(
                        request=request,
                        event_type="auth_provision_register_result",
                        status="failed",
                        identity=identity,
                        operation=operation,
                        status_code=None,
                        request_body_keys=request_body_keys,
                        failure_reason="request_execution_failed",
                        error_detail=type(exc).__name__,
                    )
                    continue
                failure_reason = "" if self._is_success(last_result.status_code) else "unexpected_status_code"
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_register_result",
                    status="success" if self._is_success(last_result.status_code) else "failed",
                    identity=identity,
                    operation=operation,
                    status_code=last_result.status_code,
                    request_body_keys=request_body_keys,
                    failure_reason=failure_reason,
                    response_body_preview=self._safe_response_preview(last_result.body_text),
                )
                if self._is_success(last_result.status_code):
                    return last_result, last_endpoint
        return last_result, last_endpoint

    async def _attempt_login(
        self,
        *,
        request: ToolTestRequest,
        identity: dict[str, Any],
        endpoint_type: str,
        operations: list[dict[str, Any]],
        fallback_cookies: dict[str, str],
    ) -> tuple[HttpExecutionResult, str, dict[str, Any]]:
        last_result = HttpExecutionResult(method="POST", url="", status_code=None, headers={}, body_text="", elapsed_ms=None, error="login_not_attempted")
        last_endpoint = ""
        authenticated_identity = dict(identity)
        for operation in operations:
            endpoint = str(operation.get("path") or "").strip()
            method = str(operation.get("method") or "POST").upper()
            content_type = str(operation.get("content_type") or "application/json").lower()
            if content_type not in {"application/json", "application/x-www-form-urlencoded", "multipart/form-data"}:
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_login_attempt",
                    status="ok",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                )
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_login_result",
                    status="failed",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                    failure_reason="unsupported_content_type",
                )
                continue
            try:
                payload_variants = self._auth_payload_variants(request, identity, operation, endpoint_type=endpoint_type)
            except Exception as exc:
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_login_attempt",
                    status="ok",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                )
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_login_result",
                    status="failed",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                    failure_reason="request_construction_failed",
                    error_detail=type(exc).__name__,
                )
                continue
            if not payload_variants:
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_login_attempt",
                    status="ok",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                )
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_login_result",
                    status="failed",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=[],
                    failure_reason="invalid_required_fields",
                )
            for payload in payload_variants:
                request_body_keys = sorted(str(key) for key in payload.keys())
                if not payload:
                    self._emit_auth_attempt_event(
                        request=request,
                        event_type="auth_provision_login_result",
                        status="failed",
                        identity=identity,
                        operation=operation,
                        status_code=None,
                        request_body_keys=[],
                        failure_reason="invalid_required_fields",
                    )
                    continue
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_login_attempt",
                    status="ok",
                    identity=identity,
                    operation=operation,
                    status_code=None,
                    request_body_keys=request_body_keys,
                )
                try:
                    request_url = self._resolve_url(str(request.execution_context.target_url), endpoint)
                    self._validate_scope(request, request_url)
                    last_endpoint = request_url
                    last_result = await self.http_client.execute(
                        method=method,
                        url=request_url,
                        headers={"Content-Type": content_type},
                        json_body=payload,
                    )
                except Exception as exc:
                    last_result = HttpExecutionResult(
                        method=method,
                        url=last_endpoint,
                        status_code=None,
                        headers={},
                        body_text="",
                        elapsed_ms=None,
                        error=str(exc),
                    )
                    self._emit_auth_attempt_event(
                        request=request,
                        event_type="auth_provision_login_result",
                        status="failed",
                        identity=identity,
                        operation=operation,
                        status_code=None,
                        request_body_keys=request_body_keys,
                        failure_reason="request_execution_failed",
                        error_detail=type(exc).__name__,
                    )
                    continue
                try:
                    extracted = self._authenticated_identity_from_result(identity, last_result, fallback_cookies=fallback_cookies)
                    extraction_summary = self._auth_extraction_summary(extracted)
                except Exception as exc:
                    extracted = dict(identity)
                    extracted.update({"cookies": {}, "auth_headers": {}, "token": None, "authenticated": False})
                    extraction_summary = {}
                    self._emit_auth_attempt_event(
                        request=request,
                        event_type="auth_provision_login_result",
                        status="failed",
                        identity=identity,
                        operation=operation,
                        status_code=last_result.status_code,
                        request_body_keys=request_body_keys,
                        failure_reason="token_extraction_failed",
                        auth_extraction=extraction_summary,
                        error_detail=type(exc).__name__,
                    )
                    continue
                failure_reason = "" if self._is_success(last_result.status_code) else "unexpected_status_code"
                if self._is_success(last_result.status_code) and not self._has_auth_material(extracted):
                    failure_reason = "token_missing"
                self._emit_auth_attempt_event(
                    request=request,
                    event_type="auth_provision_login_result",
                    status="success" if self._is_success(last_result.status_code) and self._has_auth_material(extracted) else "failed",
                    identity=identity,
                    operation=operation,
                    status_code=last_result.status_code,
                    request_body_keys=request_body_keys,
                    failure_reason=failure_reason,
                    auth_extraction=extraction_summary,
                    response_body_preview=self._safe_response_preview(last_result.body_text),
                )
                if self._has_auth_material(extracted):
                    self._emit_auth_attempt_event(
                        request=request,
                        event_type="auth_provision_token_extracted",
                        status="success",
                        identity=identity,
                        operation=operation,
                        status_code=last_result.status_code,
                        request_body_keys=request_body_keys,
                        auth_extraction=extraction_summary,
                    )
                if self._is_success(last_result.status_code):
                    authenticated_identity.update(extracted)
                    return last_result, last_endpoint, authenticated_identity

        authenticated_identity.update({"cookies": dict(fallback_cookies), "auth_headers": {}, "token": None, "authenticated": False})
        return last_result, last_endpoint, authenticated_identity

    def _authenticated_identity_from_result(
        self,
        identity: dict[str, Any],
        result: HttpExecutionResult,
        *,
        fallback_cookies: dict[str, str],
    ) -> dict[str, Any]:
        authenticated = dict(identity)
        token, token_source = self._extract_token_with_source(result)
        cookies = self._extract_cookies(result.headers) or dict(fallback_cookies)
        auth_headers = self._extract_auth_headers(result, token)
        sources = {
            "body": token_source == "body",
            "header": token_source == "header"
            or bool(self._header_value(result.headers, "authorization") or self._header_value(result.headers, "x-auth-token")),
            "cookie": bool(cookies),
        }
        authenticated.update(
            {
                "token": token,
                "auth_headers": auth_headers,
                "cookies": cookies,
                "authenticated": bool(token or cookies),
                "auth_sources": sources,
            }
        )
        return authenticated

    def _auth_payload_variants(
        self,
        request: ToolTestRequest,
        identity: dict[str, Any],
        operation: dict[str, Any],
        *,
        endpoint_type: str,
    ) -> list[dict[str, Any]]:
        fields = [str(item) for item in (operation.get("request_body_keys") or []) if str(item).strip()]
        required = [str(item) for item in (operation.get("required_body_keys") or []) if str(item).strip()]
        known = self._auth_known_values(identity)
        variants: list[dict[str, Any]] = []
        if fields:
            payload = self._schema_auth_payload(fields=fields, required=required, known=known, endpoint_type=endpoint_type)
            self._append_payload_variant(variants, payload, required=required, endpoint_type=endpoint_type)
            synthesized = self.baseline_synthesis.synthesize_request(
                spec_text=self._spec_text_for_request(request),
                endpoint_path=str(operation.get("path") or ""),
                method=str(operation.get("method") or "POST"),
                known_values={},
            )
            baseline = synthesized.get("baseline_body") if isinstance(synthesized, dict) else {}
            self._append_payload_variant(variants, baseline if isinstance(baseline, dict) else {}, required=required, endpoint_type=endpoint_type)
            if variants:
                return variants

        synthesized = self.baseline_synthesis.synthesize_request(
            spec_text=self._spec_text_for_request(request),
            endpoint_path=str(operation.get("path") or ""),
            method=str(operation.get("method") or "POST"),
            known_values=known,
        )
        baseline = synthesized.get("baseline_body") if isinstance(synthesized, dict) else {}
        if isinstance(baseline, dict) and baseline:
            self._append_payload_variant(variants, baseline, required=required, endpoint_type=endpoint_type)
            if variants:
                return variants

        if endpoint_type == "login":
            fallback = [
                {"email": identity["email"], "password": identity["password"]},
                {"username": identity["username"], "password": identity["password"]},
            ]
        else:
            fallback = [
                {"email": identity["email"], "password": identity["password"], "name": identity["name"]},
                {"username": identity["username"], "password": identity["password"], "name": identity["name"]},
            ]
        for payload in fallback:
            self._append_payload_variant(variants, payload, required=required, endpoint_type=endpoint_type)
        return variants

    def _append_payload_variant(
        self,
        variants: list[dict[str, Any]],
        payload: Mapping[str, Any] | None,
        *,
        required: list[str],
        endpoint_type: str,
    ) -> None:
        if not isinstance(payload, Mapping) or not payload:
            return
        candidate = {str(key): value for key, value in payload.items() if str(key).strip() and value not in (None, "")}
        if not candidate:
            return
        normalized_keys = {self._normalize_auth_field_name(key) for key in candidate.keys()}
        if required:
            normalized_required = {self._normalize_auth_field_name(item) for item in required}
            if not normalized_required.issubset(normalized_keys):
                return
        if endpoint_type == "login":
            has_password = any("password" in key for key in normalized_keys)
            has_principal = any(key in {"email", "username", "user", "login"} or "email" in key or "username" in key for key in normalized_keys)
            if not (has_password and has_principal):
                return
        else:
            has_password = any("password" in key for key in normalized_keys)
            has_principal = any(key in {"email", "username", "user", "login"} or "email" in key or "username" in key for key in normalized_keys)
            if not (has_password and has_principal):
                return
        fingerprint = json.dumps(candidate, sort_keys=True, ensure_ascii=True)
        if any(json.dumps(item, sort_keys=True, ensure_ascii=True) == fingerprint for item in variants):
            return
        variants.append(candidate)

    def _schema_auth_payload(
        self,
        *,
        fields: list[str],
        required: list[str],
        known: dict[str, Any],
        endpoint_type: str,
    ) -> dict[str, Any]:
        field_lookup = {field.lower().replace("-", "_"): field for field in fields}
        payload: dict[str, Any] = {}
        required_set = set(required)
        for field in required:
            value = self._auth_value_for_field(field, known)
            if value in (None, ""):
                return {}
            payload[field] = value
        if endpoint_type == "login":
            preferred = ("email", "username", "password")
        else:
            preferred = ("email", "username", "password", "name", "firstName", "lastName", "fullName", "role")
        for alias in preferred:
            normalized = alias.lower().replace("-", "_")
            field = field_lookup.get(normalized)
            if not field or field in payload:
                continue
            if required_set and field not in required_set and endpoint_type == "login" and alias not in {"email", "username", "password"}:
                continue
            value = self._auth_value_for_field(field, known)
            if value not in (None, ""):
                payload[field] = value
        if endpoint_type == "login" and not any(str(key).lower() in {"email", "username"} for key in payload.keys()):
            for alias in ("email", "username"):
                field = field_lookup.get(alias)
                if field:
                    payload[field] = self._auth_value_for_field(field, known)
                    break
        if endpoint_type == "login" and not any("password" in str(key).lower() for key in payload.keys()):
            field = field_lookup.get("password")
            if field:
                payload[field] = known["password"]
        return payload

    def _auth_known_values(self, identity: dict[str, Any]) -> dict[str, Any]:
        full_name = str(identity.get("name") or identity.get("username") or "Auto User").strip()
        parts = [item for item in full_name.replace("_", " ").split() if item]
        first_name = parts[0] if parts else "Auto"
        last_name = parts[-1] if len(parts) > 1 else "User"
        return {
            **identity,
            "email": identity.get("email"),
            "username": identity.get("username"),
            "name": identity.get("name"),
            "password": identity.get("password"),
            "firstName": first_name,
            "firstname": first_name,
            "first_name": first_name,
            "lastName": last_name,
            "lastname": last_name,
            "last_name": last_name,
            "fullName": full_name,
            "fullname": full_name,
            "full_name": full_name,
            "role": identity.get("role") or "user",
        }

    def _auth_value_for_field(self, field: str, known: dict[str, Any]) -> Any:
        normalized = str(field or "").strip()
        lowered = normalized.lower()
        candidates = [
            normalized,
            lowered,
            lowered.replace("-", "_"),
            lowered.replace("_", ""),
        ]
        alias_map = {
            "user": "username",
            "login": "username",
            "mail": "email",
            "e_mail": "email",
            "passwd": "password",
            "pass": "password",
            "firstname": "firstName",
            "lastname": "lastName",
            "fullname": "fullName",
        }
        if lowered in alias_map:
            candidates.append(alias_map[lowered])
        for key in candidates:
            if key in known and known[key] not in (None, ""):
                return known[key]
        if "password" in lowered:
            return known.get("password")
        if "email" in lowered or "mail" in lowered:
            return known.get("email")
        if "user" in lowered or "login" in lowered:
            return known.get("username")
        if lowered in {"name", "fullname", "full_name"}:
            return known.get("fullName") or known.get("name")
        if "firstname" in lowered or "first_name" in lowered:
            return known.get("firstName")
        if "lastname" in lowered or "last_name" in lowered:
            return known.get("lastName")
        if lowered == "role":
            return known.get("role")
        return None

    def _emit_auth_attempt_event(
        self,
        *,
        request: ToolTestRequest,
        event_type: str,
        status: str,
        identity: dict[str, Any],
        operation: dict[str, Any],
        status_code: int | None,
        request_body_keys: list[str],
        failure_reason: str = "",
        auth_extraction: dict[str, bool] | None = None,
        error_detail: str = "",
        response_body_preview: str = "",
    ) -> None:
        self._emit_prep_event(
            request=request,
            event_type=event_type,
            status=status,
            summary=f"Auth provisioning {event_type} for {identity.get('name') or identity.get('role')}.",
            reason={"failure_reason": failure_reason or None},
            artifacts={
                "identity_name": identity.get("name"),
                "role": identity.get("role"),
                "endpoint": operation.get("path"),
                "method": operation.get("method"),
                "content_type": operation.get("content_type"),
                "source": operation.get("source"),
                "request_body_keys": request_body_keys,
                "status_code": status_code,
                "auth_extraction": auth_extraction or {},
                "error_detail": error_detail,
                "response_body_preview": response_body_preview,
            },
        )

    def _emit_auth_operation_selected(
        self,
        request: ToolTestRequest,
        *,
        endpoint_type: str,
        operation: dict[str, Any],
    ) -> None:
        source = str(operation.get("source") or "").strip() or "fallback"
        confidence = 0.95 if source == "openapi" else 0.9 if source == "explicit" else 0.45
        self._emit_prep_event(
            request=request,
            event_type="auth_operation_selected",
            status="ok",
            summary=f"Selected {endpoint_type} auth operation.",
            artifacts={
                "endpoint_type": endpoint_type,
                "endpoint": operation.get("path"),
                "method": operation.get("method"),
                "content_type": operation.get("content_type"),
                "source": source,
                "required_fields": list(operation.get("required_body_keys") or []),
                "request_body_keys": list(operation.get("request_body_keys") or []),
                "confidence": confidence,
            },
        )

    def _safe_response_preview(self, body_text: str, limit: int = 320) -> str:
        text = str(body_text or "").strip()
        if not text:
            return ""
        redacted = re.sub(r"(?i)(\"?(?:access_?token|id_?token|refresh_?token|token|password|authorization|cookie|set-cookie|session(?:id)?|x-?api-?key)\"?\s*[:=]\s*\")([^\"]+)(\")", r"\1***REDACTED***\3", text)
        redacted = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._\\-]+=*", "Bearer ***REDACTED***", redacted)
        collapsed = " ".join(redacted.split())
        return collapsed[:limit]

    def _normalize_provisioned_identity(
        self,
        authenticated_identity: dict[str, Any],
        seed_identity: dict[str, Any],
    ) -> dict[str, Any]:
        normalized = dict(authenticated_identity)
        aliases: list[str] = []
        for source in (seed_identity, authenticated_identity):
            for key in ("name", "role", "username", "email", "owner_role", "other_role"):
                value = str(source.get(key) or "").strip()
                if value and value not in aliases:
                    aliases.append(value)
            for item in source.get("aliases") or []:
                value = str(item or "").strip()
                if value and value not in aliases:
                    aliases.append(value)
        normalized["aliases"] = aliases
        normalized["name"] = str(normalized.get("name") or seed_identity.get("name") or seed_identity.get("role") or "").strip()
        normalized["role"] = str(normalized.get("role") or seed_identity.get("role") or normalized.get("name") or "").strip()
        normalized["provisioned"] = True
        normalized["auth_material"] = self._auth_material_summary(normalized)
        return normalized

    def _auth_material_summary(self, identity: dict[str, Any]) -> dict[str, bool]:
        auth_headers = identity.get("auth_headers")
        cookies = identity.get("cookies")
        return {
            "has_token": bool(str(identity.get("token") or "").strip()),
            "has_auth_headers": bool(auth_headers) if isinstance(auth_headers, dict) else False,
            "has_cookies": bool(cookies) if isinstance(cookies, dict) else False,
        }

    def _aggregate_status(self, *, expected_total: int, register_success_total: int, login_success_total: int) -> str:
        if expected_total > 0 and register_success_total >= expected_total and login_success_total >= expected_total:
            return "success"
        if register_success_total > 0 or login_success_total > 0:
            return "partial"
        return "failed"

    def _extract_token(self, result: HttpExecutionResult) -> str | None:
        token, _ = self._extract_token_with_source(result)
        return token

    def _extract_token_with_source(self, result: HttpExecutionResult) -> tuple[str | None, str]:
        json_body = result.json_body()
        if isinstance(json_body, dict):
            for item in self._extract_token_candidates(json_body):
                value = str(item or "").strip()
                if value:
                    return value, "body"
        auth_header = self._header_value(result.headers, "authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            return auth_header.split(" ", 1)[1].strip(), "header"
        for header_name in ("x-auth-token", "x_api_token", "x-api-key"):
            header_value = str(self._header_value(result.headers, header_name) or "").strip()
            if header_value:
                return header_value, "header"
        return None, ""

    def _extract_token_candidates(self, value: Any) -> list[Any]:
        candidates: list[Any] = []
        token_keys = {"access_token", "accessToken", "token", "jwt", "authToken", "auth_token", "id_token"}
        if isinstance(value, Mapping):
            for key, item in value.items():
                if str(key) in token_keys or str(key).lower() in {item.lower() for item in token_keys}:
                    candidates.append(item)
                if isinstance(item, (Mapping, list)):
                    candidates.extend(self._extract_token_candidates(item))
        elif isinstance(value, list):
            for item in value[:6]:
                candidates.extend(self._extract_token_candidates(item))
        return candidates

    def _extract_auth_headers(self, result: HttpExecutionResult, token: str | None = None) -> dict[str, str]:
        headers: dict[str, str] = {}
        auth_header = str(self._header_value(result.headers, "authorization") or "").strip()
        if auth_header:
            headers["Authorization"] = auth_header
        x_auth_token = str(self._header_value(result.headers, "x-auth-token") or "").strip()
        if x_auth_token:
            headers["X-Auth-Token"] = x_auth_token
        if token and "Authorization" not in headers and "X-Auth-Token" not in headers:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _auth_extraction_summary(self, identity: dict[str, Any]) -> dict[str, bool]:
        sources = identity.get("auth_sources")
        if isinstance(sources, dict):
            return {
                "from_body": bool(sources.get("body")),
                "from_header": bool(sources.get("header")),
                "from_cookie": bool(sources.get("cookie")),
            }
        auth_headers = identity.get("auth_headers")
        cookies = identity.get("cookies")
        return {
            "from_body": bool(str(identity.get("token") or "").strip()),
            "from_header": bool(auth_headers) and any(str(key).lower() in {"authorization", "x-auth-token"} for key in auth_headers.keys()),
            "from_cookie": bool(cookies) if isinstance(cookies, dict) else False,
        }

    def _extract_cookies(self, headers: dict[str, str]) -> dict[str, str]:
        raw = str(self._header_value(headers, "set-cookie") or "").strip()
        if not raw:
            return {}
        cookies: dict[str, str] = {}
        for chunk in raw.split(","):
            first = chunk.split(";", 1)[0].strip()
            if "=" not in first:
                continue
            name, value = first.split("=", 1)
            if name.strip():
                cookies[name.strip()] = value.strip()
        return cookies

    def _header_value(self, headers: dict[str, str], name: str) -> str:
        target = str(name or "").strip().lower()
        for key, value in (headers or {}).items():
            if str(key or "").strip().lower() == target:
                return str(value or "")
        return ""

    def _owner_identity(self, request: ToolTestRequest, explicit_identity: Any) -> dict[str, Any] | None:
        if isinstance(explicit_identity, dict) and explicit_identity:
            return explicit_identity
        owner_name = str(request.task.auth_context.owner_role or "").strip()
        roles = [item for item in (request.execution_context.roles or []) if isinstance(item, dict)]
        for role in roles:
            if self._role_matches(role, owner_name) and self._has_auth_material(role):
                return role
        if owner_name:
            return None
        for role in roles:
            if self._has_auth_material(role):
                return role
        return None

    def _spec_text_for_request(self, request: ToolTestRequest) -> str:
        existing = str(request.execution_context.openapi_spec_text or "")
        if existing.strip():
            return existing
        ref = str(request.execution_context.openapi_url or "").strip()
        if not ref:
            return ""
        cached = self._openapi_cache.get(ref)
        if cached is not None:
            return cached
        try:
            if ref.startswith(("http://", "https://")):
                with urlopen(ref) as resp:  # nosec - constrained by backend scope/targeted OpenAPI input
                    text = resp.read().decode("utf-8")
            else:
                text = Path(ref).read_text(encoding="utf-8")
        except Exception:
            text = ""
        self._openapi_cache[ref] = text
        return text

    def _role_matches(self, role: dict[str, Any], owner_name: str) -> bool:
        target = str(owner_name or "").strip().lower()
        if not target:
            return False
        candidates = {
            str(role.get("name") or "").strip().lower(),
            str(role.get("role") or "").strip().lower(),
            str(role.get("username") or "").strip().lower(),
            str(role.get("email") or "").strip().lower(),
            str(role.get("owner_role") or "").strip().lower(),
            str(role.get("other_role") or "").strip().lower(),
            str(role.get("label") or "").strip().lower(),
        }
        aliases = role.get("aliases")
        if isinstance(aliases, list):
            for item in aliases:
                candidates.add(str(item or "").strip().lower())
        return target in {item for item in candidates if item}

    def _identity_headers(self, identity: dict[str, Any]) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        auth_headers = identity.get("auth_headers")
        if isinstance(auth_headers, dict):
            headers.update({str(k): str(v) for k, v in auth_headers.items() if str(k).strip()})
        token = str(identity.get("token") or "").strip()
        if token and "authorization" not in {k.lower() for k in headers}:
            headers["Authorization"] = f"Bearer {token}"
        cookies = identity.get("cookies")
        if isinstance(cookies, dict) and cookies and "cookie" not in {k.lower() for k in headers}:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        return headers

    def _materialize_from_values(self, endpoint: str, values: Mapping[str, Any] | None) -> str:
        materialized = str(endpoint or "")
        for name, value in (values or {}).items():
            if value in (None, ""):
                continue
            materialized = materialized.replace("{" + str(name) + "}", str(value))
        return materialized

    def _infer_create_endpoint(self, task_endpoint: str) -> str:
        endpoint = str(task_endpoint or "").strip()
        if endpoint == "/identity/api/v2/vehicle/{id}/location":
            return "/identity/api/v2/vehicle/add_vehicle"
        lowered = endpoint.lower()
        if "/workshop/api/shop/orders/" in lowered or lowered.endswith("/workshop/api/shop/orders") or "return_order" in lowered:
            return "/workshop/api/shop/orders"
        if "/community/api/v2/community/posts/" in lowered:
            return "/community/api/v2/community/posts"
        if "/identity/api/v2/user/videos/" in lowered or "/identity/api/v2/admin/videos/" in lowered or "/videos/" in lowered:
            return "/identity/api/v2/user/videos"
        if "/workshop/api/mechanic/mechanic_report" in lowered or "/workshop/api/mechanic/service_requests" in lowered:
            return "/workshop/api/mechanic/receive_report"
        if "/{id}" in endpoint:
            return endpoint.split("/{id}", 1)[0]
        return endpoint.rstrip("/")

    def _infer_list_endpoint(self, task_endpoint: str) -> str:
        endpoint = str(task_endpoint or "").strip()
        lowered = endpoint.lower()
        if "vehicle" in lowered:
            return "/identity/api/v2/vehicle/vehicles"
        if "/workshop/api/shop/orders" in lowered:
            return "/workshop/api/shop/orders/all"
        if "/community/api/v2/community/posts" in lowered:
            return "/community/api/v2/community/posts/recent"
        if "/videos/" in lowered:
            return "/identity/api/v2/user/videos"
        if "/mechanic/" in lowered and ("report" in lowered or "service_requests" in lowered):
            return "/workshop/api/mechanic/mechanic_report"
        return ""

    def _reuse_materialized_context(self, request: ToolTestRequest, resource_family: str) -> dict[str, Any]:
        family = str(resource_family or "").strip().lower()
        prepared = request.execution_context.prepared_objects or {}
        if family and isinstance(prepared, dict):
            item = prepared.get(family)
            if isinstance(item, dict):
                object_id = self._extract_object_id_from_value(item)
                if object_id:
                    return {
                        "object_id": object_id,
                        "harvested_object_ids": [object_id],
                        "harvested_links": list(request.execution_context.harvested_links or [])[:10],
                        "source": str(item.get("source") or "prepared_object"),
                    }
        workflow = request.execution_context.workflow_context or {}
        if isinstance(workflow, dict) and str(workflow.get("resource_family") or "").strip().lower() == family:
            object_id = self._extract_object_id_from_value(workflow)
            if object_id:
                return {
                    "object_id": object_id,
                    "harvested_object_ids": [object_id],
                    "harvested_links": list(request.execution_context.harvested_links or [])[:10],
                    "source": str(workflow.get("source") or "workflow_context"),
                }
        values = [str(item).strip() for item in (request.execution_context.harvested_object_ids or []) if str(item).strip()]
        if values:
            return {
                "object_id": values[0],
                "harvested_object_ids": values[:10],
                "harvested_links": list(request.execution_context.harvested_links or [])[:10],
                "source": "propagated_from_execution_context",
            }
        return {"object_id": None, "harvested_object_ids": [], "harvested_links": [], "source": ""}

    def _default_probe_base_paths(self, request: ToolTestRequest) -> list[str]:
        values = []
        task_endpoint = str(request.task.endpoint or "").strip()
        if task_endpoint:
            parts = [item for item in task_endpoint.split("/") if item]
            if parts:
                values.append("/" + "/".join(parts[: min(len(parts), 2)]))
                values.append("/" + parts[0])
        for item in ["/api", "/identity", "/auth", "/user", "/account"]:
            if item not in values:
                values.append(item)
        return values[:6]

    def _join_paths(self, base_path: str, suffix_path: str) -> str:
        base_parts = [item for item in str(base_path or "").split("/") if item]
        suffix_parts = [item for item in str(suffix_path or "").split("/") if item]
        if suffix_parts and base_parts and suffix_parts[0] == base_parts[-1]:
            suffix_parts = suffix_parts[1:]
        parts = [*base_parts, *suffix_parts]
        return "/" + "/".join(parts) if parts else "/"

    def _endpoint_type_from_path(self, path: str) -> str | None:
        lowered = str(path or "").lower()
        if any(token in lowered for token in ("register", "signup")):
            return "register"
        if any(token in lowered for token in ("login", "signin")):
            return "login"
        return None

    def _looks_like_auth_endpoint(self, result: HttpExecutionResult) -> bool:
        if result.status_code not in {200, 201, 400}:
            return False
        content_type = str(result.headers.get("content-type") or "").lower()
        if "json" not in content_type and result.json_body() is None:
            return False
        json_body = result.json_body()
        if isinstance(json_body, dict):
            flattened = json.dumps(json_body).lower()
            if any(token in flattened for token in ("token", "jwt", "access_token", "email", "password", "username", "name")):
                return True
        return True

    def _infer_create_body(self, request: ToolTestRequest, owner_identity: dict[str, Any]) -> dict[str, Any]:
        endpoint = str(request.task.endpoint or "").lower()
        if "vehicle" in endpoint:
            suffix = uuid.uuid4().hex[:8]
            return {
                "vin": f"VIN{suffix.upper()}",
                "plateNumber": f"PLT{suffix.upper()}",
                "ownerName": str(owner_identity.get("name") or "auto-owner"),
                "pincode": "123456",
            }
        if "/shop/orders" in endpoint:
            return {"product_id": 1, "quantity": 1}
        if "/community/" in endpoint and "/posts/" in endpoint:
            suffix = uuid.uuid4().hex[:6]
            return {
                "title": f"autodast-post-{suffix}",
                "content": "Created by bounded auth preparation tool.",
            }
        if "/user/videos/" in endpoint:
            suffix = uuid.uuid4().hex[:6]
            return {
                "id": 1,
                "videoName": f"autodast-{suffix}.mp4",
                "video_url": f"http://example.test/{suffix}.mp4",
                "conversion_params": "-v codec h264",
            }
        if "/mechanic/" in endpoint and ("report" in endpoint or "service_requests" in endpoint):
            return {
                "mechanic_code": "TRAC_MECH1",
                "problem_details": "Bounded test report creation.",
                "vin": "0BZCX25UTBJ987271",
            }
        return {
            "name": f"autodast-{uuid.uuid4().hex[:6]}",
            "title": f"autodast-{uuid.uuid4().hex[:6]}",
            "description": "Created by bounded auth preparation tool.",
        }

    def _extract_object_id(self, result: HttpExecutionResult) -> str | None:
        json_body = result.json_body()
        from_body = self._extract_object_id_from_value(json_body)
        if from_body:
            return from_body
        location = str(result.headers.get("location") or "").strip()
        if location:
            candidate = location.rstrip("/").split("/")[-1]
            if candidate:
                return candidate
        return None

    def _merge_harvested_candidates(self, harvested: dict[str, Any], value: Any) -> dict[str, Any]:
        merged = {
            "harvested_object_ids": list(harvested.get("harvested_object_ids") or []),
            "harvested_links": list(harvested.get("harvested_links") or []),
        }
        for item in self._extract_candidate_object_ids(value):
            if item not in merged["harvested_object_ids"]:
                merged["harvested_object_ids"].append(item)
        return merged

    def _extract_candidate_object_ids(self, value: Any) -> list[str]:
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
                values.extend(self._extract_candidate_object_ids(item))
        elif isinstance(value, list):
            for item in value[:10]:
                values.extend(self._extract_candidate_object_ids(item))
        deduped: list[str] = []
        seen: set[str] = set()
        for item in values:
            normalized = str(item or "").strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                deduped.append(normalized)
        return deduped[:20]

    def _replay_path_params(self, request: ToolTestRequest, endpoint: str, object_id: Any) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if object_id in (None, ""):
            return params
        placeholders = [item for item in self._extract_placeholders(endpoint) if item]
        preferred = str(request.task.params.object_param_name or "").strip()
        if preferred:
            params[preferred] = object_id
        for item in placeholders:
            params.setdefault(item, object_id)
        if not params:
            params["id"] = object_id
        return params

    def _extract_placeholders(self, endpoint: str) -> list[str]:
        placeholders: list[str] = []
        current = ""
        in_placeholder = False
        for char in str(endpoint or ""):
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

    def _replay_ready_endpoint(self, request: ToolTestRequest, endpoint: str, path_params: Mapping[str, Any] | None) -> str:
        materialized = self._materialize_from_values(endpoint, path_params)
        return self._resolve_url(str(request.execution_context.target_url), materialized)

    def _extract_object_id_from_value(self, value: Any) -> str | None:
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
            for item in value:
                found = self._extract_object_id_from_value(item)
                if found:
                    return found
        return None

    async def _fetch_latest_vehicle_id(self, request: ToolTestRequest, owner_identity: dict[str, Any]) -> str | None:
        list_url = self._resolve_url(str(request.execution_context.target_url), "/identity/api/v2/vehicle/vehicles")
        self._validate_scope(request, list_url)
        result = await self.http_client.execute(
            method="GET",
            url=list_url,
            headers=self._identity_headers(owner_identity),
        )
        json_body = result.json_body()
        if isinstance(json_body, list) and json_body:
            last = json_body[-1]
            return self._extract_object_id_from_value(last)
        if isinstance(json_body, dict):
            for key in ("vehicles", "data", "items", "result"):
                collection = json_body.get(key)
                if isinstance(collection, list) and collection:
                    return self._extract_object_id_from_value(collection[-1])
        return None

    def _looks_like_vehicle_create(self, endpoint: str) -> bool:
        lowered = str(endpoint or "").lower()
        return "vehicle" in lowered and ("add_vehicle" in lowered or lowered.endswith("/vehicle"))

    def _object_type(self, task_endpoint: str) -> str:
        segments = [item for item in urlparse(str(task_endpoint or "")).path.split("/") if item]
        if "vehicle" in segments:
            return "vehicle"
        if "orders" in segments:
            return "order"
        if "posts" in segments:
            return "post"
        if "videos" in segments:
            return "video"
        if "mechanic_report" in segments or "service_requests" in segments:
            return "service_request"
        if len(segments) >= 2:
            return segments[-2] if segments[-1] == "{id}" else segments[-1]
        return "resource"

    def _resolve_url(self, target_url: str, endpoint: str) -> str:
        endpoint_value = str(endpoint or "").strip()
        parsed = urlparse(endpoint_value)
        if parsed.scheme and parsed.netloc:
            return endpoint_value
        return urljoin(str(target_url or "").rstrip("/") + "/", endpoint_value.lstrip("/"))

    def _validate_scope(self, request: ToolTestRequest, endpoint: str) -> None:
        allowed_hosts = request.execution_context.allowed_hosts or []
        parsed = urlparse(endpoint)
        host = parsed.netloc if parsed.scheme and parsed.netloc else urlparse(str(request.execution_context.target_url)).netloc
        if allowed_hosts and host not in allowed_hosts:
            raise ValueError(f"Host '{host}' is outside allowed scope")
        if self._is_sensitive_host(host) and host not in allowed_hosts:
            raise ValueError(f"Host '{host}' is blocked by SSRF policy")

    def _has_auth_material(self, role: dict[str, Any]) -> bool:
        return bool(role.get("token") or role.get("auth_headers") or role.get("cookies"))

    def _stable_materialization_failure(self, reason: Any) -> str:
        value = str(reason or "").strip().lower()
        mapping = {
            "creator_not_available": "no_creator_candidate",
            "object_creation_failed": "create_failed",
            "object_harvest_failed": "id_not_harvested",
            "object_id_missing": "id_not_harvested",
            "list_not_available": "no_list_candidate",
            "materialization_failed": "object_not_reusable",
            "success_path_not_reachable": "create_failed",
        }
        return mapping.get(value, value or "object_not_reusable")

    def _is_success(self, status_code: int | None) -> bool:
        return status_code is not None and 200 <= status_code < 300

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
