import ipaddress
import json
import os
import uuid
from collections.abc import Mapping
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
        register_endpoints = self._best_auth_endpoint_candidates(
            request=request,
            endpoint_type="register",
            explicit_endpoint=args.get("register_endpoint"),
        )
        login_endpoints = self._best_auth_endpoint_candidates(
            request=request,
            endpoint_type="login",
            explicit_endpoint=args.get("login_endpoint"),
        )
        identities = [self._build_identity_seed(request, index) for index in range(identity_count)]

        register_attempts: list[dict[str, Any]] = []
        login_attempts: list[dict[str, Any]] = []
        provisioned: list[dict[str, Any]] = []
        register_success_total = 0
        login_success_total = 0

        register_endpoint_used = ""
        login_endpoint_used = ""
        registration_available = bool(register_endpoints)
        registration_unavailable_reason = None if registration_available else "register_endpoint_unavailable"

        for identity in identities:
            if registration_available:
                register_result, register_endpoint_used = await self._attempt_registration(
                    request=request,
                    identity=identity,
                    method=register_method,
                    endpoint_candidates=register_endpoints,
                )
                if self._is_success(register_result.status_code):
                    register_success_total += 1
            else:
                register_result = HttpExecutionResult(
                    method=register_method,
                    url="",
                    status_code=None,
                    headers={},
                    body_text="",
                    elapsed_ms=None,
                    error="register_endpoint_unavailable",
                )
            register_attempts.append(
                {
                    "identity_name": identity["name"],
                    "endpoint": register_endpoint_used,
                    "status_code": register_result.status_code,
                    "error": register_result.error,
                }
            )

            login_result, login_endpoint_used, authenticated_identity = await self._attempt_login(
                request=request,
                identity=identity,
                method=login_method,
                endpoint_candidates=login_endpoints,
                fallback_cookies=self._extract_cookies(register_result.headers),
            )
            login_attempts.append(
                {
                    "identity_name": identity["name"],
                    "endpoint": login_endpoint_used,
                    "status_code": login_result.status_code,
                    "error": login_result.error,
                }
            )
            if self._is_success(login_result.status_code):
                login_success_total += 1

            if self._is_success(register_result.status_code) or self._is_success(login_result.status_code):
                provisioned.append(authenticated_identity)

        raw_status = self._aggregate_status(
            expected_total=identity_count,
            register_success_total=register_success_total,
            login_success_total=login_success_total,
        )
        indicators = []
        if login_success_total >= 2:
            indicators.append("auto_provision_success")
        elif provisioned:
            indicators.append("auto_provision_partial")
        else:
            indicators.append("auto_provision_failed")
        if not registration_available:
            indicators.append("register_endpoint_unavailable")
        if self.playwright_runner_url:
            indicators.append("playwright_runner_available")

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
                "registration_available": registration_available,
                "registration_unavailable_reason": registration_unavailable_reason,
                "register_endpoint_candidates": register_endpoints[:5],
                "login_endpoint_candidates": login_endpoints[:5],
            },
            raw_status=raw_status,
            indicators=indicators,
            identities=provisioned,
            artifacts=[
                Artifact(type="provisioned_identities", value=provisioned),
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

        if not owner_identity:
            self._emit_prep_event(
                request=request,
                event_type="prep_object_materialization_failed",
                status="failed",
                summary="Object materialization failed because no owner identity was available.",
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
            event_type="prep_object_materialization_result",
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
                "owner_identity_name": created_object["owner_identity_name"],
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
                    event_type="harvested_object_id_propagated",
                    status="success",
                    summary=f"Materialized object id for family={resource_family}.",
                    counters={"harvested_object_id_count": len(harvested["harvested_object_ids"])},
                    artifacts={"resource_family": resource_family, "harvested_object_ids": harvested["harvested_object_ids"][:5]},
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
                failure_reason = synthesis.get("structured_failure_reason") or "success_path_not_reachable"
            elif not self._is_success(last_result.status_code):
                failure_reason = "object_creation_failed" if create_candidates else "creator_not_available"
            elif self._is_success(last_result.status_code):
                failure_reason = "object_harvest_failed" if list_candidates else "list_not_available"

        harvested = self.baseline_synthesis.harvest_response(last_result.json_body(), last_result.headers)
        harvested = self._merge_harvested_candidates(harvested, last_result.json_body())
        if not create_candidates and not list_candidates:
            failure_reason = "materialization_failed"
        elif not create_candidates:
            failure_reason = "creator_not_available"
        elif self._is_success(last_result.status_code) and not harvested["harvested_object_ids"]:
            failure_reason = "object_id_missing" if list_candidates else "list_not_available"
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
        spec_text = str(request.execution_context.openapi_spec_text or "").strip()
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
        suffix = uuid.uuid5(uuid.NAMESPACE_URL, f"{request.execution_context.target_url}|{request.task.id}|{role_name}|{index}").hex[:10]
        username = f"auto_{suffix}_{label}"
        aliases = [role_name]
        display_name = role_name
        return {
            "name": display_name,
            "role": role_name,
            "aliases": aliases,
            "username": username,
            "email": f"{username}@example.test",
            "password": f"AutoPass!{suffix[:6]}A1",
            "number": f"555{suffix[:7]}",
            "cookies": {},
            "auth_headers": {},
            "token": None,
        }

    async def _attempt_registration(
        self,
        *,
        request: ToolTestRequest,
        identity: dict[str, Any],
        method: str,
        endpoint_candidates: list[str],
    ) -> tuple[HttpExecutionResult, str]:
        last_result = HttpExecutionResult(method=method, url="", status_code=None, headers={}, body_text="", elapsed_ms=None, error="registration_not_attempted")
        last_endpoint = ""
        payload_variants = [
            {
                "name": identity["name"],
                "email": identity["email"],
                "password": identity["password"],
                "number": identity["number"],
            },
            {
                "username": identity["username"],
                "email": identity["email"],
                "password": identity["password"],
                "name": identity["name"],
            },
        ]
        for endpoint in endpoint_candidates:
            request_url = self._resolve_url(str(request.execution_context.target_url), endpoint)
            self._validate_scope(request, request_url)
            synthesized = self.baseline_synthesis.synthesize_request(
                spec_text=self._spec_text_for_request(request),
                endpoint_path=endpoint,
                method=method,
                known_values=identity,
            )
            for payload in payload_variants:
                merged_payload = dict(synthesized.get("baseline_body") or {})
                merged_payload.update(payload)
                last_endpoint = request_url
                last_result = await self.http_client.execute(
                    method=method,
                    url=request_url,
                    headers={"Content-Type": "application/json"},
                    query_params=synthesized.get("baseline_query") or None,
                    json_body=merged_payload,
                )
                if self._is_success(last_result.status_code):
                    return last_result, last_endpoint
        return last_result, last_endpoint

    async def _attempt_login(
        self,
        *,
        request: ToolTestRequest,
        identity: dict[str, Any],
        method: str,
        endpoint_candidates: list[str],
        fallback_cookies: dict[str, str],
    ) -> tuple[HttpExecutionResult, str, dict[str, Any]]:
        last_result = HttpExecutionResult(method=method, url="", status_code=None, headers={}, body_text="", elapsed_ms=None, error="login_not_attempted")
        last_endpoint = ""
        payload_variants = [
            {"email": identity["email"], "password": identity["password"]},
            {"username": identity["username"], "password": identity["password"]},
        ]
        authenticated_identity = dict(identity)
        for endpoint in endpoint_candidates:
            request_url = self._resolve_url(str(request.execution_context.target_url), endpoint)
            self._validate_scope(request, request_url)
            synthesized = self.baseline_synthesis.synthesize_request(
                spec_text=self._spec_text_for_request(request),
                endpoint_path=endpoint,
                method=method,
                known_values=identity,
            )
            for payload in payload_variants:
                merged_payload = dict(synthesized.get("baseline_body") or {})
                merged_payload.update(payload)
                last_endpoint = request_url
                last_result = await self.http_client.execute(
                    method=method,
                    url=request_url,
                    headers={"Content-Type": "application/json"},
                    query_params=synthesized.get("baseline_query") or None,
                    json_body=merged_payload,
                )
                if self._is_success(last_result.status_code):
                    token = self._extract_token(last_result)
                    cookies = self._extract_cookies(last_result.headers) or dict(fallback_cookies)
                    auth_headers = {"Authorization": f"Bearer {token}"} if token else {}
                    authenticated_identity.update(
                        {
                            "token": token,
                            "auth_headers": auth_headers,
                            "cookies": cookies,
                            "authenticated": True,
                        }
                    )
                    return last_result, last_endpoint, authenticated_identity

        authenticated_identity.update({"cookies": dict(fallback_cookies), "auth_headers": {}, "token": None, "authenticated": False})
        return last_result, last_endpoint, authenticated_identity

    def _aggregate_status(self, *, expected_total: int, register_success_total: int, login_success_total: int) -> str:
        if expected_total > 0 and register_success_total >= expected_total and login_success_total >= expected_total:
            return "success"
        if register_success_total > 0 or login_success_total > 0:
            return "partial"
        return "failed"

    def _extract_token(self, result: HttpExecutionResult) -> str | None:
        json_body = result.json_body()
        candidates: list[Any] = []
        if isinstance(json_body, dict):
            candidates.extend(
                [
                    json_body.get("access_token"),
                    json_body.get("accessToken"),
                    json_body.get("token"),
                    json_body.get("jwt"),
                ]
            )
            data = json_body.get("data")
            if isinstance(data, dict):
                candidates.extend(
                    [
                        data.get("access_token"),
                        data.get("accessToken"),
                        data.get("token"),
                        data.get("jwt"),
                    ]
                )
        auth_header = result.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            candidates.append(auth_header.split(" ", 1)[1])
        for item in candidates:
            value = str(item or "").strip()
            if value:
                return value
        return None

    def _extract_cookies(self, headers: dict[str, str]) -> dict[str, str]:
        raw = str(headers.get("set-cookie") or "").strip()
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
