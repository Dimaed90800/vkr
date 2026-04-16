import ipaddress
import logging
import uuid
from urllib.parse import urljoin, urlparse

try:
    from backend.models.testing import Artifact, ToolTestRequest, ToolTestResponse
    from backend.services.diff_service import DiffService
    from backend.services.http_client import HttpClient
    from backend.services.rejection_analyzer import RejectionAnalyzer
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import Artifact, ToolTestRequest, ToolTestResponse
    from services.diff_service import DiffService
    from services.http_client import HttpClient
    from services.rejection_analyzer import RejectionAnalyzer


logger = logging.getLogger(__name__)


class TestingService:
    def __init__(self) -> None:
        self.http_client = HttpClient()
        self.diff_service = DiffService()
        self.rejection_analyzer = RejectionAnalyzer()

    async def run_authorization_test(self, request: ToolTestRequest) -> ToolTestResponse:
        return await self.test_access(request)

    async def test_access(self, request: ToolTestRequest) -> ToolTestResponse:
        args = request.arguments
        method = str(args.get("method") or request.task.method).upper()
        owner_role = str(args.get("owner_role") or request.task.auth_context.owner_role or "user_a")
        other_role = str(args.get("other_role") or request.task.auth_context.other_role or "user_b")
        role_profiles = self._role_profiles(request)
        headers = dict(args.get("headers") or {})
        query_params = dict(args.get("query_params") or {})
        json_body = args.get("json_body")
        selected_object_id = args.get("object_id") or request.task.params.selected_object_id
        candidate_ids = list(request.task.params.object_id_candidates or [])
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

        if guessed_object_id and not candidate_ids and request.task.class_name == "authorization":
            failure_analysis = {
                "failure_type": "invalid_object_id",
                "should_retry": False,
                "requires_new_object_id": True,
                "reason": "Blocked guessed object ID without evidence-backed candidates.",
            }
            replan = self.rejection_analyzer.controlled_replan(
                retry_count=int(request.task.retry_count or 0),
                current_object_id=guessed_object_id,
                candidate_ids=candidate_ids,
                failure_classification=failure_analysis,
            )
            return ToolTestResponse(
                request_summary={
                    "method": method,
                    "endpoint": endpoint,
                    "tested_roles": [owner_role, other_role],
                },
                response_summary={
                    "owner": {"status_code": None, "body_length": 0, "elapsed_ms": None, "json_keys": [], "error": "blocked_guessed_object_id"},
                    "other": {"status_code": None, "body_length": 0, "elapsed_ms": None, "json_keys": [], "error": "blocked_guessed_object_id"},
                    "similarity": 0.0,
                    "failure_analysis": failure_analysis,
                    "replan": replan,
                },
                raw_status="blocked",
                indicators=["invalid_object_id", "non_authorization_error"],
                artifacts=[
                    Artifact(type="blocked_object_id", value={"object_id": guessed_object_id, "reason": replan["reason"]}),
                ],
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

        logger.info(
            "Auth test completed task_id=%s endpoint=%s owner_role=%s other_role=%s owner_status=%s other_status=%s similarity=%.4f indicators=%s raw_status=%s",
            request.task.id,
            endpoint,
            owner_role,
            other_role,
            owner_result.status_code,
            other_result.status_code,
            similarity,
            indicators,
            raw_status,
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
                },
                "other": {
                    "status_code": other_result.status_code,
                    "body_length": len(other_result.body_text or ""),
                    "elapsed_ms": other_result.elapsed_ms,
                    "json_keys": shared_keys if other_result.json_body() is not None else [],
                    "error": other_result.error,
                },
                "similarity": similarity,
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
            ],
        )

    async def run_injection_test(self, request: ToolTestRequest) -> ToolTestResponse:
        endpoint = self._resolve_url(
            str(request.execution_context.target_url),
            str(request.arguments.get("endpoint") or request.task.endpoint),
        )
        self._validate_scope(request, endpoint)
        method = str(request.arguments.get("method") or request.task.method).upper()
        payload = request.arguments.get("payload", "' OR '1'='1")

        return ToolTestResponse(
            request_summary={
                "method": method,
                "endpoint": endpoint,
                "payload_preview": str(payload)[:120],
            },
            response_summary={
                "status_code": 200,
                "body_preview": '{"result":"stubbed-injection-response"}',
                "elapsed_ms": 84,
            },
            raw_status="ok",
            indicators=["possible_injection", "input_reflection_or_behavior_change"],
            artifacts=[
                Artifact(
                    type="injection_test_run",
                    value=f"artifact:injection:{uuid.uuid4()}",
                )
            ],
        )

    async def run_logic_test(self, request: ToolTestRequest) -> ToolTestResponse:
        endpoint = self._resolve_url(
            str(request.execution_context.target_url),
            str(request.arguments.get("endpoint") or request.task.endpoint),
        )
        self._validate_scope(request, endpoint)
        method = str(request.arguments.get("method") or request.task.method).upper()

        return ToolTestResponse(
            request_summary={
                "method": method,
                "endpoint": endpoint,
                "sequence": request.arguments.get("sequence", ["step1", "step2"]),
            },
            response_summary={
                "status_code": 200,
                "body_preview": '{"result":"stubbed-business-logic-response"}',
                "elapsed_ms": 112,
            },
            raw_status="ok",
            indicators=["possible_business_logic_issue"],
            artifacts=[
                Artifact(
                    type="logic_test_run",
                    value=f"artifact:logic:{uuid.uuid4()}",
                )
            ],
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
            role_name = str(item.get("name") or item.get("role") or "").strip()
            if role_name:
                profiles[role_name] = item
        return profiles

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

        return headers

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
