"""Backend-only test account materializer.

Creates bounded owner/attacker test identities from detected signup/login
operations, performs safe in-scope signup/login requests, and stores only
runtime secret refs plus sanitized auth profile metadata.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any
from urllib.parse import urljoin
try:
    from backend.models.api_graph import Operation
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.adapters.auth_flow_detector_adapter import (
        _blob,
        _field_set,
        _login_credential_pair,
        _password_login_path_ok,
        _signup_credential_pair,
        path_segments_lower,
    )
    from backend.services.api_graph_path_matcher import normalize_api_path
    from backend.services.api_graph_service import ApiGraphService
    from backend.services.artifact_store import ArtifactStore
    from backend.services.auth_profile_store import AuthProfileStore
    from backend.services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import Operation
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.adapters.auth_flow_detector_adapter import (
        _blob,
        _field_set,
        _login_credential_pair,
        _password_login_path_ok,
        _signup_credential_pair,
        path_segments_lower,
    )
    from services.api_graph_path_matcher import normalize_api_path
    from services.api_graph_service import ApiGraphService
    from services.artifact_store import ArtifactStore
    from services.auth_profile_store import AuthProfileStore
    from services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage


_TOKEN_KEYS = ("token", "access_token", "jwt", "session", "refresh_token")


def _common_prefix_bonus(path_a: str, path_b: str) -> int:
    sa = [x.lower() for x in (path_a or "").split("/") if x]
    sb = [x.lower() for x in (path_b or "").split("/") if x]
    n = 0
    for i in range(min(len(sa), len(sb))):
        if sa[i] == sb[i]:
            n += 1
        else:
            break
    return n * 10


def _signup_materializer_score(op: Operation, materialize_mechanic: bool) -> int:
    if str(op.method or "").upper() != "POST":
        return 0
    names = _field_set(list(op.body_fields or []))
    if not ("password" in names or "passwd" in names):
        return 0
    path = str(op.path_template or "")
    op_id = str(op.operation_id or "")
    blob = _blob(path, op_id).replace("-", "").replace("_", "")
    score = 0
    if any(k in blob for k in ("signup", "register", "createuser", "create_user")):
        score += 100
    elif "users" in path_segments_lower(path) and ({"email", "mail"} & names):
        score += 70
    if _signup_credential_pair(names):
        score += 50
    if names & {"name", "number", "phone", "fullname"}:
        score += 20
    role_markers = ("mechanic", "admin", "vendor", "merchant")
    if any(r in blob for r in role_markers) and not materialize_mechanic:
        score -= 30
    return score


def _login_materializer_score(op: Operation) -> int:
    if str(op.method or "").upper() != "POST":
        return 0
    names = _field_set(list(op.body_fields or []))
    path = str(op.path_template or "")
    oid = str(op.operation_id or "")
    blob = _blob(path, oid)
    if not _login_credential_pair(names):
        return 0
    if not _password_login_path_ok(path, oid):
        return 0
    score = 80
    if any(s == "login" for s in path_segments_lower(path)) or "/login" in path.lower():
        score += 100
    return score


def _select_materialization_pair(
    operations: list[Operation],
    preferred_signup_id: str,
    preferred_login_id: str,
    materialize_mechanic: bool,
) -> tuple[Operation | None, Operation | None, dict[str, Any]]:
    signup_scores = [(op, _signup_materializer_score(op, materialize_mechanic)) for op in operations]
    login_scores = [(op, _login_materializer_score(op)) for op in operations]
    su = [(o, s) for o, s in signup_scores if s > 0]
    lo = [(o, s) for o, s in login_scores if s > 0]
    attempted_s = [o.operation_id for o, s in sorted(su, key=lambda x: -x[1])[:15]]
    attempted_l = [o.operation_id for o, s in sorted(lo, key=lambda x: -x[1])[:15]]
    diag: dict[str, Any] = {
        "attempted_signup_operation_ids": attempted_s,
        "attempted_login_operation_ids": attempted_l,
    }
    if not su or not lo:
        return None, None, diag
    pref_s = str(preferred_signup_id or "").strip()
    pref_l = str(preferred_login_id or "").strip()
    best = -10**9
    best_pair: tuple[Operation, Operation] | None = None
    for s_op, s_sc in su:
        for l_op, l_sc in lo:
            bonus = _common_prefix_bonus(str(s_op.path_template or ""), str(l_op.path_template or ""))
            pref_bonus = 0
            if pref_s and s_op.operation_id == pref_s:
                pref_bonus += 25
            if pref_l and l_op.operation_id == pref_l:
                pref_bonus += 25
            total = s_sc + l_sc + bonus + pref_bonus
            if total > best:
                best = total
                best_pair = (s_op, l_op)
    if best_pair:
        s0, l0 = best_pair
        diag.update({
            "selected_signup_operation_id": s0.operation_id,
            "selected_signup_path": str(s0.path_template or ""),
            "selected_login_operation_id": l0.operation_id,
            "selected_login_path": str(l0.path_template or ""),
        })
        return s0, l0, diag
    return None, None, diag


def _payload_field_names(op: Operation) -> list[str]:
    return [str(x) for x in (op.body_fields or []) if str(x).strip()]


def _login_payload_field_names(op: Operation) -> list[str]:
    out: list[str] = []
    for raw in op.body_fields or []:
        key = str(raw or "").strip()
        nk = key.lower()
        if nk in {"email", "mail", "password", "passwd", "username", "user", "login"}:
            out.append(key)
    return out


class TestAccountMaterializerAdapter:
    __test__ = False

    def __init__(
        self,
        http_client: SafeHttpClient | None = None,
        graph: ApiGraphService | None = None,
        auth_profiles: AuthProfileStore | None = None,
    ) -> None:
        self._http = http_client or SafeHttpClient()
        self._graph = graph or ApiGraphService()
        self._profiles = auth_profiles or AuthProfileStore()
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        operations = self._graph.list_operations(campaign.campaign_id)
        materialize_mechanic = bool(inputs.get("materialize_mechanic"))
        sel_s, sel_l, pair_diag = _select_materialization_pair(
            operations,
            str(inputs.get("signup_operation_id") or ""),
            str(inputs.get("login_operation_id") or ""),
            materialize_mechanic,
        )
        signup_op = sel_s or self._find_operation(campaign.campaign_id, str(inputs.get("signup_operation_id") or ""))
        login_op = sel_l or self._find_operation(campaign.campaign_id, str(inputs.get("login_operation_id") or ""))
        validation_mode = str(inputs.get("validation_mode") or "test_account_materialization").strip() or "test_account_materialization"
        timeout_sec = min(int(command.budget.timeout_sec or 10), campaign.limits.max_duration_sec, 15)
        max_response_bytes = max(4096, int(inputs.get("max_response_bytes") or 262144))
        reason_codes: list[str] = []
        errors: list[dict[str, Any]] = []
        requests: list[ToolResultRequest] = []
        responses: list[ToolResultResponse] = []
        auth_profiles_created: list[dict[str, str]] = []
        login_success_count = 0
        signup_success_count = 0
        signup_response_status_codes: list[int] = []
        login_response_status_codes: list[int] = []
        if signup_op is not None:
            pair_diag["signup_payload_field_names"] = _payload_field_names(signup_op)
        if login_op is not None:
            pair_diag["login_payload_field_names"] = _login_payload_field_names(login_op)

        if signup_op is None or login_op is None:
            if signup_op is None:
                reason_codes.append("signup_operation_missing")
            if login_op is None:
                reason_codes.append("login_operation_missing")
            return self._finished_result(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                requests=requests,
                responses=responses,
                observation=self._observation(
                    validation_mode=validation_mode,
                    signup_operation_id=str(inputs.get("signup_operation_id") or ""),
                    login_operation_id=str(inputs.get("login_operation_id") or ""),
                    owner_auth_profile_id="",
                    attacker_auth_profile_id="",
                    signup_success_count=0,
                    login_success_count=0,
                    auth_profiles_created_count=0,
                    auth_type="unknown",
                    token_response_detected=False,
                    reason_codes=reason_codes,
                    materialization_errors=errors,
                    safe_extras=pair_diag,
                ),
                artifact_content=self._artifact_content(
                    validation_mode=validation_mode,
                    signup_operation_id=str(inputs.get("signup_operation_id") or ""),
                    login_operation_id=str(inputs.get("login_operation_id") or ""),
                    signup_success_count=0,
                    login_success_count=0,
                    auth_profiles_created_count=0,
                    result="materialization_failed",
                    reason_codes=reason_codes,
                    safe_extras=pair_diag,
                ),
            )

        identities = [
            _identity_bundle(campaign.campaign_id, "owner"),
            _identity_bundle(campaign.campaign_id, "attacker"),
        ]
        for ident in identities:
            signup_payload = _build_signup_payload(signup_op, ident)
            signup_url = _operation_url(campaign.target_url, signup_op.path_template)
            signup_req_id = f"req_signup_{ident['role_hint']}"
            signup_result = self._http.request(
                campaign,
                method=str(signup_op.method or "POST").upper(),
                url=signup_url,
                body=signup_payload,
                timeout_sec=timeout_sec,
                max_response_bytes=max_response_bytes,
                follow_redirects=False,
            )
            requests.append(
                ToolResultRequest(
                    request_id=signup_req_id,
                    role=ident["role_hint"],
                    method=str(signup_op.method or "POST").upper(),
                    url=sanitize_url_for_storage(signup_url),
                    path_template=normalize_api_path(signup_op.path_template),
                )
            )
            sc_signup = int(signup_result.status_code or 0)
            responses.append(ToolResultResponse(request_id=signup_req_id, status_code=sc_signup))
            signup_response_status_codes.append(sc_signup)
            if signup_result.error is None and _is_success_status(sc_signup):
                signup_success_count += 1
            else:
                reason_codes.append(f"signup_{ident['role_hint']}_failed")
                errors.append(_safe_error("signup", ident["role_hint"], signup_result))
                continue

            login_payload = _build_login_payload(login_op, ident)
            login_url = _operation_url(campaign.target_url, login_op.path_template)
            login_req_id = f"req_login_{ident['role_hint']}"
            login_result = self._http.request(
                campaign,
                method=str(login_op.method or "POST").upper(),
                url=login_url,
                body=login_payload,
                timeout_sec=timeout_sec,
                max_response_bytes=max_response_bytes,
                follow_redirects=False,
            )
            requests.append(
                ToolResultRequest(
                    request_id=login_req_id,
                    role=ident["role_hint"],
                    method=str(login_op.method or "POST").upper(),
                    url=sanitize_url_for_storage(login_url),
                    path_template=normalize_api_path(login_op.path_template),
                )
            )
            sc_login = int(login_result.status_code or 0)
            responses.append(ToolResultResponse(request_id=login_req_id, status_code=sc_login))
            login_response_status_codes.append(sc_login)
            if login_result.error is not None or not _is_success_status(sc_login):
                reason_codes.append(f"login_{ident['role_hint']}_failed")
                if sc_login == 403:
                    if "login_http_403" not in reason_codes:
                        reason_codes.append("login_http_403")
                    if "possible_invalid_credentials_or_wrong_login_endpoint" not in reason_codes:
                        reason_codes.append("possible_invalid_credentials_or_wrong_login_endpoint")
                errors.append(_safe_error("login", ident["role_hint"], login_result))
                continue

            login_success_count += 1
            raw_body = login_result.get_raw_response_body()
            token_value, token_field_path = _extract_token_candidate(raw_body)
            auth_type = "unknown"
            raw_secret: Any = None
            if token_value:
                auth_type = "bearer"
                raw_secret = token_value
            else:
                raw_cookies = login_result.get_raw_response_cookies()
                if raw_cookies:
                    auth_type = "cookie"
                    raw_secret = raw_cookies

            if raw_secret in (None, "", {}):
                reason_codes.append(f"token_missing_{ident['role_hint']}")
                errors.append({
                    "stage": "login",
                    "user_label": ident["user_label"],
                    "error_type": "token_not_found",
                    "status_code": int(login_result.status_code or 0),
                })
                continue

            profile = self._profiles.create_auth_profile(
                campaign_id=campaign.campaign_id,
                role_hint=ident["role_hint"],
                user_label=ident["user_label"],
                auth_type=auth_type,
                raw_token=raw_secret,
                raw_credentials={
                    "email": ident["email"],
                    "username": ident["username"],
                    "password": ident["password"],
                },
                created_by="test_account_materializer",
                metadata={
                    "signup_operation_id": signup_op.operation_id,
                    "login_operation_id": login_op.operation_id,
                    "token_field_path": token_field_path,
                },
            )
            auth_profiles_created.append({
                "role_hint": ident["role_hint"],
                "auth_profile_id": profile.auth_profile_id,
                "auth_type": auth_type,
            })

        created_count = len(auth_profiles_created)
        owner_profile_id = next((x["auth_profile_id"] for x in auth_profiles_created if x["role_hint"] == "owner"), "")
        attacker_profile_id = next((x["auth_profile_id"] for x in auth_profiles_created if x["role_hint"] == "attacker"), "")
        auth_type = _aggregate_auth_type(auth_profiles_created)
        token_detected = created_count > 0
        if created_count >= 2:
            reason_codes.append("materialization_succeeded")
            result_name = "materialization_succeeded"
        elif created_count > 0:
            reason_codes.append("materialization_partial")
            result_name = "materialization_partial"
        else:
            reason_codes.append("materialization_failed")
            result_name = "materialization_failed"

        pair_diag["signup_response_status_codes"] = signup_response_status_codes
        pair_diag["login_response_status_codes"] = login_response_status_codes
        safe_extras = dict(pair_diag)

        return self._finished_result(
            command=command,
            tool_run_id=tool_run_id,
            start_ms=start_ms,
            requests=requests,
            responses=responses,
            observation=self._observation(
                validation_mode=validation_mode,
                signup_operation_id=signup_op.operation_id,
                login_operation_id=login_op.operation_id,
                owner_auth_profile_id=owner_profile_id,
                attacker_auth_profile_id=attacker_profile_id,
                signup_success_count=signup_success_count,
                login_success_count=login_success_count,
                auth_profiles_created_count=created_count,
                auth_type=auth_type,
                token_response_detected=token_detected,
                reason_codes=reason_codes,
                materialization_errors=errors,
                safe_extras=safe_extras,
            ),
            artifact_content=self._artifact_content(
                validation_mode=validation_mode,
                signup_operation_id=signup_op.operation_id,
                login_operation_id=login_op.operation_id,
                signup_success_count=signup_success_count,
                login_success_count=login_success_count,
                auth_profiles_created_count=created_count,
                result=result_name,
                reason_codes=reason_codes,
                safe_extras=safe_extras,
            ),
        )

    def _find_operation(self, campaign_id: str, operation_id: str) -> Operation | None:
        wanted = str(operation_id or "").strip()
        if not wanted:
            return None
        for op in self._graph.list_operations(campaign_id):
            if op.operation_id == wanted:
                return op
        return None

    def _finished_result(
        self,
        *,
        command: WorkerCommand,
        tool_run_id: str,
        start_ms: int,
        requests: list[ToolResultRequest],
        responses: list[ToolResultResponse],
        observation: ToolResultObservationLite,
        artifact_content: dict[str, Any],
    ) -> ToolResult:
        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="test_account_materialization_summary",
            content=artifact_content,
        )
        duration_ms = int(time.monotonic() * 1000) - start_ms
        success_count = sum(1 for r in responses if _is_success_status(int(r.status_code or 0)))
        client_error_count = sum(1 for r in responses if 400 <= int(r.status_code or 0) <= 499)
        server_error_count = sum(1 for r in responses if 500 <= int(r.status_code or 0) <= 599)
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=len(requests),
                success_count=success_count,
                client_error_count=client_error_count,
                server_error_count=server_error_count,
                duration_ms=duration_ms,
            ),
            requests=requests,
            responses=responses,
            observations=[observation],
            artifacts=[artifact],
        )

    @staticmethod
    def _observation(
        *,
        validation_mode: str,
        signup_operation_id: str,
        login_operation_id: str,
        owner_auth_profile_id: str,
        attacker_auth_profile_id: str,
        signup_success_count: int,
        login_success_count: int,
        auth_profiles_created_count: int,
        auth_type: str,
        token_response_detected: bool,
        reason_codes: list[str],
        materialization_errors: list[dict[str, Any]],
        safe_extras: dict[str, Any] | None = None,
    ) -> ToolResultObservationLite:
        details: dict[str, Any] = {
            "source": "test_account_materializer",
            "validation_mode": validation_mode,
            "signup_operation_id": signup_operation_id,
            "login_operation_id": login_operation_id,
            "owner_auth_profile_id": owner_auth_profile_id,
            "attacker_auth_profile_id": attacker_auth_profile_id,
            "signup_success_count": signup_success_count,
            "login_success_count": login_success_count,
            "auth_profiles_created_count": auth_profiles_created_count,
            "auth_type": auth_type,
            "token_response_detected": token_response_detected,
            "reason_codes": reason_codes[:20],
            "materialization_errors": materialization_errors[:10],
        }
        if isinstance(safe_extras, dict):
            for k, v in safe_extras.items():
                if k in details:
                    continue
                details[k] = v
        return ToolResultObservationLite(
            observation_type="test_account_materialization_result",
            confidence=0.55 if auth_profiles_created_count >= 2 else 0.3,
            details=details,
        )

    @staticmethod
    def _artifact_content(
        *,
        validation_mode: str,
        signup_operation_id: str,
        login_operation_id: str,
        signup_success_count: int,
        login_success_count: int,
        auth_profiles_created_count: int,
        result: str,
        reason_codes: list[str],
        safe_extras: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        out: dict[str, Any] = {
            "validation_mode": validation_mode,
            "signup_operation_id": signup_operation_id,
            "login_operation_id": login_operation_id,
            "signup_success_count": signup_success_count,
            "login_success_count": login_success_count,
            "auth_profiles_created_count": auth_profiles_created_count,
            "result": result,
            "reason_codes": reason_codes[:20],
        }
        if isinstance(safe_extras, dict):
            for k, v in safe_extras.items():
                if k in out:
                    continue
                out[k] = v
        return out


def _identity_bundle(campaign_id: str, role_hint: str) -> dict[str, str]:
    suffix = hashlib.sha256(f"{campaign_id}:{role_hint}:v1material".encode("utf-8")).hexdigest()[:8]
    short = (campaign_id or "cmp").replace("cmp_", "")[:8] or "cmp"
    local = f"vkr_{role_hint}_{short}_{suffix}"
    digits = "".join(ch for ch in suffix if ch.isdigit()) or "31415926"
    return {
        "role_hint": role_hint,
        "user_label": f"{role_hint}_user",
        "email": f"{local}@example.test",
        "username": local[:32],
        "password": f"Vkr!{suffix}Pass9",
        "number": (digits * 3)[:10],
        "name": "VKR Owner" if role_hint == "owner" else "VKR Attacker",
    }


def _build_signup_payload(op: Operation, identity: dict[str, str]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for raw in op.body_fields or []:
        key = str(raw or "").strip()
        lowered = key.lower()
        if not key:
            continue
        if lowered in {"email", "mail"}:
            payload[key] = identity["email"]
        elif lowered in {"password", "passwd"}:
            payload[key] = identity["password"]
        elif lowered in {"username", "user", "login"}:
            payload[key] = identity["username"]
        elif lowered in {"name", "fullname", "displayname"}:
            payload[key] = identity["name"]
        elif lowered in {"number", "phone", "phonenumber"}:
            payload[key] = identity["number"]
        elif lowered == "role":
            continue
        elif any(part in lowered for part in ("count", "age", "qty", "quantity", "total")):
            payload[key] = 1
        elif lowered.startswith("is") or lowered.startswith("has"):
            payload[key] = False
        else:
            payload[key] = f"test_{identity['role_hint']}_{lowered}"[:80]
    return payload


def _build_login_payload(op: Operation, identity: dict[str, str]) -> dict[str, Any]:
    """Only credential fields present on the login operation schema (no signup-only fields)."""
    payload: dict[str, Any] = {}
    for raw in op.body_fields or []:
        key = str(raw or "").strip()
        lowered = key.lower()
        if not key:
            continue
        if lowered in {"email", "mail"}:
            payload[key] = identity["email"]
        elif lowered in {"password", "passwd"}:
            payload[key] = identity["password"]
        elif lowered == "username":
            payload[key] = identity["username"]
        elif lowered in {"user", "login"}:
            payload[key] = identity["email"]
        else:
            continue
    return payload


def _operation_url(target_url: str, path_template: str) -> str:
    return urljoin(str(target_url or "").rstrip("/") + "/", str(path_template or "").lstrip("/"))


def _is_success_status(status_code: int) -> bool:
    return 200 <= int(status_code or 0) <= 399


def _safe_error(stage: str, role_hint: str, result: Any) -> dict[str, Any]:
    err = getattr(result, "error", None)
    return {
        "stage": stage,
        "user_label": f"{role_hint}_user",
        "error_type": str(getattr(err, "code", "") or "request_failed"),
        "status_code": int(getattr(result, "status_code", 0) or 0),
    }


def _extract_token_candidate(body: Any, path: str = "$") -> tuple[str, str]:
    if isinstance(body, dict):
        for key in _TOKEN_KEYS:
            if key in body:
                value = body.get(key)
                if isinstance(value, (str, int, float)) and str(value).strip():
                    return str(value), f"{path}.{key}"
        for key, value in body.items():
            child_path = f"{path}.{key}"
            found, field_path = _extract_token_candidate(value, child_path)
            if found:
                return found, field_path
    elif isinstance(body, list):
        for idx, value in enumerate(body):
            found, field_path = _extract_token_candidate(value, f"{path}[{idx}]")
            if found:
                return found, field_path
    return "", ""


def _aggregate_auth_type(profiles: list[dict[str, str]]) -> str:
    types = {str(item.get("auth_type") or "unknown") for item in profiles if str(item.get("auth_type") or "").strip()}
    if len(types) == 1:
        return next(iter(types))
    if "bearer" in types and len(types) == 1:
        return "bearer"
    if "cookie" in types and len(types) == 1:
        return "cookie"
    return "unknown"
