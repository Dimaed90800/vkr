"""Diagnostic-only auth flow candidate detection from OpenAPI graph metadata.

Does not perform HTTP, signup, login, or store secrets.
"""
from __future__ import annotations

import re
import time
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.api_graph import Operation
    from backend.models.tool_run import (
        ToolResult,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.api_graph_service import ApiGraphService
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.api_graph import Operation
    from models.tool_run import (
        ToolResult,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.api_graph_service import ApiGraphService


def _norm_ident(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _field_set(fields: list[str] | None) -> set[str]:
    return {_norm_ident(x) for x in (fields or []) if str(x).strip()}


def _blob(path: str, op_id: str) -> str:
    return f"{path} {op_id}".lower()


def path_segments_lower(path: str) -> list[str]:
    return [s.lower() for s in (path or "").split("/") if s.strip()]


def _signup_path_match(blob: str) -> bool:
    b = blob.replace("-", "").replace("_", "")
    return any(
        needle in b
        for needle in ("signup", "register", "createuser", "create_user", "/users")
    )


def _excluded_from_normal_login_blob(blob: str) -> bool:
    """Paths/operation ids that look like auth but are not password login."""
    b = blob.replace("-", "").replace("_", "").replace("/", "").lower()
    return any(
        frag in b
        for frag in (
            "checkotp",
            "verifyotp",
            "forgetpassword",
            "forgotpassword",
            "resetpassword",
            "loginwithtoken",
            "refreshtoken",
        )
    )


def _password_login_path_ok(path: str, op_id: str) -> bool:
    """True when path suggests a normal password login endpoint (segment login or /login)."""
    blob = _blob(path, op_id)
    if _excluded_from_normal_login_blob(blob):
        return False
    segs = path_segments_lower(path)
    if any(s == "login" for s in segs):
        return True
    oid = (op_id or "").lower()
    if "/login" in oid or oid.endswith("login"):
        if "login-with-token" in oid.replace("_", "-") or "loginwithtoken" in oid.replace("-", "").replace("_", ""):
            return False
        return True
    return False


def _otp_like_blob(blob: str) -> bool:
    b = blob.replace("-", "").replace("_", "").lower()
    return "checkotp" in b or "verifyotp" in b or ("/otp" in blob.lower() and "login" not in blob.lower())


def _password_reset_like_blob(blob: str) -> bool:
    b = blob.replace("-", "").replace("_", "").lower()
    return "forget" in b or "forgot" in b or "resetpassword" in b


def _token_login_like_blob(blob: str) -> bool:
    b = blob.replace("-", "").replace("_", "").lower()
    return "loginwithtoken" in b or ("refresh" in b and "token" in b)


def _signup_credential_pair(names: set[str]) -> bool:
    has_pw = "password" in names or "passwd" in names
    if not has_pw:
        return False
    email_like = bool({"email", "mail"} & names)
    user_like = bool({"username", "user", "login", "name"} & names)
    return email_like or user_like


def _login_credential_pair(names: set[str]) -> bool:
    """Login: email+password OR username+password (not name-only + password)."""
    has_pw = "password" in names or "passwd" in names
    if not has_pw:
        return False
    if bool({"email", "mail"} & names):
        return True
    if bool({"username"} & names):
        return True
    if bool({"user", "login"} & names) and not bool({"email", "mail", "name"} & names):
        return True
    return False


def _profile_path_match(path: str) -> bool:
    p = path.lower()
    return any(
        frag in p
        for frag in ("/me", "/profile", "/user", "/account")
    )


def _token_response_fields(resp_fields: set[str]) -> bool:
    needles = {"token", "accesstoken", "access_token", "refreshtoken", "refresh_token", "jwt", "session"}
    return bool(resp_fields & needles)


class AuthFlowDetectorAdapter:
    def __init__(self, graph: ApiGraphService | None = None) -> None:
        self._graph = graph or ApiGraphService()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        max_ops = int(inputs.get("max_operations_scanned") or 200)
        max_ops = max(1, min(max_ops, 500))

        operations = self._graph.list_operations(campaign.campaign_id)[:max_ops]
        signup: list[dict[str, Any]] = []
        login: list[dict[str, Any]] = []
        otp_c: list[dict[str, Any]] = []
        pwd_reset: list[dict[str, Any]] = []
        token_login: list[dict[str, Any]] = []
        token_resp: list[dict[str, Any]] = []
        profile: list[dict[str, Any]] = []

        for op in operations:
            self._classify_operation(
                op, signup, login, otp_c, pwd_reset, token_login, token_resp, profile,
            )

        detected = bool(signup or login or token_resp or profile or otp_c or pwd_reset or token_login)
        reason_codes: list[str] = []
        if not detected:
            reason_codes.append("no_auth_flow_patterns")

        details: dict[str, Any] = {
            "source": "auth_flow_detector",
            "validation_mode": "auth_flow_detection",
            "auth_flow_detected": detected,
            "signup_candidates": signup[:15],
            "login_candidates": login[:15],
            "otp_candidates": otp_c[:10],
            "password_reset_candidates": pwd_reset[:10],
            "token_login_candidates": token_login[:10],
            "token_response_candidates": token_resp[:15],
            "profile_candidates": profile[:15],
            "missing_prerequisites": [],
            "reason_codes": reason_codes,
        }

        obs = ToolResultObservationLite(
            observation_type="auth_flow_signal",
            confidence=0.25 if detected else 0.1,
            details=details,
        )
        duration_ms = int(time.monotonic() * 1000) - start_ms
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=0,
                success_count=1,
                client_error_count=0,
                server_error_count=0,
                duration_ms=duration_ms,
            ),
            requests=[],
            responses=[],
            observations=[obs],
            artifacts=[],
        )

    def _classify_operation(
        self,
        op: Operation,
        signup: list[dict[str, Any]],
        login: list[dict[str, Any]],
        otp_c: list[dict[str, Any]],
        pwd_reset: list[dict[str, Any]],
        token_login: list[dict[str, Any]],
        token_resp: list[dict[str, Any]],
        profile: list[dict[str, Any]],
    ) -> None:
        method = str(op.method or "").strip().upper() or "GET"
        path = str(op.path_template or "").strip()
        op_id = str(op.operation_id or "").strip()
        blob = _blob(path, op_id)
        body_names = _field_set(list(op.body_fields or []))
        resp_names = _field_set(list(op.response_fields or []))
        has_pw = "password" in body_names or "passwd" in body_names

        if method == "GET" and _profile_path_match(path):
            profile.append(self._candidate_row(op, ["path_profile_me_user_account"], "medium"))

        if method == "POST" and _signup_path_match(blob) and body_names and has_pw:
            rc = ["path_signup_register", "password_field_in_body"]
            if _signup_credential_pair(body_names):
                rc.append("email_or_username_password_fields")
            elif body_names & {"name", "username", "email", "mail", "number"}:
                rc.append("identity_like_fields")
            conf = "high" if "email_or_username_password_fields" in rc else "medium"
            signup.append(self._candidate_row(op, rc, conf))

        if method == "POST" and body_names and has_pw:
            if (
                _password_login_path_ok(path, op_id)
                and _login_credential_pair(body_names)
                and not _excluded_from_normal_login_blob(blob)
            ):
                login.append(self._candidate_row(op, ["path_password_login", "email_or_username_password_fields"], "high"))
            elif _excluded_from_normal_login_blob(blob):
                if _password_reset_like_blob(blob):
                    pwd_reset.append(self._candidate_row(op, ["password_reset_flow"], "low"))
                elif _token_login_like_blob(blob):
                    token_login.append(self._candidate_row(op, ["token_based_login_flow"], "low"))
                elif _otp_like_blob(blob):
                    otp_c.append(self._candidate_row(op, ["otp_or_verification_flow"], "low"))

        if _token_response_fields(resp_names):
            token_resp.append(self._candidate_row(op, ["response_token_like_fields"], "high"))
        elif method in {"POST", "PUT", "PATCH"} and (
            "token" in blob or "/token" in path.lower()
        ) and _token_response_fields(body_names | resp_names):
            token_resp.append(self._candidate_row(op, ["path_token_hint", "mutation_method", "token_like_fields"], "medium"))

    @staticmethod
    def _candidate_row(op: Operation, reason_codes: list[str], confidence: str) -> dict[str, Any]:
        return {
            "operation_id": op.operation_id,
            "method": str(op.method or "").strip().upper() or "GET",
            "path": str(op.path_template or "").strip(),
            "confidence": confidence,
            "reason_codes": reason_codes,
        }
