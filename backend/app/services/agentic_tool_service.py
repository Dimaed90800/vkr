from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException

from ..models import Observation, RoleCredential, TestSession
from .analysis_service import compare_observations
from .bola_service import infer_bola_from_observations
from .bopla_service import analyze_bopla_observation
from .http_service import send_request
from .openapi_service import find_openapi_document, parse_openapi_spec
from .role_service import extract_tokens_from_response_text, generate_unique_identity
from .zap_baseline_service import run_zap_baseline
from .zap_service import run_active_scan_and_wait, run_ajax_spider_and_wait, run_spider_and_wait

_ALLOWED_AGENTIC_TOOLS = {
    "bootstrap_roles",
    "compare_observations",
    "discover_openapi",
    "get_session_context",
    "infer_bola",
    "infer_bopla",
    "login_role",
    "list_roles",
    "list_observations",
    "measure_timing_delta",
    "probe_same_object_across_roles",
    "register_role",
    "replay_request",
    "replay_with_body_override",
    "replay_with_param_override",
    "replay_with_payloads",
    "register_role",
    "zap_active_scan",
    "zap_ajax_spider",
    "zap_baseline_scan",
    "zap_spider",
}


def get_allowed_agentic_tools() -> list[str]:
    return sorted(_ALLOWED_AGENTIC_TOOLS)


def _get_session(db, session_id: int) -> TestSession:
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        raise HTTPException(status_code=404, detail="Session not found")
    return session_obj


def _get_role(db, session_id: int, role_name: str) -> RoleCredential:
    role = db.query(RoleCredential).filter(
        RoleCredential.session_id == session_id,
        RoleCredential.role_name == role_name,
    ).first()
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{role_name}' not found")
    return role


def _serialize_observation(obs: Observation) -> dict[str, Any]:
    return {
        "id": obs.id,
        "endpoint": obs.endpoint,
        "method": obs.method,
        "role_name": obs.role_name,
        "status_code": obs.status_code,
        "body_preview": (obs.body_preview or "")[:500],
    }


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value or {}) if isinstance(value or {}, dict) else {}


def _clone_jsonable_dict(value: Any) -> dict[str, Any]:
    return json.loads(json.dumps(_safe_dict(value), ensure_ascii=False))


def _apply_nested_override(target: dict[str, Any], dotted_key: str, value: Any) -> None:
    dotted_key = str(dotted_key or "").strip()
    if not dotted_key:
        return

    parts = [part for part in dotted_key.split(".") if part]
    if not parts:
        return

    current = target
    for part in parts[:-1]:
        existing = current.get(part)
        if not isinstance(existing, dict):
            existing = {}
            current[part] = existing
        current = existing
    current[parts[-1]] = value


def _prepare_request_parts(
    db,
    *,
    session_id: int,
    endpoint: str,
    method: str,
    role_name: str | None,
    use_role_token: bool,
    headers: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> tuple[str, str, str | None, dict[str, Any], dict[str, Any], dict[str, Any]]:
    _get_session(db, session_id)

    normalized_endpoint = str(endpoint or "").strip()
    normalized_method = str(method or "GET").upper()
    normalized_role_name = str(role_name or "").strip() or None
    normalized_headers = _clone_jsonable_dict(headers)
    normalized_params = _clone_jsonable_dict(params)
    normalized_json_body = _clone_jsonable_dict(json_body)

    if not normalized_endpoint:
        raise HTTPException(status_code=400, detail="endpoint is required")

    if use_role_token:
        if not normalized_role_name:
            raise HTTPException(status_code=400, detail="role_name is required when use_role_token=true")
        role = _get_role(db, session_id, normalized_role_name)
        if not role.access_token:
            raise HTTPException(status_code=400, detail=f"Role '{normalized_role_name}' has no access token")
        normalized_headers["Authorization"] = f"{role.token_type or 'Bearer'} {role.access_token}"

    return (
        normalized_endpoint,
        normalized_method,
        normalized_role_name,
        normalized_headers,
        normalized_params,
        normalized_json_body,
    )


def _execute_and_store_request(
    db,
    *,
    session_id: int,
    endpoint: str,
    method: str,
    role_name: str | None,
    headers: dict[str, Any],
    params: dict[str, Any],
    json_body: dict[str, Any],
) -> tuple[dict[str, Any], Observation]:
    result = send_request(
        method=method,
        url=endpoint,
        headers=headers,
        params=params,
        json_body=json_body,
    )
    observation = _store_observation(
        db,
        session_id=session_id,
        endpoint=endpoint,
        method=method,
        role_name=role_name,
        request_headers=headers,
        request_params=params,
        request_body=json_body,
        result=result,
    )
    return result, observation


def _serialize_execution(observation: Observation, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "observation": _serialize_observation(observation),
        "status_code": result.get("status_code"),
        "elapsed_ms": result.get("elapsed_ms"),
        "response_preview": (result.get("text") or "")[:500],
    }


def _store_observation(
    db,
    *,
    session_id: int,
    endpoint: str,
    method: str,
    role_name: str | None,
    request_headers: dict[str, Any] | None,
    request_params: dict[str, Any] | None,
    request_body: dict[str, Any] | None,
    result: dict[str, Any],
) -> Observation:
    obs = Observation(
        session_id=session_id,
        endpoint=endpoint,
        method=method.upper(),
        role_name=role_name,
        request_headers=json.dumps(request_headers or {}, ensure_ascii=False),
        request_params=json.dumps(request_params or {}, ensure_ascii=False),
        request_body=json.dumps(request_body or {}, ensure_ascii=False),
        status_code=result.get("status_code"),
        response_headers=json.dumps(result.get("headers") or {}, ensure_ascii=False),
        body_preview=(result.get("text") or "")[:5000],
    )
    db.add(obs)
    db.commit()
    db.refresh(obs)
    return obs


def build_agentic_session_context(db, session_id: int) -> dict[str, Any]:
    session_obj = _get_session(db, session_id)
    roles = db.query(RoleCredential).filter(
        RoleCredential.session_id == session_id
    ).order_by(RoleCredential.id.asc()).all()
    observations = db.query(Observation).filter(
        Observation.session_id == session_id
    ).order_by(Observation.id.desc()).limit(10).all()

    return {
        "session": {
            "id": session_obj.id,
            "target_name": session_obj.target_name,
            "target_url": session_obj.target_url,
            "status": session_obj.status,
            "rounds_completed": session_obj.rounds_completed,
            "max_rounds": session_obj.max_rounds,
            "budget_requests_used": session_obj.budget_requests_used,
            "budget_requests_total": session_obj.budget_requests_total,
        },
        "roles": [
            {
                "role_name": item.role_name,
                "status": item.status,
                "has_access_token": bool(item.access_token),
                "last_auth_status": item.last_auth_status,
            }
            for item in roles
        ],
        "recent_observations": [_serialize_observation(item) for item in observations],
        "available_tools": get_allowed_agentic_tools(),
    }


def execute_agentic_tool_command(db, *, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if tool_name not in _ALLOWED_AGENTIC_TOOLS:
        raise HTTPException(status_code=400, detail=f"Tool '{tool_name}' is not allowed")

    arguments = dict(arguments or {})

    if tool_name == "bootstrap_roles":
        session_id = int(arguments.get("session_id") or 0)
        role_names = arguments.get("role_names") or ["user_a", "user_b"]
        if not isinstance(role_names, list):
            raise HTTPException(status_code=400, detail="role_names must be a list")
        session_obj = _get_session(db, session_id)

        created_roles = []
        for role_name in role_names:
            role_name = str(role_name or "").strip()
            if not role_name:
                continue
            existing = db.query(RoleCredential).filter(
                RoleCredential.session_id == session_id,
                RoleCredential.role_name == role_name,
            ).first()
            if existing:
                created_roles.append(
                    {
                        "role_name": existing.role_name,
                        "status": existing.status,
                        "created": False,
                    }
                )
                continue

            identity = generate_unique_identity(role_name)
            role = RoleCredential(
                session_id=session_id,
                role_name=role_name,
                email=identity["email"],
                password=identity["password"],
                phone_number=identity["phone_number"],
                status="created",
                notes=json.dumps({"name": identity["name"]}, ensure_ascii=False),
            )
            db.add(role)
            db.commit()
            db.refresh(role)
            created_roles.append(
                {
                    "role_name": role.role_name,
                    "status": role.status,
                    "created": True,
                }
            )
        session_obj.status = "bootstrap_ready"
        db.commit()
        return {
            "session_id": session_id,
            "roles": created_roles,
        }

    if tool_name == "get_session_context":
        session_id = int(arguments.get("session_id") or 0)
        return build_agentic_session_context(db, session_id)

    if tool_name == "discover_openapi":
        session_id = int(arguments.get("session_id") or 0)
        session_obj = _get_session(db, session_id)
        openapi_url, spec = find_openapi_document(session_obj.target_url)
        endpoints = parse_openapi_spec(spec) if openapi_url and spec else []
        return {
            "session_id": session_id,
            "target_url": session_obj.target_url,
            "discovered": bool(openapi_url and spec),
            "openapi_url": openapi_url,
            "endpoints_total": len(endpoints),
            "endpoints": endpoints[:100],
        }

    if tool_name == "list_roles":
        session_id = int(arguments.get("session_id") or 0)
        _get_session(db, session_id)
        roles = db.query(RoleCredential).filter(
            RoleCredential.session_id == session_id
        ).order_by(RoleCredential.id.asc()).all()
        return {
            "session_id": session_id,
            "roles": [
                {
                    "role_name": item.role_name,
                    "status": item.status,
                    "has_access_token": bool(item.access_token),
                    "last_auth_status": item.last_auth_status,
                }
                for item in roles
            ],
        }

    if tool_name == "list_observations":
        session_id = int(arguments.get("session_id") or 0)
        limit = min(max(int(arguments.get("limit") or 10), 1), 50)
        role_name = str(arguments.get("role_name") or "").strip() or None
        endpoint = str(arguments.get("endpoint") or "").strip() or None
        _get_session(db, session_id)

        query = db.query(Observation).filter(Observation.session_id == session_id)
        if role_name:
            query = query.filter(Observation.role_name == role_name)
        if endpoint:
            query = query.filter(Observation.endpoint == endpoint)
        observations = query.order_by(Observation.id.desc()).limit(limit).all()
        return {
            "session_id": session_id,
            "observations": [_serialize_observation(item) for item in observations],
        }

    if tool_name == "replay_request":
        session_id = int(arguments.get("session_id") or 0)
        endpoint = arguments.get("endpoint")
        method = arguments.get("method") or "GET"
        role_name = arguments.get("role_name")
        headers = arguments.get("headers") or {}
        params = arguments.get("params") or {}
        json_body = arguments.get("json_body") or {}
        use_role_token = bool(arguments.get("use_role_token"))
        (
            endpoint,
            method,
            role_name,
            headers,
            params,
            json_body,
        ) = _prepare_request_parts(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            use_role_token=use_role_token,
            headers=headers,
            params=params,
            json_body=json_body,
        )

        result, observation = _execute_and_store_request(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            headers=headers,
            params=params,
            json_body=json_body,
        )
        return {
            "session_id": session_id,
            "observation": _serialize_observation(observation),
        }

    if tool_name == "replay_with_param_override":
        session_id = int(arguments.get("session_id") or 0)
        endpoint = arguments.get("endpoint")
        method = arguments.get("method") or "GET"
        role_name = arguments.get("role_name")
        headers = arguments.get("headers") or {}
        params = arguments.get("params") or {}
        json_body = arguments.get("json_body") or {}
        use_role_token = bool(arguments.get("use_role_token"))
        overrides = _safe_dict(arguments.get("param_overrides"))
        if not overrides:
            raise HTTPException(status_code=400, detail="param_overrides must be a non-empty object")

        (
            endpoint,
            method,
            role_name,
            headers,
            params,
            json_body,
        ) = _prepare_request_parts(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            use_role_token=use_role_token,
            headers=headers,
            params=params,
            json_body=json_body,
        )
        params.update(overrides)
        result, observation = _execute_and_store_request(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            headers=headers,
            params=params,
            json_body=json_body,
        )
        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "applied_overrides": overrides,
            "execution": _serialize_execution(observation, result),
        }

    if tool_name == "replay_with_body_override":
        session_id = int(arguments.get("session_id") or 0)
        endpoint = arguments.get("endpoint")
        method = arguments.get("method") or "GET"
        role_name = arguments.get("role_name")
        headers = arguments.get("headers") or {}
        params = arguments.get("params") or {}
        json_body = arguments.get("json_body") or {}
        use_role_token = bool(arguments.get("use_role_token"))
        overrides = _safe_dict(arguments.get("body_overrides"))
        if not overrides:
            raise HTTPException(status_code=400, detail="body_overrides must be a non-empty object")

        (
            endpoint,
            method,
            role_name,
            headers,
            params,
            json_body,
        ) = _prepare_request_parts(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            use_role_token=use_role_token,
            headers=headers,
            params=params,
            json_body=json_body,
        )
        for dotted_key, override_value in overrides.items():
            _apply_nested_override(json_body, str(dotted_key), override_value)
        result, observation = _execute_and_store_request(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            headers=headers,
            params=params,
            json_body=json_body,
        )
        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "applied_overrides": overrides,
            "execution": _serialize_execution(observation, result),
        }

    if tool_name == "replay_with_payloads":
        session_id = int(arguments.get("session_id") or 0)
        endpoint = arguments.get("endpoint")
        method = arguments.get("method") or "GET"
        role_name = arguments.get("role_name")
        headers = arguments.get("headers") or {}
        params = arguments.get("params") or {}
        json_body = arguments.get("json_body") or {}
        use_role_token = bool(arguments.get("use_role_token"))
        injection_location = str(arguments.get("injection_location") or "").strip().lower()
        injection_key = str(arguments.get("injection_key") or "").strip()
        payloads = arguments.get("payloads") or []
        if injection_location not in {"params", "json_body", "headers"}:
            raise HTTPException(status_code=400, detail="injection_location must be one of: params, json_body, headers")
        if not injection_key:
            raise HTTPException(status_code=400, detail="injection_key is required")
        if not isinstance(payloads, list) or not payloads:
            raise HTTPException(status_code=400, detail="payloads must be a non-empty list")
        if len(payloads) > 10:
            raise HTTPException(status_code=400, detail="payloads may contain at most 10 items")

        (
            endpoint,
            method,
            role_name,
            headers,
            params,
            json_body,
        ) = _prepare_request_parts(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            use_role_token=use_role_token,
            headers=headers,
            params=params,
            json_body=json_body,
        )

        executions = []
        reflected_payload_count = 0
        error_status_count = 0

        for raw_payload in payloads:
            payload = str(raw_payload)
            run_headers = _clone_jsonable_dict(headers)
            run_params = _clone_jsonable_dict(params)
            run_json_body = _clone_jsonable_dict(json_body)
            if injection_location == "params":
                run_params[injection_key] = payload
            elif injection_location == "headers":
                run_headers[injection_key] = payload
            else:
                _apply_nested_override(run_json_body, injection_key, payload)

            result, observation = _execute_and_store_request(
                db,
                session_id=session_id,
                endpoint=endpoint,
                method=method,
                role_name=role_name,
                headers=run_headers,
                params=run_params,
                json_body=run_json_body,
            )
            response_text = result.get("text") or ""
            if payload and payload in response_text:
                reflected_payload_count += 1
            if int(result.get("status_code") or 0) >= 500:
                error_status_count += 1

            item = _serialize_execution(observation, result)
            item["payload"] = payload
            executions.append(item)

        status_codes = [item.get("status_code") for item in executions]
        unique_status_codes = sorted({code for code in status_codes if code is not None})
        anomaly_signals = []
        if error_status_count:
            anomaly_signals.append("server_error_observed")
        if reflected_payload_count:
            anomaly_signals.append("payload_reflection_observed")
        if len(unique_status_codes) > 1:
            anomaly_signals.append("status_code_variation_observed")

        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "injection_location": injection_location,
            "injection_key": injection_key,
            "executions": executions,
            "analysis": {
                "payloads_total": len(executions),
                "status_codes": unique_status_codes,
                "reflected_payload_count": reflected_payload_count,
                "error_status_count": error_status_count,
                "signals": anomaly_signals,
                "inference": "possible_injection_signal" if anomaly_signals else "no_signal",
            },
        }

    if tool_name == "measure_timing_delta":
        session_id = int(arguments.get("session_id") or 0)
        endpoint = arguments.get("endpoint")
        method = arguments.get("method") or "GET"
        role_name = arguments.get("role_name")
        headers = arguments.get("headers") or {}
        params = arguments.get("params") or {}
        json_body = arguments.get("json_body") or {}
        use_role_token = bool(arguments.get("use_role_token"))
        injection_location = str(arguments.get("injection_location") or "").strip().lower()
        injection_key = str(arguments.get("injection_key") or "").strip()
        control_value = arguments.get("control_value")
        payload_value = arguments.get("payload_value")
        threshold_ms = float(arguments.get("threshold_ms") or 1500)
        if injection_location not in {"params", "json_body", "headers"}:
            raise HTTPException(status_code=400, detail="injection_location must be one of: params, json_body, headers")
        if not injection_key:
            raise HTTPException(status_code=400, detail="injection_key is required")

        (
            endpoint,
            method,
            role_name,
            headers,
            params,
            json_body,
        ) = _prepare_request_parts(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            use_role_token=use_role_token,
            headers=headers,
            params=params,
            json_body=json_body,
        )

        def _build_request_variant(value: Any) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
            run_headers = _clone_jsonable_dict(headers)
            run_params = _clone_jsonable_dict(params)
            run_json_body = _clone_jsonable_dict(json_body)
            if injection_location == "params":
                run_params[injection_key] = value
            elif injection_location == "headers":
                run_headers[injection_key] = value
            else:
                _apply_nested_override(run_json_body, injection_key, value)
            return run_headers, run_params, run_json_body

        control_headers, control_params, control_body = _build_request_variant(control_value)
        payload_headers, payload_params, payload_body = _build_request_variant(payload_value)

        control_result, control_observation = _execute_and_store_request(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            headers=control_headers,
            params=control_params,
            json_body=control_body,
        )
        payload_result, payload_observation = _execute_and_store_request(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=role_name,
            headers=payload_headers,
            params=payload_params,
            json_body=payload_body,
        )

        control_elapsed = float(control_result.get("elapsed_ms") or 0.0)
        payload_elapsed = float(payload_result.get("elapsed_ms") or 0.0)
        delta_ms = round(payload_elapsed - control_elapsed, 2)
        signals = []
        if delta_ms >= threshold_ms:
            signals.append("time_delay_signal")
        if int(control_result.get("status_code") or 0) != int(payload_result.get("status_code") or 0):
            signals.append("status_code_delta")

        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "control_execution": _serialize_execution(control_observation, control_result),
            "payload_execution": _serialize_execution(payload_observation, payload_result),
            "analysis": {
                "control_elapsed_ms": control_elapsed,
                "payload_elapsed_ms": payload_elapsed,
                "delta_ms": delta_ms,
                "threshold_ms": threshold_ms,
                "signals": signals,
                "inference": "possible_time_based_injection" if "time_delay_signal" in signals else "no_signal",
            },
        }

    if tool_name == "zap_spider":
        session_id = int(arguments.get("session_id") or 0)
        max_wait_sec = int(arguments.get("max_wait_sec") or 120)
        session_obj = _get_session(db, session_id)
        result = run_spider_and_wait(session_obj.target_url, max_wait_sec=max_wait_sec)
        urls = list((result or {}).get("urls") or [])
        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "target_url": session_obj.target_url,
            "max_wait_sec": max_wait_sec,
            "urls_total": len(urls),
            "urls": urls[:200],
        }

    if tool_name == "zap_ajax_spider":
        session_id = int(arguments.get("session_id") or 0)
        max_wait_sec = int(arguments.get("max_wait_sec") or 120)
        session_obj = _get_session(db, session_id)
        result = run_ajax_spider_and_wait(session_obj.target_url, max_wait_sec=max_wait_sec)
        urls = list((result or {}).get("urls") or [])
        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "target_url": session_obj.target_url,
            "max_wait_sec": max_wait_sec,
            "urls_total": len(urls),
            "urls": urls[:200],
        }

    if tool_name == "zap_active_scan":
        session_id = int(arguments.get("session_id") or 0)
        max_wait_sec = int(arguments.get("max_wait_sec") or 300)
        recurse = bool(arguments.get("recurse", True))
        session_obj = _get_session(db, session_id)
        result = run_active_scan_and_wait(
            session_obj.target_url,
            max_wait_sec=max_wait_sec,
            recurse=recurse,
        )
        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "target_url": session_obj.target_url,
            "max_wait_sec": max_wait_sec,
            "recurse": recurse,
            "scan": result,
        }

    if tool_name == "zap_baseline_scan":
        session_id = int(arguments.get("session_id") or 0)
        profile = str(arguments.get("profile") or "mixed")
        max_spider_sec = int(arguments.get("max_spider_sec") or 120)
        max_active_sec = int(arguments.get("max_active_sec") or 300)
        use_ajax_spider = bool(arguments.get("use_ajax_spider", False))
        import_openapi = bool(arguments.get("import_openapi", True))
        session_obj = _get_session(db, session_id)
        result = run_zap_baseline(
            target_name=session_obj.target_name,
            target_url=session_obj.target_url,
            profile=profile,
            max_spider_sec=max_spider_sec,
            max_active_sec=max_active_sec,
            use_ajax_spider=use_ajax_spider,
            import_openapi=import_openapi,
        )
        return {
            "session_id": session_id,
            "tool_name": tool_name,
            "result": result,
        }

    if tool_name == "register_role":
        session_id = int(arguments.get("session_id") or 0)
        role_name = str(arguments.get("role_name") or "").strip()
        session_obj = _get_session(db, session_id)
        if not role_name:
            raise HTTPException(status_code=400, detail="role_name is required")

        role = _get_role(db, session_id, role_name)

        notes = {}
        if role.notes:
            try:
                notes = json.loads(role.notes)
            except Exception:
                notes = {}

        signup_url = f"{session_obj.target_url.rstrip('/')}/identity/api/auth/signup"
        req_body = {
            "name": notes.get("name", role.role_name),
            "email": role.email,
            "password": role.password,
            "number": role.phone_number,
        }
        result = send_request(
            method="POST",
            url=signup_url,
            headers={"Content-Type": "application/json"},
            json_body=req_body,
        )
        observation = _store_observation(
            db,
            session_id=session_id,
            endpoint=signup_url,
            method="POST",
            role_name=role.role_name,
            request_headers={"Content-Type": "application/json"},
            request_params={},
            request_body=req_body,
            result=result,
        )
        role.last_auth_status = result["status_code"]
        role.status = "registered" if result["status_code"] == 200 else "failed"
        session_obj.status = "active"
        db.commit()
        db.refresh(role)
        return {
            "session_id": session_id,
            "role": {
                "role_name": role.role_name,
                "status": role.status,
                "last_auth_status": role.last_auth_status,
            },
            "observation": _serialize_observation(observation),
        }

    if tool_name == "login_role":
        session_id = int(arguments.get("session_id") or 0)
        role_name = str(arguments.get("role_name") or "").strip()
        session_obj = _get_session(db, session_id)
        if not role_name:
            raise HTTPException(status_code=400, detail="role_name is required")

        role = _get_role(db, session_id, role_name)
        login_url = f"{session_obj.target_url.rstrip('/')}/identity/api/auth/login"
        req_body = {
            "email": role.email,
            "password": role.password,
        }
        result = send_request(
            method="POST",
            url=login_url,
            headers={"Content-Type": "application/json"},
            json_body=req_body,
        )
        observation = _store_observation(
            db,
            session_id=session_id,
            endpoint=login_url,
            method="POST",
            role_name=role.role_name,
            request_headers={"Content-Type": "application/json"},
            request_params={},
            request_body=req_body,
            result=result,
        )
        tokens = extract_tokens_from_response_text(result["text"])
        if result["status_code"] == 200 and tokens.get("access_token"):
            role.access_token = tokens.get("access_token")
            role.refresh_token = tokens.get("refresh_token")
            role.token_type = tokens.get("token_type") or "Bearer"
            role.status = "authenticated"
            session_obj.status = "active"
        else:
            role.status = "failed"
        role.last_auth_status = result["status_code"]
        db.commit()
        db.refresh(role)
        return {
            "session_id": session_id,
            "role": {
                "role_name": role.role_name,
                "status": role.status,
                "has_access_token": bool(role.access_token),
                "last_auth_status": role.last_auth_status,
            },
            "observation": _serialize_observation(observation),
        }

    if tool_name == "probe_same_object_across_roles":
        session_id = int(arguments.get("session_id") or 0)
        endpoint = str(arguments.get("endpoint") or "").strip()
        method = str(arguments.get("method") or "GET").upper()
        owner_role = str(arguments.get("owner_role") or "").strip()
        other_role = str(arguments.get("other_role") or "").strip()
        _get_session(db, session_id)

        if not endpoint or not owner_role or not other_role:
            raise HTTPException(status_code=400, detail="endpoint, owner_role, and other_role are required")

        owner = _get_role(db, session_id, owner_role)
        other = _get_role(db, session_id, other_role)
        if not owner.access_token or not other.access_token:
            raise HTTPException(status_code=400, detail="Both roles must have access tokens")

        owner_headers = {"Authorization": f"{owner.token_type or 'Bearer'} {owner.access_token}"}
        other_headers = {"Authorization": f"{other.token_type or 'Bearer'} {other.access_token}"}

        owner_result = send_request(method=method, url=endpoint, headers=owner_headers)
        other_result = send_request(method=method, url=endpoint, headers=other_headers)

        owner_observation = _store_observation(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=owner_role,
            request_headers=owner_headers,
            request_params={},
            request_body={},
            result=owner_result,
        )
        other_observation = _store_observation(
            db,
            session_id=session_id,
            endpoint=endpoint,
            method=method,
            role_name=other_role,
            request_headers=other_headers,
            request_params={},
            request_body={},
            result=other_result,
        )

        return {
            "session_id": session_id,
            "owner_observation": _serialize_observation(owner_observation),
            "other_observation": _serialize_observation(other_observation),
            "analysis": infer_bola_from_observations(owner_observation, other_observation),
        }

    if tool_name == "compare_observations":
        observation_a_id = int(arguments.get("observation_a_id") or 0)
        observation_b_id = int(arguments.get("observation_b_id") or 0)
        obs_a = db.query(Observation).filter(Observation.id == observation_a_id).first()
        obs_b = db.query(Observation).filter(Observation.id == observation_b_id).first()
        if not obs_a or not obs_b:
            raise HTTPException(status_code=404, detail="One or both observations not found")
        return {
            "comparison": compare_observations(obs_a, obs_b),
        }

    if tool_name == "infer_bola":
        owner_observation_id = int(arguments.get("owner_observation_id") or 0)
        other_observation_id = int(arguments.get("other_observation_id") or 0)
        obs_owner = db.query(Observation).filter(Observation.id == owner_observation_id).first()
        obs_other = db.query(Observation).filter(Observation.id == other_observation_id).first()
        if not obs_owner or not obs_other:
            raise HTTPException(status_code=404, detail="Observations not found")
        return {
            "analysis": infer_bola_from_observations(obs_owner, obs_other),
        }

    if tool_name == "infer_bopla":
        observation_id = int(arguments.get("observation_id") or 0)
        suspected_fields = arguments.get("suspected_fields") or []
        if not isinstance(suspected_fields, list):
            raise HTTPException(status_code=400, detail="suspected_fields must be a list")
        observation = db.query(Observation).filter(Observation.id == observation_id).first()
        if not observation:
            raise HTTPException(status_code=404, detail="Observation not found")
        return {
            "observation": _serialize_observation(observation),
            "analysis": analyze_bopla_observation(observation, suspected_fields=suspected_fields),
        }

    raise HTTPException(status_code=400, detail=f"Tool '{tool_name}' is not implemented")
