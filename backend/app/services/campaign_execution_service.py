import json

from fastapi import HTTPException

from ..models import Observation, RoleCredential, Finding
from ..services.http_service import send_request
from ..services.discovery_service import persist_discovery_results, save_openapi_endpoints
from ..services.openapi_service import find_openapi_document, parse_openapi_spec
from ..services.role_service import generate_unique_identity, extract_tokens_from_response_text
from ..services.analysis_service import compare_observations
from ..services.bola_service import infer_bola_from_observations
from ..services.bopla_service import analyze_bopla_observation
from ..services.finding_dedup_service import (
    matching_bola_finding,
    matching_bopla_finding,
    merge_related_observation_ids,
)
from ..services.zap_service import run_spider_and_wait


def _load_payload(selected):
    payload_data = {}
    if getattr(selected, "payload_json", None):
        try:
            payload_data = json.loads(selected.payload_json)
        except Exception:
            payload_data = {}
    return payload_data

def execute_hypothesis(db, session_obj, selected):
    payload_data = _load_payload(selected)
    execution_result = {
        "action_executed": None,
        "status": "not_executed",
    }
    request_count = 0

    if selected.hypothesis_type == "register_role":
        role_name = payload_data.get("role_name")
        role = db.query(RoleCredential).filter(
            RoleCredential.session_id == session_obj.id,
            RoleCredential.role_name == role_name,
        ).first()

        if not role:
            identity = generate_unique_identity(role_name)
            role = RoleCredential(
                session_id=session_obj.id,
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
        request_count = 1

        obs = Observation(
            session_id=session_obj.id,
            endpoint=signup_url,
            method="POST",
            role_name=role.role_name,
            request_headers=json.dumps({"Content-Type": "application/json"}, ensure_ascii=False),
            request_params=json.dumps({}, ensure_ascii=False),
            request_body=json.dumps(req_body, ensure_ascii=False),
            status_code=result["status_code"],
            response_headers=json.dumps(result["headers"], ensure_ascii=False),
            body_preview=result["text"][:5000],
        )
        db.add(obs)

        role.last_auth_status = result["status_code"]
        role.status = "registered" if result["status_code"] == 200 else "failed"
        selected.status = "executed"
        session_obj.status = "active"
        db.commit()

        execution_result = {
            "action_executed": "register_role",
            "status": "executed",
            "role_name": role.role_name,
            "http_status": result["status_code"],
            "body_preview": result["text"][:300],
        }
        return execution_result, request_count

    if selected.hypothesis_type == "bootstrap_roles":
        role_names = payload_data.get("role_names", ["user_a", "user_b"])
        created_roles = []

        for role_name in role_names:
            role = db.query(RoleCredential).filter(
                RoleCredential.session_id == session_obj.id,
                RoleCredential.role_name == role_name,
            ).first()
            if role:
                created_roles.append(role.role_name)
                continue

            identity = generate_unique_identity(role_name)
            role = RoleCredential(
                session_id=session_obj.id,
                role_name=role_name,
                email=identity["email"],
                password=identity["password"],
                phone_number=identity["phone_number"],
                status="created",
                notes=json.dumps({"name": identity["name"]}, ensure_ascii=False),
            )
            db.add(role)
            created_roles.append(role_name)

        selected.status = "executed"
        session_obj.status = "bootstrap_ready"
        db.commit()

        execution_result = {
            "action_executed": "bootstrap_roles",
            "status": "executed",
            "roles": created_roles,
        }
        return execution_result, request_count

    if selected.hypothesis_type == "login_role":
        role_name = payload_data.get("role_name")
        role = db.query(RoleCredential).filter(
            RoleCredential.session_id == session_obj.id,
            RoleCredential.role_name == role_name,
        ).first()

        if not role:
            raise HTTPException(status_code=400, detail="Role for login_role not found")

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
        request_count = 1

        obs = Observation(
            session_id=session_obj.id,
            endpoint=login_url,
            method="POST",
            role_name=role.role_name,
            request_headers=json.dumps({"Content-Type": "application/json"}, ensure_ascii=False),
            request_params=json.dumps({}, ensure_ascii=False),
            request_body=json.dumps(req_body, ensure_ascii=False),
            status_code=result["status_code"],
            response_headers=json.dumps(result["headers"], ensure_ascii=False),
            body_preview=result["text"][:5000],
        )
        db.add(obs)

        tokens = extract_tokens_from_response_text(result["text"])
        if result["status_code"] == 200 and tokens.get("access_token"):
            role.access_token = tokens.get("access_token")
            role.refresh_token = tokens.get("refresh_token")
            role.token_type = tokens.get("token_type") or "Bearer"
            role.status = "authenticated"
        else:
            role.status = "failed"

        role.last_auth_status = result["status_code"]
        selected.status = "executed"
        session_obj.status = "active"
        db.commit()

        execution_result = {
            "action_executed": "login_role",
            "status": "executed",
            "role_name": role.role_name,
            "http_status": result["status_code"],
            "has_access_token": bool(role.access_token),
            "body_preview": result["text"][:300],
        }
        return execution_result, request_count

    if selected.hypothesis_type in {
        "probe",
        "login",
        "anonymous_probe",
        "tokenless_replay_probe",
        "auth_boundary_probe",
    } and selected.target_endpoint:
        req_headers = payload_data.get("headers", {})
        req_params = payload_data.get("params", {})
        req_json_body = payload_data.get("json_body", {})

        result = send_request(
            method=selected.http_method or "GET",
            url=selected.target_endpoint,
            headers=req_headers,
            params=req_params,
            json_body=req_json_body,
        )
        request_count = 1

        obs = Observation(
            session_id=session_obj.id,
            endpoint=selected.target_endpoint,
            method=(selected.http_method or "GET").upper(),
            role_name=None,
            request_headers=json.dumps(req_headers, ensure_ascii=False),
            request_params=json.dumps(req_params or {}, ensure_ascii=False),
            request_body=json.dumps(req_json_body or {}, ensure_ascii=False),
            status_code=result["status_code"],
            response_headers=json.dumps(result["headers"], ensure_ascii=False),
            body_preview=result["text"][:5000],
        )
        db.add(obs)

        selected.status = "executed"
        session_obj.status = "active"
        db.commit()
        db.refresh(obs)

        execution_result = {
            "action_executed": selected.hypothesis_type,
            "status": "executed",
            "observation_id": obs.id,
            "status_code": obs.status_code,
            "source_role": payload_data.get("source_role"),
            "body_preview": obs.body_preview[:300],
        }
        return execution_result, request_count

    if selected.hypothesis_type == "authenticated_probe" and selected.target_endpoint:
        role_name = payload_data.get("role_name")
        role = db.query(RoleCredential).filter(
            RoleCredential.session_id == session_obj.id,
            RoleCredential.role_name == role_name,
        ).first()

        if not role or not role.access_token:
            raise HTTPException(status_code=400, detail="Role token unavailable for authenticated probe")

        req_headers = dict(payload_data.get("headers", {}))
        req_headers["Authorization"] = f"{role.token_type or 'Bearer'} {role.access_token}"
        req_params = payload_data.get("params", {})
        req_json_body = payload_data.get("json_body", {})

        result = send_request(
            method=selected.http_method or "GET",
            url=selected.target_endpoint,
            headers=req_headers,
            params=req_params,
            json_body=req_json_body,
        )
        request_count = 1

        obs = Observation(
            session_id=session_obj.id,
            endpoint=selected.target_endpoint,
            method=(selected.http_method or "GET").upper(),
            role_name=role.role_name,
            request_headers=json.dumps(req_headers, ensure_ascii=False),
            request_params=json.dumps(req_params or {}, ensure_ascii=False),
            request_body=json.dumps(req_json_body or {}, ensure_ascii=False),
            status_code=result["status_code"],
            response_headers=json.dumps(result["headers"], ensure_ascii=False),
            body_preview=result["text"][:5000],
        )
        db.add(obs)

        selected.status = "executed"
        session_obj.status = "active"
        db.commit()
        db.refresh(obs)

        execution_result = {
            "action_executed": "authenticated_probe",
            "status": "executed",
            "role_name": role.role_name,
            "observation_id": obs.id,
            "status_code": obs.status_code,
            "body_preview": obs.body_preview[:300],
        }
        return execution_result, request_count

    if selected.hypothesis_type == "compare_roles":
        observation_a_id = payload_data.get("observation_a_id")
        observation_b_id = payload_data.get("observation_b_id")

        obs_a = db.query(Observation).filter(Observation.id == observation_a_id).first()
        obs_b = db.query(Observation).filter(Observation.id == observation_b_id).first()

        if not obs_a or not obs_b:
            raise HTTPException(status_code=400, detail="Comparison observations not found")

        comparison = compare_observations(obs_a, obs_b)
        selected.status = "executed"
        session_obj.status = "analysis_active"
        db.commit()

        execution_result = {
            "action_executed": "compare_roles",
            "status": "executed",
            "comparison": comparison,
        }
        return execution_result, request_count

    if selected.hypothesis_type == "bopla_probe":
        observation_id = payload_data.get("observation_id")
        suspected_fields = payload_data.get("suspected_fields", [])

        obs = db.query(Observation).filter(
            Observation.id == observation_id,
            Observation.session_id == session_obj.id
        ).first()

        if not obs:
            raise HTTPException(status_code=400, detail="Observation for BOPLA probe not found")

        analysis = analyze_bopla_observation(obs, suspected_fields=suspected_fields)
        if analysis["inference"] == "possible_bopla":
            existing_findings = db.query(Finding).filter(
                Finding.session_id == session_obj.id,
                Finding.finding_type == "possible_bopla",
                Finding.endpoint == obs.endpoint,
                Finding.verification_status.in_(["candidate", "confirmed"]),
            ).all()

            finding = matching_bopla_finding(existing_findings, obs.endpoint, analysis)

            if finding:
                finding.related_hypothesis_id = selected.id
                finding.related_observation_ids = merge_related_observation_ids(
                    finding.related_observation_ids,
                    [obs.id],
                )
                finding.description = (
                    f"Response on {obs.endpoint} exposes potentially sensitive fields: "
                    f"{', '.join(analysis.get('exposed_fields', []))}"
                )
                finding.evidence_json = json.dumps(analysis, ensure_ascii=False)
            else:
                finding = Finding(
                    session_id=session_obj.id,
                    finding_type="possible_bopla",
                    severity="medium",
                    endpoint=obs.endpoint,
                    related_hypothesis_id=selected.id,
                    related_observation_ids=json.dumps([obs.id], ensure_ascii=False),
                    title="Possible Broken Object Property Level Authorization / Excessive Data Exposure",
                    description=(
                        f"Response on {obs.endpoint} exposes potentially sensitive fields: "
                        f"{', '.join(analysis.get('exposed_fields', []))}"
                    ),
                    evidence_json=json.dumps(analysis, ensure_ascii=False),
                    verification_status="candidate",
                )
                db.add(finding)

        selected.status = "executed"
        session_obj.status = "analysis_active"
        db.commit()

        execution_result = {
            "action_executed": "bopla_probe",
            "status": "executed",
            "analysis": analysis,
        }
        return execution_result, request_count

    if selected.hypothesis_type == "bola_probe" and selected.target_endpoint:
        owner_role_name = payload_data.get("owner_role")
        other_role_name = payload_data.get("other_role")

        owner = db.query(RoleCredential).filter(
            RoleCredential.session_id == session_obj.id,
            RoleCredential.role_name == owner_role_name,
        ).first()
        other = db.query(RoleCredential).filter(
            RoleCredential.session_id == session_obj.id,
            RoleCredential.role_name == other_role_name,
        ).first()

        if not owner or not other:
            raise HTTPException(status_code=400, detail="Owner or other role not found for BOLA probe")
        if not owner.access_token or not other.access_token:
            raise HTTPException(status_code=400, detail="Missing access token for BOLA probe")

        owner_headers = {"Authorization": f"{owner.token_type or 'Bearer'} {owner.access_token}"}
        other_headers = {"Authorization": f"{other.token_type or 'Bearer'} {other.access_token}"}

        owner_result = send_request(
            method=selected.http_method or "GET",
            url=selected.target_endpoint,
            headers=owner_headers,
        )
        other_result = send_request(
            method=selected.http_method or "GET",
            url=selected.target_endpoint,
            headers=other_headers,
        )
        request_count = 2

        obs_owner = Observation(
            session_id=session_obj.id,
            endpoint=selected.target_endpoint,
            method=(selected.http_method or "GET").upper(),
            role_name=owner.role_name,
            request_headers=json.dumps(owner_headers, ensure_ascii=False),
            request_params=json.dumps({}, ensure_ascii=False),
            request_body=json.dumps({}, ensure_ascii=False),
            status_code=owner_result["status_code"],
            response_headers=json.dumps(owner_result["headers"], ensure_ascii=False),
            body_preview=owner_result["text"][:5000],
        )
        db.add(obs_owner)
        db.commit()
        db.refresh(obs_owner)

        obs_other = Observation(
            session_id=session_obj.id,
            endpoint=selected.target_endpoint,
            method=(selected.http_method or "GET").upper(),
            role_name=other.role_name,
            request_headers=json.dumps(other_headers, ensure_ascii=False),
            request_params=json.dumps({}, ensure_ascii=False),
            request_body=json.dumps({}, ensure_ascii=False),
            status_code=other_result["status_code"],
            response_headers=json.dumps(other_result["headers"], ensure_ascii=False),
            body_preview=other_result["text"][:5000],
        )
        db.add(obs_other)
        db.commit()
        db.refresh(obs_other)

        bola_analysis = infer_bola_from_observations(obs_owner, obs_other)

        if bola_analysis.get("inference") == "possible_bola":
            existing_findings = db.query(Finding).filter(
                Finding.session_id == session_obj.id,
                Finding.finding_type == "possible_bola",
                Finding.endpoint == selected.target_endpoint,
                Finding.verification_status.in_(["candidate", "confirmed"]),
            ).all()
            finding = matching_bola_finding(
                existing_findings,
                selected.target_endpoint,
                bola_analysis,
            )

            if finding:
                finding.related_hypothesis_id = selected.id
                finding.related_observation_ids = merge_related_observation_ids(
                    finding.related_observation_ids,
                    [obs_owner.id, obs_other.id],
                )
                finding.description = (
                    f"Same object endpoint was accessible for roles {owner.role_name} and {other.role_name} "
                    f"with successful responses and equivalent object evidence."
                )
                finding.evidence_json = json.dumps(bola_analysis, ensure_ascii=False)
            else:
                finding = Finding(
                    session_id=session_obj.id,
                    finding_type="possible_bola",
                    severity="high",
                    endpoint=selected.target_endpoint,
                    related_hypothesis_id=selected.id,
                    related_observation_ids=json.dumps([obs_owner.id, obs_other.id], ensure_ascii=False),
                    title="Possible Broken Object Level Authorization",
                    description=(
                        f"Same object endpoint was accessible for roles {owner.role_name} and {other.role_name} "
                        f"with successful responses and equivalent object evidence."
                    ),
                    evidence_json=json.dumps(bola_analysis, ensure_ascii=False),
                    verification_status="candidate",
                )
                db.add(finding)

        selected.status = "executed"
        session_obj.status = "analysis_active"
        db.commit()

        execution_result = {
            "action_executed": "bola_probe",
            "status": "executed",
            "analysis": bola_analysis,
        }
        return execution_result, request_count

    if selected.hypothesis_type == "verify_bopla":
        finding_id = payload_data.get("finding_id")
        endpoint = payload_data.get("endpoint")
        expected_fields = payload_data.get("expected_fields", [])
        source_observation_id = payload_data.get("observation_id")

        finding = db.query(Finding).filter(
            Finding.id == finding_id,
            Finding.session_id == session_obj.id
        ).first()

        if not finding:
            raise HTTPException(status_code=400, detail="BOPLA finding not found for verification")

        headers = None
        role_name = None

        role = db.query(RoleCredential).filter(
            RoleCredential.session_id == session_obj.id,
            RoleCredential.access_token.isnot(None)
        ).first()
        if role:
            headers = {"Authorization": f"{role.token_type or 'Bearer'} {role.access_token}"}
            role_name = role.role_name

        if headers is None and source_observation_id:
            source_obs = db.query(Observation).filter(
                Observation.id == source_observation_id,
                Observation.session_id == session_obj.id
            ).first()
            if source_obs and source_obs.request_headers:
                try:
                    source_headers = json.loads(source_obs.request_headers)
                except Exception:
                    source_headers = {}
                auth_header = source_headers.get("Authorization")
                if auth_header:
                    headers = {"Authorization": auth_header}
                    role_name = source_obs.role_name

        if headers is None:
            raise HTTPException(status_code=400, detail="No authentication context available for BOPLA verification")

        result = send_request(
            method="GET",
            url=endpoint,
            headers=headers,
        )
        request_count = 1

        obs = Observation(
            session_id=session_obj.id,
            endpoint=endpoint,
            method="GET",
            role_name=role_name,
            request_headers=json.dumps(headers, ensure_ascii=False),
            request_params=json.dumps({}, ensure_ascii=False),
            request_body=json.dumps({}, ensure_ascii=False),
            status_code=result["status_code"],
            response_headers=json.dumps(result["headers"], ensure_ascii=False),
            body_preview=result["text"][:5000],
        )
        db.add(obs)
        db.commit()
        db.refresh(obs)

        analysis = analyze_bopla_observation(obs, suspected_fields=expected_fields)
        finding.verification_status = "confirmed" if analysis.get("inference") == "possible_bopla" else "rejected"

        selected.status = "executed"
        session_obj.status = "analysis_active"
        db.commit()

        execution_result = {
            "action_executed": "verify_bopla",
            "status": "executed",
            "finding_id": finding.id,
            "verification_status": finding.verification_status,
            "analysis": analysis,
        }
        return execution_result, request_count

    if selected.hypothesis_type == "verify_auth_boundary":
        finding_id = payload_data.get("finding_id")
        endpoint = payload_data.get("endpoint")
        expected_status_code = payload_data.get("expected_status_code")

        finding = db.query(Finding).filter(
            Finding.id == finding_id,
            Finding.session_id == session_obj.id
        ).first()

        if not finding:
            raise HTTPException(status_code=400, detail="Auth boundary finding not found for verification")
        if not endpoint:
            raise HTTPException(status_code=400, detail="Auth boundary verification endpoint missing")

        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer invalid-auth-boundary-token",
        }
        result = send_request(
            method=selected.http_method or "GET",
            url=endpoint,
            headers=headers,
        )
        request_count = 1

        obs = Observation(
            session_id=session_obj.id,
            endpoint=endpoint,
            method=(selected.http_method or "GET").upper(),
            role_name=None,
            request_headers=json.dumps(headers, ensure_ascii=False),
            request_params=json.dumps({}, ensure_ascii=False),
            request_body=json.dumps({}, ensure_ascii=False),
            status_code=result["status_code"],
            response_headers=json.dumps(result["headers"], ensure_ascii=False),
            body_preview=result["text"][:5000],
        )
        db.add(obs)
        db.commit()
        db.refresh(obs)

        finding.verification_status = (
            "confirmed"
            if expected_status_code is not None and int(result["status_code"]) == int(expected_status_code)
            else "rejected"
        )

        selected.status = "executed"
        session_obj.status = "analysis_active"
        db.commit()

        execution_result = {
            "action_executed": "verify_auth_boundary",
            "status": "executed",
            "finding_id": finding.id,
            "verification_status": finding.verification_status,
            "status_code": result["status_code"],
            "observation_id": obs.id,
            "expected_status_code": expected_status_code,
        }
        return execution_result, request_count

    if selected.hypothesis_type == "verify_bola":
        finding_id = payload_data.get("finding_id")
        endpoint = payload_data.get("endpoint")
        owner_role_name = payload_data.get("owner_role")
        other_role_name = payload_data.get("other_role")

        finding = db.query(Finding).filter(
            Finding.id == finding_id,
            Finding.session_id == session_obj.id
        ).first()

        if not finding:
            raise HTTPException(status_code=400, detail="BOLA finding not found for verification")

        owner = db.query(RoleCredential).filter(
            RoleCredential.session_id == session_obj.id,
            RoleCredential.role_name == owner_role_name
        ).first()
        other = db.query(RoleCredential).filter(
            RoleCredential.session_id == session_obj.id,
            RoleCredential.role_name == other_role_name
        ).first()

        if not owner or not other:
            raise HTTPException(status_code=400, detail="Owner or other role not found for BOLA verification")
        if not owner.access_token or not other.access_token:
            raise HTTPException(status_code=400, detail="Missing access token for BOLA verification")

        owner_headers = {"Authorization": f"{owner.token_type or 'Bearer'} {owner.access_token}"}
        other_headers = {"Authorization": f"{other.token_type or 'Bearer'} {other.access_token}"}

        owner_result = send_request(
            method="GET",
            url=endpoint,
            headers=owner_headers,
        )
        other_result = send_request(
            method="GET",
            url=endpoint,
            headers=other_headers,
        )
        request_count = 2

        obs_owner = Observation(
            session_id=session_obj.id,
            endpoint=endpoint,
            method="GET",
            role_name=owner.role_name,
            request_headers=json.dumps(owner_headers, ensure_ascii=False),
            request_params=json.dumps({}, ensure_ascii=False),
            request_body=json.dumps({}, ensure_ascii=False),
            status_code=owner_result["status_code"],
            response_headers=json.dumps(owner_result["headers"], ensure_ascii=False),
            body_preview=owner_result["text"][:5000],
        )
        db.add(obs_owner)
        db.commit()
        db.refresh(obs_owner)

        obs_other = Observation(
            session_id=session_obj.id,
            endpoint=endpoint,
            method="GET",
            role_name=other.role_name,
            request_headers=json.dumps(other_headers, ensure_ascii=False),
            request_params=json.dumps({}, ensure_ascii=False),
            request_body=json.dumps({}, ensure_ascii=False),
            status_code=other_result["status_code"],
            response_headers=json.dumps(other_result["headers"], ensure_ascii=False),
            body_preview=other_result["text"][:5000],
        )
        db.add(obs_other)
        db.commit()
        db.refresh(obs_other)

        bola_analysis = infer_bola_from_observations(obs_owner, obs_other)
        finding.verification_status = "confirmed" if bola_analysis.get("inference") == "possible_bola" else "rejected"

        selected.status = "executed"
        session_obj.status = "analysis_active"
        db.commit()

        execution_result = {
            "action_executed": "verify_bola",
            "status": "executed",
            "finding_id": finding.id,
            "verification_status": finding.verification_status,
            "analysis": bola_analysis,
        }
        return execution_result, request_count

    if selected.hypothesis_type == "discovery":
        openapi_url, spec = find_openapi_document(session_obj.target_url)
        openapi_saved = 0
        openapi_sample = []
        if openapi_url and spec:
            endpoints = parse_openapi_spec(spec)
            openapi_saved = save_openapi_endpoints(
                db=db,
                session_id=session_obj.id,
                endpoints=endpoints,
                source_type="openapi_autodiscovery",
            )
            openapi_sample = endpoints[:10]

        spider_results = run_spider_and_wait(session_obj.target_url)
        persisted = persist_discovery_results(
            db=db,
            session_obj=session_obj,
            urls=spider_results.get("urls", []),
            source_type="zap_spider",
            confidence=0.7,
        )
        selected.status = "executed"
        session_obj.status = "discovery_followup" if not persisted["api_urls"] else "discovered"
        db.commit()

        execution_result = {
            "action_executed": "discovery",
            "status": "executed",
            "openapi_discovered": bool(openapi_url),
            "openapi_url": openapi_url,
            "openapi_saved_endpoints": openapi_saved,
            "openapi_sample": openapi_sample,
            "discovered_urls_count": len(persisted["scoped_urls"]),
            "api_urls_count": len(persisted["api_urls"]),
            "urls_sample": persisted["scoped_urls"][:10],
            "api_urls_sample": persisted["api_urls"][:10],
            "js_discovered_urls": persisted["js_discovered_urls"][:10],
        }
        return execution_result, request_count

    selected.status = "rejected"
    db.commit()
    execution_result = {
        "action_executed": selected.hypothesis_type,
        "status": "rejected",
        "reason": "Unsupported hypothesis type for executor",
    }
    return execution_result, request_count
