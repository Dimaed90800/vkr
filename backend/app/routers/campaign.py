import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import (
    TestSession,
    Hypothesis,
    JudgeDecision,
    Observation,
    RoleCredential,
    Finding,
)
from ..schemas import CampaignStepRequest
from ..services.hypothesis_service import generate_hypotheses_for_session
from ..services.judge_service import (
    calculate_priority_score,
    classify_decision_type,
    build_reasoning_summary,
    build_required_evidence,
    build_stop_condition,
    serialize_hypothesis,
)
from ..services.dify_service import call_dify_judge
from ..services.http_service import send_request
from ..services.zap_service import run_spider_and_wait
from ..services.role_service import generate_unique_identity, extract_tokens_from_response_text
from ..services.analysis_service import compare_observations
from ..services.bola_service import infer_bola_from_observations

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _select_hypothesis(payload: CampaignStepRequest, saved_candidates, db: Session):
    if not saved_candidates:
        raise HTTPException(status_code=400, detail="No hypotheses generated")

    judge_mode = getattr(payload, "judge_mode", "rule_based")

    if judge_mode == "dify":
        hypotheses_json = [serialize_hypothesis(h) for h in saved_candidates]

        context = {
            "session_id": payload.session_id,
            "recent_findings_count": db.query(Finding)
            .filter(Finding.session_id == payload.session_id)
            .count(),
            "candidate_count": len(saved_candidates),
            "valid_candidate_keys": [h["candidate_key"] for h in hypotheses_json],
        }

        dify_response = call_dify_judge(hypotheses_json, context)

        selected_key = dify_response.get("selected_key")
        selected = None

        if selected_key is not None:
            for h, serialized in zip(saved_candidates, hypotheses_json):
                if serialized["candidate_key"] == selected_key:
                    selected = h
                    break

        if selected is None:
            reason_text = str(dify_response.get("reason", "")).lower()
            bola_candidates = [h for h, s in zip(saved_candidates, hypotheses_json) if s["type"] == "bola_probe"]

            if ("bola" in reason_text or "object" in reason_text) and bola_candidates:
                selected = bola_candidates[0]
                score = float(dify_response.get("score", 0.5))
                reasoning_summary = (
                    f"Dify returned invalid candidate key '{selected_key}', "
                    f"but reasoning indicated BOLA-like intent. "
                    f"Resolved to first matching bola_probe candidate. "
                    f"Original Dify reason: {dify_response.get('reason', 'N/A')}"
                )
                return selected, score, reasoning_summary

        try:
            score = float(dify_response.get("score", 0.5))
        except (TypeError, ValueError):
            score = 0.5

        reasoning_summary = str(dify_response.get("reason", "Dify selection"))
        return selected, score, reasoning_summary

    scored = [(h, calculate_priority_score(h)) for h in saved_candidates]
    scored.sort(key=lambda x: x[1], reverse=True)
    selected, score = scored[0]
    reasoning_summary = build_reasoning_summary(selected, score)
    return selected, score, reasoning_summary


@router.post("/step")
def campaign_step(payload: CampaignStepRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    generated = generate_hypotheses_for_session(db, payload.session_id)
    saved_candidates = []

    for item in generated:
        h = Hypothesis(
            session_id=payload.session_id,
            agent_name=item["agent_name"],
            hypothesis_type=item["hypothesis_type"],
            target_endpoint=item["target_endpoint"],
            http_method=item["http_method"],
            description=item["description"],
            payload_json=json.dumps(
                {
                    **item["payload"],
                    "candidate_key": item["candidate_key"],
                },
                ensure_ascii=False
            ),
            confidence=item["confidence"],
            estimated_cost=item["estimated_cost"],
            false_positive_risk=item["false_positive_risk"],
            coverage_gain=item["coverage_gain"],
            evidence_readiness=item["evidence_readiness"],
            status="candidate",
        )
        db.add(h)
        saved_candidates.append(h)

    db.commit()

    for h in saved_candidates:
        db.refresh(h)

    selected, score, reasoning_summary = _select_hypothesis(payload, saved_candidates, db)
    selected.status = "selected"

    previous_rounds = db.query(JudgeDecision).filter(
        JudgeDecision.session_id == payload.session_id
    ).count()

    decision = JudgeDecision(
        session_id=payload.session_id,
        round_no=previous_rounds + 1,
        selected_hypothesis_id=selected.id,
        decision_type=classify_decision_type(selected.hypothesis_type),
        priority_score=score,
        judge_mode=getattr(payload, "judge_mode", "rule_based"),
        reasoning_summary=reasoning_summary,
        required_evidence_json=json.dumps(build_required_evidence(selected), ensure_ascii=False),
        stop_condition_json=json.dumps(build_stop_condition(selected), ensure_ascii=False),
    )
    db.add(decision)
    db.commit()
    db.refresh(decision)

    execution_result = {
        "action_executed": None,
        "status": "not_executed",
    }

    payload_data = {}
    if selected.payload_json:
        try:
            payload_data = json.loads(selected.payload_json)
        except Exception:
            payload_data = {}

    if selected.hypothesis_type == "register_role":
        role_name = payload_data.get("role_name")
        role = db.query(RoleCredential).filter(
            RoleCredential.session_id == payload.session_id,
            RoleCredential.role_name == role_name,
        ).first()

        if not role:
            identity = generate_unique_identity(role_name)
            role = RoleCredential(
                session_id=payload.session_id,
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

        signup_url = f"{session.target_url.rstrip('/')}/identity/api/auth/signup"
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

        obs = Observation(
            session_id=payload.session_id,
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
        session.status = "active"
        db.commit()

        execution_result = {
            "action_executed": "register_role",
            "status": "executed",
            "role_name": role.role_name,
            "http_status": result["status_code"],
            "body_preview": result["text"][:300],
        }

    elif selected.hypothesis_type == "login_role":
        role_name = payload_data.get("role_name")
        role = db.query(RoleCredential).filter(
            RoleCredential.session_id == payload.session_id,
            RoleCredential.role_name == role_name,
        ).first()

        if not role:
            raise HTTPException(status_code=400, detail="Role for login_role not found")

        login_url = f"{session.target_url.rstrip('/')}/identity/api/auth/login"
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

        obs = Observation(
            session_id=payload.session_id,
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
        session.status = "active"
        db.commit()

        execution_result = {
            "action_executed": "login_role",
            "status": "executed",
            "role_name": role.role_name,
            "http_status": result["status_code"],
            "has_access_token": bool(role.access_token),
            "body_preview": result["text"][:300],
        }

    elif selected.hypothesis_type in {"probe", "login"} and selected.target_endpoint:
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

        obs = Observation(
            session_id=payload.session_id,
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
        session.status = "active"
        db.commit()
        db.refresh(obs)

        execution_result = {
            "action_executed": selected.hypothesis_type,
            "status": "executed",
            "observation_id": obs.id,
            "status_code": obs.status_code,
            "body_preview": obs.body_preview[:300],
        }

    elif selected.hypothesis_type == "authenticated_probe" and selected.target_endpoint:
        role_name = payload_data.get("role_name")
        role = db.query(RoleCredential).filter(
            RoleCredential.session_id == payload.session_id,
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

        obs = Observation(
            session_id=payload.session_id,
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
        session.status = "active"
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

    elif selected.hypothesis_type == "compare_roles":
        observation_a_id = payload_data.get("observation_a_id")
        observation_b_id = payload_data.get("observation_b_id")

        obs_a = db.query(Observation).filter(Observation.id == observation_a_id).first()
        obs_b = db.query(Observation).filter(Observation.id == observation_b_id).first()

        if not obs_a or not obs_b:
            raise HTTPException(status_code=400, detail="Comparison observations not found")

        comparison = compare_observations(obs_a, obs_b)

        selected.status = "executed"
        session.status = "analysis_active"
        db.commit()

        execution_result = {
            "action_executed": "compare_roles",
            "status": "executed",
            "comparison": comparison,
        }

    elif selected.hypothesis_type == "bopla_probe":
        observation_id = payload_data.get("observation_id")
        suspected_fields = payload_data.get("suspected_fields", [])

        obs = db.query(Observation).filter(
            Observation.id == observation_id,
            Observation.session_id == payload.session_id
        ).first()

        if not obs:
            raise HTTPException(status_code=400, detail="Observation for BOPLA probe not found")

        try:
            parsed = json.loads(obs.body_preview or "{}")
        except Exception:
            parsed = None

        exposed_fields = []
        if isinstance(parsed, dict):
            exposed_fields = [
                k for k in parsed.keys()
                if k in suspected_fields or any(
                    s in k.lower() for s in ["role", "admin", "balance", "email", "userid", "credit"]
                )
            ]

        analysis = {
            "observation_id": obs.id,
            "endpoint": obs.endpoint,
            "method": obs.method,
            "status_code": obs.status_code,
            "suspected_fields": suspected_fields,
            "exposed_fields": exposed_fields,
            "signals": ["sensitive_fields_exposed"] if exposed_fields else [],
            "inference": "possible_bopla" if exposed_fields else "no_issue"
        }

        if analysis["inference"] == "possible_bopla":
            finding = Finding(
                session_id=payload.session_id,
                finding_type="possible_bopla",
                severity="medium",
                endpoint=obs.endpoint,
                related_hypothesis_id=selected.id,
                related_observation_ids=json.dumps([obs.id], ensure_ascii=False),
                title="Possible Broken Object Property Level Authorization / Excessive Data Exposure",
                description=(
                    f"Response on {obs.endpoint} exposes potentially sensitive fields: "
                    f"{', '.join(exposed_fields)}"
                ),
                evidence_json=json.dumps(analysis, ensure_ascii=False),
                verification_status="candidate",
            )
            db.add(finding)

        selected.status = "executed"
        session.status = "analysis_active"
        db.commit()

        execution_result = {
            "action_executed": "bopla_probe",
            "status": "executed",
            "analysis": analysis,
        }

    elif selected.hypothesis_type == "bola_probe" and selected.target_endpoint:
        owner_role_name = payload_data.get("owner_role")
        other_role_name = payload_data.get("other_role")

        owner = db.query(RoleCredential).filter(
            RoleCredential.session_id == payload.session_id,
            RoleCredential.role_name == owner_role_name,
        ).first()
        other = db.query(RoleCredential).filter(
            RoleCredential.session_id == payload.session_id,
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

        obs_owner = Observation(
            session_id=payload.session_id,
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
            session_id=payload.session_id,
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
            finding = Finding(
                session_id=payload.session_id,
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
        session.status = "analysis_active"
        db.commit()

        execution_result = {
            "action_executed": "bola_probe",
            "status": "executed",
            "analysis": bola_analysis,
        }

    elif selected.hypothesis_type == "discovery":
        spider_results = run_spider_and_wait(session.target_url)
        selected.status = "executed"
        session.status = "discovery_followup"
        db.commit()

        execution_result = {
            "action_executed": "discovery",
            "status": "executed",
            "discovered_urls_count": len(spider_results.get("urls", [])),
            "urls_sample": spider_results.get("urls", [])[:10],
        }

    else:
        selected.status = "rejected"
        db.commit()
        execution_result = {
            "action_executed": selected.hypothesis_type,
            "status": "rejected",
            "reason": "Unsupported hypothesis type for executor",
        }

    return {
        "session_id": payload.session_id,
        "round_no": decision.round_no,
        "judge_mode": getattr(payload, "judge_mode", "rule_based"),
        "selected_hypothesis": {
            "id": selected.id,
            "type": selected.hypothesis_type,
            "target_endpoint": selected.target_endpoint,
            "http_method": selected.http_method,
            "description": selected.description,
        },
        "judge": {
            "decision_type": decision.decision_type,
            "priority_score": decision.priority_score,
            "reasoning_summary": decision.reasoning_summary,
        },
        "execution_result": execution_result,
    }