import json


def _safe_load_json(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return value


def build_session_report(session_obj, roles, findings, judge_decisions, observations):
    high_findings = [f for f in findings if (f.severity or "").lower() == "high"]
    medium_findings = [f for f in findings if (f.severity or "").lower() == "medium"]
    low_findings = [f for f in findings if (f.severity or "").lower() == "low"]

    authenticated_roles = [r for r in roles if r.access_token]
    recent_observations = observations[-10:] if len(observations) > 10 else observations
    recent_decisions = judge_decisions[-10:] if len(judge_decisions) > 10 else judge_decisions

    report = {
        "session": {
            "id": session_obj.id,
            "target_name": session_obj.target_name,
            "target_url": session_obj.target_url,
            "status": session_obj.status,
            "created_at": str(session_obj.created_at),
        },
        "summary": {
            "roles_total": len(roles),
            "authenticated_roles": len(authenticated_roles),
            "observations_total": len(observations),
            "judge_decisions_total": len(judge_decisions),
            "findings_total": len(findings),
            "high_findings_total": len(high_findings),
            "medium_findings_total": len(medium_findings),
            "low_findings_total": len(low_findings),
        },
        "key_conclusion": _build_key_conclusion(findings),
        "roles": [
            {
                "role_name": r.role_name,
                "email": r.email,
                "status": r.status,
                "last_auth_status": r.last_auth_status,
                "has_access_token": bool(r.access_token),
            }
            for r in roles
        ],
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "endpoint": f.endpoint,
                "verification_status": f.verification_status,
                "related_hypothesis_id": f.related_hypothesis_id,
                "related_observation_ids": _safe_load_json(f.related_observation_ids),
                "evidence": _safe_load_json(f.evidence_json),
                "created_at": str(f.created_at),
            }
            for f in findings
        ],
        "recent_judge_decisions": [
            {
                "id": d.id,
                "round_no": d.round_no,
                "decision_type": d.decision_type,
                "selected_hypothesis_id": d.selected_hypothesis_id,
                "priority_score": d.priority_score,
                "reasoning_summary": d.reasoning_summary,
                "required_evidence": _safe_load_json(d.required_evidence_json),
                "stop_condition": _safe_load_json(d.stop_condition_json),
                "created_at": str(d.created_at),
            }
            for d in recent_decisions
        ],
        "recent_observations": [
            {
                "id": o.id,
                "endpoint": o.endpoint,
                "method": o.method,
                "role_name": o.role_name,
                "status_code": o.status_code,
                "body_preview": o.body_preview[:500] if o.body_preview else None,
                "created_at": str(o.created_at),
            }
            for o in recent_observations
        ],
    }

    return report


def _build_key_conclusion(findings):
    if not findings:
        return {
            "status": "no_findings",
            "message": "No findings were recorded for the session."
        }

    bola_findings = [f for f in findings if f.finding_type == "possible_bola"]
    if bola_findings:
        return {
            "status": "security_issue_candidates_found",
            "message": (
                f"Session contains {len(bola_findings)} possible BOLA candidate(s). "
                f"Manual verification is recommended for object ownership and business context."
            )
        }

    return {
        "status": "findings_present",
        "message": f"Session contains {len(findings)} finding(s), but no BOLA candidate was recorded."
    }


def build_session_summary_text(session_obj, roles, findings, judge_decisions, observations):
    roles_total = len(roles)
    authenticated_roles = len([r for r in roles if r.access_token])
    findings_total = len(findings)
    bola_findings = [f for f in findings if f.finding_type == "possible_bola"]

    base = (
        f"В рамках сессии тестирования #{session_obj.id} для цели '{session_obj.target_name}' "
        f"({session_obj.target_url}) система выполнила автоматизированную кампанию анализа API. "
        f"В ходе кампании было подготовлено {roles_total} ролей, из которых успешно аутентифицированы "
        f"{authenticated_roles}. Всего накоплено {len(observations)} наблюдений, принято "
        f"{len(judge_decisions)} решений арбитража и зафиксировано {findings_total} результатов анализа."
    )

    if bola_findings:
        finding = bola_findings[0]
        evidence = _safe_load_json(finding.evidence_json) or {}
        endpoint = finding.endpoint or "N/A"
        owner_role = evidence.get("owner_role", "unknown")
        other_role = evidence.get("other_role", "unknown")
        status_owner = evidence.get("status_owner", "unknown")
        status_other = evidence.get("status_other", "unknown")

        bola_text = (
            f" Наиболее значимым результатом стал кандидат на Broken Object Level Authorization. "
            f"Система автоматически выбрала гипотезу проверки объектного доступа и выполнила запрос "
            f"к endpoint '{endpoint}' от имени ролей {owner_role} и {other_role}. "
            f"Обе роли получили успешные ответы ({status_owner} и {status_other}), "
            f"а содержимое ответов было интерпретировано как эквивалентное, что дало основание "
            f"классифицировать результат как 'possible_bola'. "
            f"Найденный результат сохранён в виде finding с уровнем критичности '{finding.severity}' "
            f"и статусом верификации '{finding.verification_status}'."
        )
        return base + bola_text

    no_bola_text = (
        " По итогам кампании кандидаты на BOLA не были зафиксированы, однако собранные observations "
        "и judge trace могут быть использованы для последующего ручного анализа и расширения набора проверок."
    )
    return base + no_bola_text


def build_session_executive_summary(session_obj, findings):
    bola_findings = [f for f in findings if f.finding_type == "possible_bola"]

    if bola_findings:
        return {
            "risk_level": "high",
            "headline": "Обнаружен кандидат на нарушение объектного разграничения доступа",
            "message": (
                f"Для цели '{session_obj.target_name}' автоматизированная кампания выявила "
                f"{len(bola_findings)} кандидат(а/ов) на Broken Object Level Authorization."
            )
        }

    return {
        "risk_level": "low",
        "headline": "Критические кандидаты не обнаружены",
        "message": (
            f"Для цели '{session_obj.target_name}' автоматизированная кампания не выявила "
            "критических кандидатов на BOLA."
        )
    }