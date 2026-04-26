"""Phase 7 - backend-owned Judge verdict application.

This service applies an already-produced Judge verdict to stored EvidencePack
state. It does not call a Judge, execute tools, enqueue scheduler tasks, write
legacy evidence records, or create legacy findings.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4

try:
    from backend.models.evidence_pack import EvidencePack, EvidencePackStatus
    from backend.models.judge import (
        ConfirmedFinding,
        FindingCandidatePayload,
        JudgeApplyRequest,
        JudgeApplyResult,
        JudgeDecisionRecord,
        JudgeVerdictKind,
    )
    from backend.models.observation import (
        VerificationPlan,
        VerificationPlanCommand,
        VerificationPlanStatus,
    )
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.evidence_pack import EvidencePack, EvidencePackStatus
    from models.judge import (
        ConfirmedFinding,
        FindingCandidatePayload,
        JudgeApplyRequest,
        JudgeApplyResult,
        JudgeDecisionRecord,
        JudgeVerdictKind,
    )
    from models.observation import (
        VerificationPlan,
        VerificationPlanCommand,
        VerificationPlanStatus,
    )
    from storage.memory_store import memory_store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_decision_id() -> str:
    return f"jdec_{uuid4().hex[:16]}"


def _make_finding_id() -> str:
    return f"finding_{uuid4().hex[:16]}"


def _make_plan_id() -> str:
    return f"vplan_{uuid4().hex[:16]}"


class JudgeApplyError:
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        self.code = code
        self.message = message
        self.status_code = status_code


class JudgeApplyService:
    def apply(
        self, request: JudgeApplyRequest
    ) -> tuple[JudgeApplyResult | None, JudgeApplyError | None]:
        if memory_store.get_campaign(request.campaign_id) is None:
            return None, JudgeApplyError(
                "campaign_not_found",
                f"Campaign '{request.campaign_id}' not found.",
                404,
            )

        raw_pack = memory_store.get_evidence_pack(request.evidence_id)
        if raw_pack is None:
            return None, JudgeApplyError(
                "evidence_pack_not_found",
                f"EvidencePack '{request.evidence_id}' not found.",
                404,
            )
        pack = EvidencePack.model_validate(raw_pack)
        if pack.campaign_id != request.campaign_id:
            return None, JudgeApplyError(
                "campaign_mismatch",
                (
                    f"EvidencePack campaign_id '{pack.campaign_id}' does not "
                    f"match request campaign_id '{request.campaign_id}'."
                ),
                409,
            )

        verdict = request.verdict.verdict
        if verdict == JudgeVerdictKind.confirmed:
            return self._apply_confirmed(request, pack), None
        if verdict == JudgeVerdictKind.rework:
            return self._apply_rework(request, pack, JudgeVerdictKind.rework), None
        if verdict == JudgeVerdictKind.rejected:
            return self._apply_terminal(request, pack, JudgeVerdictKind.rejected), None
        if verdict == JudgeVerdictKind.out_of_scope:
            return self._apply_terminal(request, pack, JudgeVerdictKind.out_of_scope), None
        if verdict == JudgeVerdictKind.inconclusive:
            return self._apply_inconclusive(request, pack), None
        if verdict == JudgeVerdictKind.duplicate:
            return self._apply_duplicate(request, pack)
        return None, JudgeApplyError("unsupported_verdict", f"Unsupported verdict '{verdict}'.")

    def _apply_confirmed(
        self, request: JudgeApplyRequest, pack: EvidencePack
    ) -> JudgeApplyResult:
        readiness = self._readiness_issues(pack)
        if pack.status == EvidencePackStatus.not_judge_ready:
            return self._apply_terminal(
                request,
                pack,
                JudgeVerdictKind.inconclusive,
                applied_status="applied_with_downgrade",
                readiness_issues=["evidence_not_judge_ready", *readiness],
                notes=["confirmed_downgraded_to_inconclusive"],
            )
        if readiness:
            return self._apply_rework(
                request,
                pack,
                JudgeVerdictKind.rework,
                applied_status="applied_with_downgrade",
                readiness_issues=["evidence_incomplete", *readiness],
                notes=["confirmed_downgraded_to_rework"],
            )

        fingerprint = self._fingerprint(pack, request.verdict.finding_candidate)
        existing = memory_store.get_finding_by_fingerprint(pack.campaign_id, fingerprint)
        decision_id = _make_decision_id()
        finding: ConfirmedFinding | None = None
        finding_id = ""
        duplicate_of = ""

        if existing is not None:
            duplicate_of = str(existing.get("finding_id", "") or "")
            finding_id = duplicate_of
        else:
            finding = self._build_finding(request, pack, decision_id, fingerprint)
            finding_id = finding.finding_id
            memory_store.store_confirmed_finding(
                finding.finding_id,
                finding.campaign_id,
                finding.fingerprint,
                finding.model_dump(mode="json"),
            )

        decision = self._decision(
            request,
            pack,
            JudgeVerdictKind.confirmed,
            decision_id=decision_id,
            finding_id=finding_id,
            duplicate_of_finding_id=duplicate_of,
        )
        self._store_decision_and_meta(decision, pack)
        if duplicate_of:
            memory_store.append_finding_duplicate(duplicate_of, decision.decision_id)

        return JudgeApplyResult(
            status=decision.applied_status,
            decision_id=decision.decision_id,
            decision=decision,
            finding_id=finding_id,
            finding=finding,
            duplicate_of_finding_id=duplicate_of,
            readiness_issues=[],
            campaign_summary=self._campaign_summary(pack.campaign_id),
        )

    def _apply_rework(
        self,
        request: JudgeApplyRequest,
        pack: EvidencePack,
        verdict: JudgeVerdictKind,
        applied_status: str = "applied",
        readiness_issues: list[str] | None = None,
        notes: list[str] | None = None,
    ) -> JudgeApplyResult:
        issues = list(readiness_issues or self._readiness_issues(pack))
        plan = self._create_or_reuse_followup_plan(request, pack)
        decision = self._decision(
            request,
            pack,
            verdict,
            created_followup_verification_plan_id=(
                plan.verification_plan_id if plan else ""
            ),
            readiness_issues=issues,
            applied_status=applied_status,
            notes=notes or [],
        )
        self._store_decision_and_meta(decision, pack)
        return JudgeApplyResult(
            status=decision.applied_status,
            decision_id=decision.decision_id,
            decision=decision,
            followup_verification_plan_id=decision.created_followup_verification_plan_id,
            followup_verification_plan=plan,
            readiness_issues=issues,
            campaign_summary=self._campaign_summary(pack.campaign_id),
        )

    def _apply_inconclusive(
        self, request: JudgeApplyRequest, pack: EvidencePack
    ) -> JudgeApplyResult:
        plan = None
        if pack.missing_evidence and request.create_rework_on_inconclusive:
            plan = self._create_or_reuse_followup_plan(request, pack)
        decision = self._decision(
            request,
            pack,
            JudgeVerdictKind.inconclusive,
            created_followup_verification_plan_id=(
                plan.verification_plan_id if plan else ""
            ),
            readiness_issues=self._readiness_issues(pack),
        )
        self._store_decision_and_meta(decision, pack)
        return JudgeApplyResult(
            status=decision.applied_status,
            decision_id=decision.decision_id,
            decision=decision,
            followup_verification_plan_id=decision.created_followup_verification_plan_id,
            followup_verification_plan=plan,
            readiness_issues=decision.readiness_issues,
            campaign_summary=self._campaign_summary(pack.campaign_id),
        )

    def _apply_terminal(
        self,
        request: JudgeApplyRequest,
        pack: EvidencePack,
        verdict: JudgeVerdictKind,
        applied_status: str = "applied",
        readiness_issues: list[str] | None = None,
        notes: list[str] | None = None,
    ) -> JudgeApplyResult:
        decision = self._decision(
            request,
            pack,
            verdict,
            readiness_issues=readiness_issues or [],
            applied_status=applied_status,
            notes=notes or [],
        )
        self._store_decision_and_meta(decision, pack)
        return JudgeApplyResult(
            status=decision.applied_status,
            decision_id=decision.decision_id,
            decision=decision,
            readiness_issues=decision.readiness_issues,
            campaign_summary=self._campaign_summary(pack.campaign_id),
        )

    def _apply_duplicate(
        self, request: JudgeApplyRequest, pack: EvidencePack
    ) -> tuple[JudgeApplyResult | None, JudgeApplyError | None]:
        target_id = request.verdict.duplicate_of_finding_id
        if not target_id:
            fp = self._fingerprint(pack, request.verdict.finding_candidate)
            target = memory_store.get_finding_by_fingerprint(pack.campaign_id, fp)
            target_id = str(target.get("finding_id", "") or "") if target else ""
        if not target_id:
            return None, JudgeApplyError(
                "duplicate_target_required",
                "Duplicate verdict requires duplicate_of_finding_id or an existing fingerprint match.",
                422,
            )
        target = memory_store.get_confirmed_finding(target_id)
        if target is None:
            return None, JudgeApplyError(
                "duplicate_target_required",
                f"Duplicate target '{target_id}' was not found.",
                422,
            )
        if target.get("campaign_id") != pack.campaign_id:
            return None, JudgeApplyError(
                "duplicate_target_other_campaign",
                f"Duplicate target '{target_id}' belongs to another campaign.",
                409,
            )

        decision = self._decision(
            request,
            pack,
            JudgeVerdictKind.duplicate,
            duplicate_of_finding_id=target_id,
        )
        self._store_decision_and_meta(decision, pack)
        memory_store.append_finding_duplicate(target_id, decision.decision_id)
        return JudgeApplyResult(
            status=decision.applied_status,
            decision_id=decision.decision_id,
            decision=decision,
            duplicate_of_finding_id=target_id,
            campaign_summary=self._campaign_summary(pack.campaign_id),
        ), None

    def _decision(
        self,
        request: JudgeApplyRequest,
        pack: EvidencePack,
        verdict: JudgeVerdictKind,
        decision_id: str | None = None,
        finding_id: str = "",
        duplicate_of_finding_id: str = "",
        created_followup_verification_plan_id: str = "",
        readiness_issues: list[str] | None = None,
        applied_status: str = "applied",
        notes: list[str] | None = None,
    ) -> JudgeDecisionRecord:
        payload = request.verdict
        return JudgeDecisionRecord(
            decision_id=decision_id or _make_decision_id(),
            campaign_id=pack.campaign_id,
            evidence_id=pack.evidence_id,
            observation_id=pack.observation_id,
            verification_plan_id=pack.verification_plan_id,
            task_id=request.task_id or pack.task_id,
            verdict=verdict,
            confidence=float(payload.confidence or pack.confidence or 0.0),
            severity=self._severity(payload, pack),
            reason=payload.reason,
            judge_source=payload.judge_source,
            judge_model=payload.judge_model,
            duplicate_of_finding_id=duplicate_of_finding_id,
            finding_id=finding_id,
            created_followup_verification_plan_id=created_followup_verification_plan_id,
            readiness_issues=list(dict.fromkeys(readiness_issues or [])),
            applied_status=applied_status,
            notes=notes or [],
            created_at=_now_iso(),
        )

    def _build_finding(
        self,
        request: JudgeApplyRequest,
        pack: EvidencePack,
        decision_id: str,
        fingerprint: str,
    ) -> ConfirmedFinding:
        candidate = request.verdict.finding_candidate
        return ConfirmedFinding(
            finding_id=_make_finding_id(),
            campaign_id=pack.campaign_id,
            evidence_id=pack.evidence_id,
            observation_id=pack.observation_id,
            verification_plan_id=pack.verification_plan_id,
            task_id=request.task_id or pack.task_id,
            decision_id=decision_id,
            fingerprint=fingerprint,
            owasp_category=pack.owasp_category,
            vulnerability_class=(
                candidate.vulnerability_class or pack.vulnerability_class
            ),
            operation_id=pack.operation_id,
            endpoint=pack.endpoint,
            method=pack.method,
            title=candidate.title or self._default_title(pack),
            severity=self._severity(request.verdict, pack),
            confidence=float(request.verdict.confidence or pack.confidence or 0.0),
            summary=candidate.summary or pack.hypothesis,
            reproduction_pointer={
                "evidence_id": pack.evidence_id,
                "replay_steps_count": len(pack.replay_steps),
                "artifact_refs_count": len(pack.artifact_refs),
            },
            candidate_extras=candidate.extras,
            created_at=_now_iso(),
        )

    def _create_or_reuse_followup_plan(
        self, request: JudgeApplyRequest, pack: EvidencePack
    ) -> VerificationPlan | None:
        existing = self._find_active_plan(pack)
        if existing is not None:
            return existing
        if self._rework_depth(pack) >= max(0, request.max_rework_depth):
            return None

        required = [m.code for m in pack.missing_evidence]
        plan = VerificationPlan(
            verification_plan_id=_make_plan_id(),
            campaign_id=pack.campaign_id,
            parent_observation_id=pack.observation_id,
            parent_task_id=pack.task_id,
            goal=request.rework_hint or "collect_missing_evidence",
            worker_class="",
            strategy=request.rework_hint or "collect_missing_evidence",
            required_evidence=required,
            commands=[],
            status=VerificationPlanStatus.pending,
            created_at=_now_iso(),
        )
        memory_store.store_verification_plan(
            plan.verification_plan_id,
            plan.campaign_id,
            plan.model_dump(mode="json"),
        )
        return plan

    def _find_active_plan(self, pack: EvidencePack) -> VerificationPlan | None:
        for raw in memory_store.list_verification_plans_by_campaign(pack.campaign_id):
            plan = VerificationPlan.model_validate(raw)
            if plan.parent_observation_id != pack.observation_id:
                continue
            if plan.status in {
                VerificationPlanStatus.pending,
                VerificationPlanStatus.in_progress,
            }:
                return plan
        return None

    def _rework_depth(self, pack: EvidencePack) -> int:
        return sum(
            1
            for raw in memory_store.list_verification_plans_by_campaign(pack.campaign_id)
            if raw.get("parent_observation_id") == pack.observation_id
        )

    def _store_decision_and_meta(
        self, decision: JudgeDecisionRecord, pack: EvidencePack
    ) -> None:
        memory_store.store_judge_decision(
            decision.decision_id,
            decision.campaign_id,
            decision.evidence_id,
            decision.model_dump(mode="json"),
        )
        meta = {
            "applied_status": decision.applied_status,
            "decision_id": decision.decision_id,
            "finding_id": decision.finding_id,
            "verdict": decision.verdict.value,
        }
        memory_store.mark_evidence_pack_applied(pack.evidence_id, meta)
        memory_store.mark_observation_applied(pack.observation_id, meta)

    def _readiness_issues(self, pack: EvidencePack) -> list[str]:
        issues = [m.code for m in pack.missing_evidence]
        if pack.status != EvidencePackStatus.ready_for_judge:
            issues.append(f"status:{pack.status.value}")
        if not pack.judge_ready:
            issues.append("judge_ready_false")
        return list(dict.fromkeys(issues))

    def _fingerprint(
        self, pack: EvidencePack, candidate: FindingCandidatePayload
    ) -> str:
        parts = [
            pack.campaign_id,
            pack.owasp_category,
            candidate.vulnerability_class or pack.vulnerability_class,
            pack.operation_id,
            pack.endpoint,
            pack.method,
            candidate.title,
        ]
        parts.extend(self._authorization_fingerprint_context(pack))
        payload = "|".join(parts)
        return hashlib.sha256(payload.encode()).hexdigest()[:32]

    def _authorization_fingerprint_context(self, pack: EvidencePack) -> list[str]:
        category = (pack.owasp_category or "").upper()
        vulnerability_class = (pack.vulnerability_class or "").lower()
        is_authorization_like = (
            category.startswith(("API1_", "API2_", "API5_"))
            or "bola" in vulnerability_class
            or "bfla" in vulnerability_class
            or "auth" in vulnerability_class
            or "access" in vulnerability_class
        )
        if not is_authorization_like:
            return []

        context: list[tuple[str, str]] = []
        if pack.ownership_proof:
            context.extend([
                ("object_id", pack.ownership_proof.object_id),
                ("owner_role", pack.ownership_proof.owner_role),
            ])
        if pack.baseline:
            context.append(("baseline_role", pack.baseline.role))
        if pack.attack:
            context.append(("attack_role", pack.attack.role))

        control_roles = sorted({
            control.role
            for control in pack.controls
            if getattr(control, "role", "")
        })
        context.extend(("control_role", role) for role in control_roles)
        return [f"{key}:{value}" for key, value in context if value]

    def _severity(self, verdict, pack: EvidencePack) -> str:
        candidate = getattr(verdict, "finding_candidate", FindingCandidatePayload())
        explicit = (getattr(verdict, "severity", "") or candidate.severity or "").strip()
        if explicit:
            return explicit
        cat = (pack.owasp_category or "").upper()
        if cat in {"API1_BOLA", "API2_AUTH", "API5_BFLA"}:
            return "high"
        if cat.startswith("API3_BOPLA") or cat.startswith("API4_"):
            return "medium"
        if cat.startswith("API8_") or cat.startswith("API9_"):
            return "low"
        return "info"

    def _default_title(self, pack: EvidencePack) -> str:
        category = pack.owasp_category or pack.vulnerability_class or "security issue"
        target = f" on {pack.method} {pack.endpoint}" if pack.endpoint else ""
        return f"Confirmed {category}{target}"

    def _campaign_summary(self, campaign_id: str) -> dict:
        return {
            "campaign_id": campaign_id,
            "decisions": len(memory_store.list_judge_decisions_by_campaign(campaign_id)),
            "confirmed_findings": len(memory_store.list_confirmed_findings_by_campaign(campaign_id)),
        }
