"""Phase 5.6 — ObservationTriage.

Triages a single Observation: sets security_relevance,
recommended_next_action, and optionally creates a VerificationPlan.

Phase 5.6 rules:
- judge_worthy stays False for ALL observations.
- No EvidencePack, Judge input, or confirmed findings.
- VerificationPlan.commands are lightweight stubs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

try:
    from backend.models.observation import (
        Observation,
        SecurityRelevance,
        VerificationPlan,
        VerificationPlanCommand,
        VerificationPlanStatus,
    )
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.observation import (
        Observation,
        SecurityRelevance,
        VerificationPlan,
        VerificationPlanCommand,
        VerificationPlanStatus,
    )
    from storage.memory_store import memory_store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_plan_id() -> str:
    return f"vplan_{uuid4().hex[:16]}"


_TRIAGE_RULES: dict[str, dict] = {
    "unexpected_500": {
        "security_relevance": "low",
        "recommended_next_action": "replay_minimized_payload",
        "goal": "replay_minimized_payload",
        "worker_class": "contract_fuzzing",
        "strategy": "replay_minimized_payload",
        "required_evidence": ["minimized_request", "reproduced_500"],
    },
    "server_error_candidate": {
        "security_relevance": "low",
        "recommended_next_action": "replay_minimized_payload",
        "goal": "replay_minimized_payload",
        "worker_class": "contract_fuzzing",
        "strategy": "replay_minimized_payload",
        "required_evidence": ["minimized_request", "reproduced_500"],
    },
    "cross_role_access_signal": {
        "security_relevance": "high",
        "recommended_next_action": "prove_ownership",
        "goal": "prove_ownership",
        "worker_class": "access_control",
        "strategy": "prove_ownership",
        "required_evidence": [
            "owner_collection_contains_object",
            "attacker_collection_does_not_contain_object",
        ],
    },
    "validated_security_header_issue": {
        "security_relevance": "medium",
        "recommended_next_action": "prove_security_header_misconfiguration",
        "goal": "prove_security_header_misconfiguration",
        "worker_class": "misconfiguration",
        "strategy": "prove_security_header_misconfiguration",
        "required_evidence": [],
    },
    "zap_alert": {
        "security_relevance": "medium",
        "recommended_next_action": "replay_misconfiguration",
        "goal": "replay_misconfiguration",
        "worker_class": "misconfiguration",
        "strategy": "replay_misconfiguration",
        "required_evidence": ["replayed_response_confirms_alert"],
    },
    "nuclei_match": {
        "security_relevance": "medium",
        "recommended_next_action": "validate_template_match",
        "goal": "validate_template_match",
        "worker_class": "misconfiguration",
        "strategy": "validate_template_match",
        "required_evidence": ["reproduced_match"],
    },
    "discovered_endpoint": {
        "security_relevance": "low",
        "recommended_next_action": "undocumented_endpoint_auth_check",
        "goal": "undocumented_endpoint_auth_check",
        "worker_class": "discovery_inventory",
        "strategy": "undocumented_endpoint_auth_check",
        "required_evidence": ["auth_required_confirmed", "no_auth_access_result"],
    },
    "hidden_parameter": {
        "security_relevance": "low",
        "recommended_next_action": "parameter_replay_validation",
        "goal": "parameter_replay_validation",
        "worker_class": "contract_fuzzing",
        "strategy": "parameter_replay_validation",
        "required_evidence": ["parameter_impact_confirmed"],
    },
    "auth_anomaly": {
        "security_relevance": "medium",
        "recommended_next_action": "auth_replay_validation",
        "goal": "auth_replay_validation",
        "worker_class": "access_control",
        "strategy": "auth_replay_validation",
        "required_evidence": ["auth_bypass_confirmed"],
    },
    "state_changed_after_invalid_payload": {
        "security_relevance": "medium",
        "recommended_next_action": "replay_minimized_payload",
        "goal": "replay_minimized_payload",
        "worker_class": "contract_fuzzing",
        "strategy": "replay_minimized_payload",
        "required_evidence": ["state_change_reproduced"],
    },
}

_STORE_ONLY_TYPES = {
    "timeout_signal",
    "unsupported_tool_signal",
    "tool_error",
    "sensitive_field_seen",
}


class ObservationTriage:

    def triage(self, observation_id: str) -> tuple[Observation | None, VerificationPlan | None, str | None]:
        """Triage a single observation.

        Returns (observation, verification_plan_or_None, error_or_None).
        """
        obs_data = memory_store.get_observation(observation_id)
        if obs_data is None:
            return None, None, "observation_not_found"

        obs = Observation.model_validate(obs_data)
        obs_type = obs.type

        if obs_type in _STORE_ONLY_TYPES:
            obs.recommended_next_action = "store_only"
            obs.security_relevance = SecurityRelevance.informational
            obs.judge_worthy = False
            self._persist_obs(obs)
            return obs, None, None

        if obs_type == "schema_mismatch":
            return self._triage_schema_mismatch(obs)

        rule = _TRIAGE_RULES.get(obs_type)
        if rule is None:
            obs.recommended_next_action = "store_only"
            obs.security_relevance = SecurityRelevance.informational
            obs.judge_worthy = False
            self._persist_obs(obs)
            return obs, None, None

        obs.security_relevance = SecurityRelevance(rule["security_relevance"])
        obs.recommended_next_action = rule["recommended_next_action"]
        obs.judge_worthy = False
        self._persist_obs(obs)

        existing_plan = self._find_existing_active_plan(obs)
        if existing_plan is not None:
            return obs, existing_plan, None

        plan = self._create_plan(obs, rule)
        return obs, plan, None

    def _triage_schema_mismatch(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        has_impact = bool(obs.details.get("impact"))
        if has_impact:
            obs.security_relevance = SecurityRelevance.low
            obs.recommended_next_action = "impact_validation"
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = self._create_plan(obs, {
                "goal": "impact_validation",
                "worker_class": "contract_fuzzing",
                "strategy": "impact_validation",
                "required_evidence": ["impact_confirmed"],
            })
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _create_plan(self, obs: Observation, rule: dict) -> VerificationPlan:
        plan = VerificationPlan(
            verification_plan_id=_make_plan_id(),
            campaign_id=obs.campaign_id,
            parent_observation_id=obs.observation_id,
            parent_task_id=obs.task_id,
            goal=rule["goal"],
            worker_class=rule.get("worker_class", ""),
            strategy=rule.get("strategy", ""),
            required_evidence=rule.get("required_evidence", []),
            commands=[
                VerificationPlanCommand(
                    tool_name="custom_request_executor",
                    strategy=rule.get("strategy", ""),
                    inputs={"parent_observation_id": obs.observation_id},
                ),
            ],
            status=VerificationPlanStatus.pending,
            created_at=_now_iso(),
        )
        memory_store.store_verification_plan(
            plan.verification_plan_id, obs.campaign_id,
            plan.model_dump(mode="json"),
        )
        return plan

    def _persist_obs(self, obs: Observation) -> None:
        memory_store.update_observation(obs.observation_id, obs.model_dump(mode="json"))

    def _find_existing_active_plan(self, obs: Observation) -> VerificationPlan | None:
        plans = memory_store.list_verification_plans_by_campaign(obs.campaign_id)
        for raw in plans:
            plan = VerificationPlan.model_validate(raw)
            if plan.parent_observation_id != obs.observation_id:
                continue
            if plan.status in {
                VerificationPlanStatus.pending,
                VerificationPlanStatus.in_progress,
            }:
                return plan
        return None
