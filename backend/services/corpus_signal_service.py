"""Phase 8 — backend-owned corpus signal bridge.

Creates lightweight Observations from already-stored RequestCorpus signals.
No tools are executed, no EvidencePacks are built, no Judge is called, and no
Findings are created here.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

try:
    from backend.models.observation import Observation, SecurityRelevance
    from backend.services.request_corpus_service import RequestCorpusService
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.observation import Observation, SecurityRelevance
    from services.request_corpus_service import RequestCorpusService
    from storage.memory_store import memory_store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_observation_id() -> str:
    return f"obs_{uuid4().hex[:16]}"


class CorpusSignalService:
    def __init__(self) -> None:
        self._corpus = RequestCorpusService()

    def create_cross_role_signals(
        self,
        campaign_id: str,
        *,
        operation_id: str = "",
        limit: int = 10,
    ) -> dict[str, Any]:
        candidates = self._corpus.find_cross_role_candidates(campaign_id)
        observations: list[Observation] = []
        created = 0
        existing = 0
        max_items = max(0, int(limit or 0))

        for candidate in candidates:
            if max_items and len(observations) >= max_items:
                break
            if operation_id and str(candidate.get("operation_key", "")) != operation_id:
                continue

            for object_id in candidate.get("overlapping_ids", []) or []:
                if max_items and len(observations) >= max_items:
                    break
                obs, was_created = self._create_or_get_observation(
                    campaign_id=campaign_id,
                    candidate=candidate,
                    object_id=str(object_id),
                )
                observations.append(obs)
                if was_created:
                    created += 1
                else:
                    existing += 1

        return {
            "campaign_id": campaign_id,
            "observations_created": created,
            "already_existing": existing,
            "observations": [obs.model_dump(mode="json") for obs in observations],
        }

    def _create_or_get_observation(
        self,
        *,
        campaign_id: str,
        candidate: dict[str, Any],
        object_id: str,
    ) -> tuple[Observation, bool]:
        operation_key = str(candidate.get("operation_key", "") or "")
        role_a = str(candidate.get("role_a", "") or "")
        role_b = str(candidate.get("role_b", "") or "")
        sample_a = str(candidate.get("sample_request_a", "") or "")
        sample_b = str(candidate.get("sample_request_b", "") or "")
        owner_role = self._infer_owner_role(campaign_id, object_id, role_a, role_b)
        attacker_role = role_b if owner_role == role_a else role_a
        owner_request_id = sample_a if owner_role == role_a else sample_b
        attack_request_id = sample_b if owner_role == role_a else sample_a
        operation_id = operation_key if operation_key.startswith("op_") else ""
        operation_context = operation_id or operation_key
        key = self._idempotency_key(
            campaign_id, operation_context, object_id, owner_role, attacker_role
        )

        existing = self._find_existing(campaign_id, key)
        if existing is not None:
            return existing, False

        details = {
            "object_id": object_id,
            "owner_role": owner_role,
            "attacker_role": attacker_role,
            "owner_request_id": owner_request_id,
            "attack_request_id": attack_request_id,
            "baseline_request_id": owner_request_id,
            "candidate": {
                "source": "request_corpus.cross_role_candidate",
                "operation_key": operation_key,
                "role_a": role_a,
                "role_b": role_b,
                "sample_request_a": sample_a,
                "sample_request_b": sample_b,
                "overlapping_ids": candidate.get("overlapping_ids", []),
                "confidence": candidate.get("confidence", 0.0),
            },
            "idempotency_key": key,
        }
        obs = Observation(
            observation_id=_make_observation_id(),
            campaign_id=campaign_id,
            source="request_corpus",
            type="cross_role_access_signal",
            operation_id=operation_id,
            request_id=attack_request_id,
            auth_profile=attacker_role,
            confidence=float(candidate.get("confidence", 0.0) or 0.0),
            security_relevance=SecurityRelevance.high,
            judge_worthy=False,
            recommended_next_action="prove_ownership",
            details=details,
            created_at=_now_iso(),
        )
        memory_store.store_observation(
            obs.observation_id,
            campaign_id,
            "",
            obs.model_dump(mode="json"),
        )
        return obs, True

    def _infer_owner_role(
        self, campaign_id: str, object_id: str, role_a: str, role_b: str
    ) -> str:
        for raw in memory_store.list_resources_by_campaign(campaign_id):
            if str(raw.get("object_id", "") or "") != object_id:
                continue
            owner = str(raw.get("owner_role", "") or "")
            if owner in {role_a, role_b}:
                return owner
        return role_a

    @staticmethod
    def _idempotency_key(
        campaign_id: str,
        operation_id: str,
        object_id: str,
        owner_role: str,
        attacker_role: str,
    ) -> str:
        return "|".join([
            campaign_id,
            "cross_role_access_signal",
            operation_id,
            object_id,
            owner_role,
            attacker_role,
        ])

    @staticmethod
    def _find_existing(campaign_id: str, key: str) -> Observation | None:
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            details = raw.get("details") if isinstance(raw, dict) else {}
            if not isinstance(details, dict):
                continue
            if details.get("idempotency_key") != key:
                continue
            if raw.get("type") != "cross_role_access_signal":
                continue
            return Observation.model_validate(raw)
        return None
