from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

try:
    from backend.models.bola_object_pair import BolaObjectPair
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.bola_object_pair import BolaObjectPair
    from storage.memory_store import memory_store


_DROP_KEY_PARTS = (
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "password",
    "secret",
    "raw",
    "body",
    "object_id",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class BolaObjectPairStore:
    def create_bola_object_pair(
        self,
        *,
        campaign_id: str,
        resource_type: str,
        object_ref_id: str,
        object_id_ref: str,
        owner_auth_profile_id: str,
        attacker_auth_profile_id: str,
        target_operation_id: str,
        target_path_template: str,
        target_method: str,
        path_param_name: str,
        confidence: str,
        created_by: str,
        reason_codes: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> BolaObjectPair:
        pair = BolaObjectPair(
            object_pair_id=f"objpair_{uuid4().hex[:16]}",
            campaign_id=str(campaign_id or ""),
            resource_type=str(resource_type or "unknown"),
            object_ref_id=str(object_ref_id or ""),
            object_id_ref=str(object_id_ref or ""),
            owner_auth_profile_id=str(owner_auth_profile_id or ""),
            attacker_auth_profile_id=str(attacker_auth_profile_id or ""),
            target_operation_id=str(target_operation_id or ""),
            target_path_template=str(target_path_template or ""),
            target_method=str(target_method or "GET").upper() or "GET",
            path_param_name=str(path_param_name or ""),
            confidence=str(confidence or "low"),
            created_by=str(created_by or "bola_object_pair_builder"),
            created_at=_now_iso(),
            reason_codes=[str(x) for x in (reason_codes or []) if str(x).strip()],
            metadata=self._sanitize_mapping(metadata or {}),
        )
        memory_store.store_runtime_bola_object_pair(
            pair.object_pair_id,
            campaign_id,
            pair.model_dump(mode="json"),
        )
        return pair

    def get_bola_object_pair(self, object_pair_id: str) -> BolaObjectPair | None:
        data = memory_store.get_runtime_bola_object_pair(str(object_pair_id or ""))
        if data is None:
            return None
        return BolaObjectPair.model_validate(data)

    def list_bola_object_pairs(self, campaign_id: str) -> list[dict[str, Any]]:
        return [
            self.sanitize_bola_object_pair(BolaObjectPair.model_validate(item))
            for item in memory_store.list_runtime_bola_object_pairs_by_campaign(str(campaign_id or ""))
        ]

    def sanitize_bola_object_pair(
        self,
        pair: BolaObjectPair | dict[str, Any],
    ) -> dict[str, Any]:
        payload = pair.model_dump(mode="json") if isinstance(pair, BolaObjectPair) else dict(pair or {})
        payload["metadata"] = self._sanitize_mapping(
            payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
        )
        return payload

    def _sanitize_mapping(self, payload: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in payload.items():
            lowered = str(key or "").strip().lower()
            if any(part in lowered for part in _DROP_KEY_PARTS):
                continue
            if isinstance(value, dict):
                out[str(key)] = self._sanitize_mapping(value)
            elif isinstance(value, list):
                safe_list: list[Any] = []
                for item in value:
                    if isinstance(item, dict):
                        safe_list.append(self._sanitize_mapping(item))
                    else:
                        safe_list.append(item)
                out[str(key)] = safe_list
            else:
                out[str(key)] = value
        return out
