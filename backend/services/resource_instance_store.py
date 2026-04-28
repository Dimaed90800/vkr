from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

try:
    from backend.models.resource_instance import ResourceInstance
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.resource_instance import ResourceInstance
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
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ResourceInstanceStore:
    def create_resource_instance(
        self,
        *,
        campaign_id: str,
        resource_type: str,
        object_id_field: str,
        raw_object_id: Any,
        source_operation_id: str,
        source_path: str,
        source_auth_profile_id: str,
        source_role_hint: str,
        confidence: str,
        created_by: str,
        metadata: dict[str, Any] | None = None,
    ) -> ResourceInstance:
        object_ref_id = f"objref_{uuid4().hex[:16]}"
        object_id_ref = f"objidref_{uuid4().hex[:16]}"
        memory_store.store_runtime_object_id_secret(object_id_ref, raw_object_id)
        instance = ResourceInstance(
            object_ref_id=object_ref_id,
            campaign_id=campaign_id,
            resource_type=str(resource_type or "unknown"),
            object_id_field=str(object_id_field or ""),
            object_id_ref=object_id_ref,
            source_operation_id=str(source_operation_id or ""),
            source_path=str(source_path or ""),
            source_auth_profile_id=str(source_auth_profile_id or ""),
            source_role_hint=str(source_role_hint or "unknown"),
            confidence=str(confidence or "low"),
            created_by=str(created_by or ""),
            created_at=_now_iso(),
            metadata=self._sanitize_mapping(metadata or {}),
        )
        memory_store.store_runtime_resource_instance(
            instance.object_ref_id,
            campaign_id,
            instance.model_dump(mode="json"),
        )
        return instance

    def get_raw_object_id(self, object_id_ref: str) -> Any:
        return memory_store.get_runtime_object_id_secret(str(object_id_ref or ""))

    def list_resource_instances(self, campaign_id: str) -> list[dict[str, Any]]:
        return [
            self.sanitize_resource_instance(ResourceInstance.model_validate(item))
            for item in memory_store.list_runtime_resource_instances_by_campaign(campaign_id)
        ]

    def sanitize_resource_instance(
        self,
        instance: ResourceInstance | dict[str, Any],
    ) -> dict[str, Any]:
        payload = instance.model_dump(mode="json") if isinstance(instance, ResourceInstance) else dict(instance or {})
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
