from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

try:
    from backend.models.auth_profile import AuthProfile
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.auth_profile import AuthProfile
    from storage.memory_store import memory_store


_DROP_KEY_PARTS = (
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "secret",
    "bearer",
)

_SAFE_EXACT_KEYS = {"token_ref", "token_field_path", "credential_ref"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuthProfileStore:
    def create_auth_profile(
        self,
        *,
        campaign_id: str,
        role_hint: str,
        user_label: str,
        auth_type: str,
        raw_token: Any = None,
        raw_credentials: dict[str, Any] | None = None,
        created_by: str,
        expires_at: str = "not_available",
        metadata: dict[str, Any] | None = None,
    ) -> AuthProfile:
        token_ref = ""
        if raw_token not in (None, "", {}):
            token_ref = f"tokenref_{uuid4().hex[:16]}"
            memory_store.store_runtime_token_secret(token_ref, raw_token)

        safe_meta = dict(metadata or {})
        if raw_credentials:
            credential_ref = f"credref_{uuid4().hex[:16]}"
            memory_store.store_runtime_credential_secret(credential_ref, dict(raw_credentials))
            safe_meta.setdefault("credential_ref", credential_ref)

        profile = AuthProfile(
            auth_profile_id=f"authprof_{uuid4().hex[:16]}",
            campaign_id=campaign_id,
            role_hint=str(role_hint or "unknown"),
            user_label=str(user_label or ""),
            auth_type=str(auth_type or "unknown"),
            token_ref=token_ref,
            created_by=str(created_by or ""),
            created_at=_now_iso(),
            expires_at=str(expires_at or "not_available"),
            metadata=self._sanitize_mapping(safe_meta),
        )
        memory_store.store_auth_profile(
            profile.auth_profile_id,
            campaign_id,
            profile.model_dump(mode="json"),
        )
        return profile

    def get_token_by_ref(self, token_ref: str) -> Any:
        return memory_store.get_runtime_token_secret(str(token_ref or ""))

    def get_credential_by_ref(self, credential_ref: str) -> Any:
        return memory_store.get_runtime_credential_secret(str(credential_ref or ""))

    def get_auth_profile(self, auth_profile_id: str) -> AuthProfile | None:
        data = memory_store.get_auth_profile(str(auth_profile_id or ""))
        if data is None:
            return None
        return AuthProfile.model_validate(data)

    def list_auth_profiles(self, campaign_id: str) -> list[dict[str, Any]]:
        return [
            self.sanitize_auth_profile(AuthProfile.model_validate(item))
            for item in memory_store.list_auth_profiles_by_campaign(campaign_id)
        ]

    def sanitize_auth_profile(self, profile: AuthProfile | dict[str, Any]) -> dict[str, Any]:
        payload = profile.model_dump(mode="json") if isinstance(profile, AuthProfile) else dict(profile or {})
        payload["metadata"] = self._sanitize_mapping(payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {})
        return payload

    def _sanitize_mapping(self, payload: dict[str, Any]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in payload.items():
            k = str(key or "")
            lowered = k.lower()
            if lowered not in _SAFE_EXACT_KEYS and any(part in lowered for part in _DROP_KEY_PARTS):
                continue
            if isinstance(value, dict):
                out[k] = self._sanitize_mapping(value)
            elif isinstance(value, list):
                safe_list: list[Any] = []
                for item in value:
                    if isinstance(item, dict):
                        safe_list.append(self._sanitize_mapping(item))
                    else:
                        safe_list.append(item)
                out[k] = safe_list
            else:
                out[k] = value
        return out
