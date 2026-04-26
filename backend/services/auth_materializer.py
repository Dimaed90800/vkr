"""Phase 9A — role auth materialization for replay adapters."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.services.request_corpus_service import redact_sensitive_data
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from services.request_corpus_service import redact_sensitive_data


@dataclass
class AuthMaterializationError:
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class MaterializedAuth:
    role: str
    headers: dict[str, Any] = field(default_factory=dict)
    cookies: dict[str, Any] = field(default_factory=dict)

    def redacted(self) -> dict[str, Any]:
        headers_redacted, _ = redact_sensitive_data(self.headers, None)
        return {
            "role": self.role,
            "headers": headers_redacted,
            "cookies": {str(k): "<redacted>" for k in self.cookies},
        }


class AuthMaterializer:
    def materialize(
        self,
        campaign: Campaign,
        role: str,
        *,
        extra_headers: dict[str, Any] | None = None,
        extra_cookies: dict[str, Any] | None = None,
    ) -> tuple[MaterializedAuth | None, AuthMaterializationError | None]:
        role_name = str(role or "").strip()
        if not role_name:
            return MaterializedAuth(
                role="",
                headers=dict(extra_headers or {}),
                cookies=dict(extra_cookies or {}),
            ), None

        entry = self._find_role(campaign, role_name)
        if entry is None:
            return None, AuthMaterializationError(
                code="auth_profile_not_found",
                message=f"Auth profile '{role_name}' is not configured.",
                details={"role": role_name},
            )

        headers = dict(entry.get("headers") or {})
        cookies = dict(entry.get("cookies") or {})
        bearer = str(entry.get("bearer_token") or "").strip()
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"

        headers.update(extra_headers or {})
        cookies.update(extra_cookies or {})
        return MaterializedAuth(role=role_name, headers=headers, cookies=cookies), None

    @staticmethod
    def _find_role(campaign: Campaign, role: str) -> dict[str, Any] | None:
        lowered = role.lower()
        for item in campaign.roles_json or []:
            if not isinstance(item, dict):
                continue
            if str(item.get("name") or "").strip().lower() == lowered:
                return item
        return None
