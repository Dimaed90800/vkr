from __future__ import annotations

import json

from backend.services.auth_profile_store import AuthProfileStore
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    memory_store.auth_profiles.clear()
    memory_store.auth_profiles_by_campaign.clear()
    memory_store.runtime_token_secrets.clear()
    memory_store.runtime_credential_secrets.clear()


def test_create_profile_stores_token_ref_but_not_raw_token_in_sanitized_profile() -> None:
    _reset_store()
    store = AuthProfileStore()
    profile = store.create_auth_profile(
        campaign_id="cmp_auth",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="super-secret-token",
        raw_credentials={"email": "vkr_owner@example.test", "password": "P@ssw0rd!"},
        created_by="test_account_materializer",
        metadata={"signup_operation_id": "op_signup", "login_operation_id": "op_login", "token_field_path": "$.token"},
    )
    sanitized = store.sanitize_auth_profile(profile)
    assert sanitized["token_ref"].startswith("tokenref_")
    blob = json.dumps(sanitized, sort_keys=True).lower()
    assert "super-secret-token" not in blob
    assert "p@ssw0rd!" not in blob
    assert "authorization" not in blob
    assert "set-cookie" not in blob


def test_get_token_by_ref_returns_raw_token_internally() -> None:
    _reset_store()
    store = AuthProfileStore()
    profile = store.create_auth_profile(
        campaign_id="cmp_auth",
        role_hint="attacker",
        user_label="attacker_user",
        auth_type="bearer",
        raw_token="raw-token-value",
        created_by="test_account_materializer",
        metadata={"token_field_path": "$.access_token"},
    )
    assert store.get_token_by_ref(profile.token_ref) == "raw-token-value"


def test_list_profiles_returns_sanitized_data_only() -> None:
    _reset_store()
    store = AuthProfileStore()
    store.create_auth_profile(
        campaign_id="cmp_auth",
        role_hint="owner",
        user_label="owner_user",
        auth_type="cookie",
        raw_token={"sessionid": "cookie-secret"},
        raw_credentials={"email": "vkr_owner@example.test", "password": "P@ssw0rd!"},
        created_by="test_account_materializer",
        metadata={"signup_operation_id": "op_signup", "login_operation_id": "op_login", "token_field_path": "$.token"},
    )
    rows = store.list_auth_profiles("cmp_auth")
    assert len(rows) == 1
    blob = json.dumps(rows, sort_keys=True).lower()
    assert "cookie-secret" not in blob
    assert "p@ssw0rd!" not in blob
    assert "authorization" not in blob
    assert "bearer " not in blob
