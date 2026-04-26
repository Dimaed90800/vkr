"""Phase 11A — ZAP discovery/passive adapter tests."""
from __future__ import annotations

import json

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.zap_discovery_passive_adapter import ZapDiscoveryPassiveAdapter
from backend.services.observation_normalizer import ObservationNormalizer
from backend.services.tool_executor import ToolExecutor
from backend.services.zap_passive_client import ZapPassiveClientError, ZapPassiveResult
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "campaigns", "campaign_by_run_id", "campaign_by_session_id",
        "corpus_items", "corpus_by_campaign", "resource_instances",
        "resources_by_campaign", "graphs_by_campaign", "commands",
        "commands_by_campaign", "command_fingerprints", "tool_runs",
        "tool_runs_by_campaign", "tool_results", "artifacts",
        "artifacts_by_run", "observations", "observations_by_campaign",
        "observations_by_tool_run", "verification_plans",
        "verification_plans_by_campaign", "evidence_packs",
        "evidence_packs_by_campaign", "evidence_packs_by_observation",
        "evidence_packs_by_verification_plan", "judge_decisions",
        "judge_decisions_by_campaign", "judge_decisions_by_evidence",
        "confirmed_findings", "confirmed_findings_by_campaign",
        "findings_by_fingerprint", "evidence_pack_apply_meta",
        "observation_apply_meta",
    ]:
        getattr(memory_store, name).clear()
    memory_store.evidence_records.clear()
    memory_store.findings.clear()
    memory_store.evidence_by_session.clear()
    memory_store.findings_by_session.clear()


def _campaign(**overrides) -> Campaign:
    data = {
        "campaign_id": "cmp_zap",
        "target_url": "http://target.local",
        "allowed_hosts": ["target.local"],
        "limits": CampaignLimits(max_requests=100, max_duration_sec=60),
    }
    data.update(overrides)
    campaign = Campaign(**data)
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _command(**overrides) -> WorkerCommand:
    defaults = {
        "campaign_id": "cmp_zap",
        "worker_class": "discovery_inventory",
        "strategy": "zap_discovery_passive",
        "tool_name": "zap_discovery_passive",
        "operation_id": "op_GET_/api/users",
        "inputs": {
            "target_url": "http://target.local",
            "seed_urls": ["http://target.local/api"],
            "use_spider": True,
            "max_duration_sec": 10,
            "max_discovered_urls": 10,
            "max_alerts": 10,
        },
        "budget": CommandBudget(max_requests=1, timeout_sec=30),
    }
    defaults.update(overrides)
    return WorkerCommand(**defaults)


class FakeZapClient:
    def __init__(self, result: ZapPassiveResult | None = None, error: ZapPassiveClientError | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict] = []

    def run_discovery_passive(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result or ZapPassiveResult()


def test_zap_discovery_passive_creates_discovered_endpoint_and_zap_alert_signals():
    _reset_store()
    campaign = _campaign()
    fake = FakeZapClient(ZapPassiveResult(
        version="2.16.1",
        discovered_urls=[
            "http://target.local/api/users?token=secret",
            "http://evil.local/api/hidden",
        ],
        alerts=[{
            "alert": "Missing Anti-clickjacking Header",
            "risk": "Medium",
            "confidence": "High",
            "url": "http://target.local/api/users?session=secret",
            "pluginId": "10020",
            "evidence": "Authorization: Bearer very-secret-token",
        }],
        metadata={"source": "test"},
    ))

    result = ZapDiscoveryPassiveAdapter(zap_client=fake).execute(
        _command(),
        campaign,
        "toolrun_zap",
    )

    assert result.status == "finished"
    assert [obs.observation_type for obs in result.observations] == [
        "discovered_endpoint",
        "zap_alert",
    ]
    assert result.observations[0].details["url"].startswith("http://target.local/api/users")
    assert "token=secret" not in result.observations[0].details["url"]
    assert result.observations[1].details["alert_name"] == "Missing Anti-clickjacking Header"
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    payload = json.dumps(artifact)
    assert "evil.local" not in payload
    assert "very-secret-token" not in payload
    assert "ignored_out_of_scope" in payload


def test_zap_discovery_passive_rejects_empty_allowed_hosts_before_zap_call():
    _reset_store()
    campaign = _campaign(allowed_hosts=[])
    fake = FakeZapClient(ZapPassiveResult())

    result = ZapDiscoveryPassiveAdapter(zap_client=fake).execute(
        _command(),
        campaign,
        "toolrun_zap",
    )

    assert result.status == "failed"
    assert result.errors[0].error_type == "allowed_hosts_not_configured"
    assert fake.calls == []


def test_zap_discovery_passive_rejects_out_of_scope_seed_before_zap_call():
    _reset_store()
    campaign = _campaign()
    fake = FakeZapClient(ZapPassiveResult())
    cmd = _command(inputs={
        "target_url": "http://target.local",
        "seed_urls": ["http://evil.local/api"],
    })

    result = ZapDiscoveryPassiveAdapter(zap_client=fake).execute(
        cmd,
        campaign,
        "toolrun_zap",
    )

    assert result.status == "failed"
    assert result.errors[0].error_type == "host_not_allowed"
    assert fake.calls == []


def test_zap_discovery_passive_limits_observations():
    _reset_store()
    campaign = _campaign()
    fake = FakeZapClient(ZapPassiveResult(
        discovered_urls=[
            "http://target.local/api/one",
            "http://target.local/api/two",
        ],
        alerts=[
            {"alert": "A", "url": "http://target.local/api/one"},
            {"alert": "B", "url": "http://target.local/api/two"},
        ],
    ))
    cmd = _command(inputs={
        "target_url": "http://target.local",
        "max_discovered_urls": 1,
        "max_alerts": 1,
    })

    result = ZapDiscoveryPassiveAdapter(zap_client=fake).execute(
        cmd,
        campaign,
        "toolrun_zap",
    )

    assert result.status == "finished"
    assert [obs.observation_type for obs in result.observations].count("discovered_endpoint") == 1
    assert [obs.observation_type for obs in result.observations].count("zap_alert") == 1


def test_zap_discovery_passive_ignores_out_of_scope_alert_urls():
    _reset_store()
    campaign = _campaign()
    fake = FakeZapClient(ZapPassiveResult(
        discovered_urls=["http://target.local/api/one"],
        alerts=[
            {"alert": "InScope", "url": "http://target.local/api/one"},
            {"alert": "OutScope", "url": "http://evil.local/api/x"},
        ],
    ))

    result = ZapDiscoveryPassiveAdapter(zap_client=fake).execute(
        _command(),
        campaign,
        "toolrun_zap",
    )

    assert result.status == "finished"
    alert_obs = [obs for obs in result.observations if obs.observation_type == "zap_alert"]
    assert len(alert_obs) == 1
    assert alert_obs[0].details["alert_name"] == "InScope"


def test_zap_discovery_passive_client_error_returns_failed_tool_result():
    _reset_store()
    campaign = _campaign()
    fake = FakeZapClient(error=ZapPassiveClientError(
        code="zap_unreachable",
        message="ZAP API is unreachable.",
    ))

    result = ZapDiscoveryPassiveAdapter(zap_client=fake).execute(
        _command(),
        campaign,
        "toolrun_zap",
    )

    assert result.status == "failed"
    assert result.errors[0].error_type == "zap_unreachable"


def test_zap_discovery_passive_timeout_returns_partial_and_preserves_discovered():
    _reset_store()
    campaign = _campaign()

    class TimeoutWithDiscoveryClient:
        def run_discovery_passive(self, **kwargs):
            raise ZapPassiveClientError(
                code="zap_passive_timeout",
                message="Passive queue did not drain.",
                details={"records_to_scan": 3},
            )

        def core_urls(self, base_url: str):
            return [
                "http://target.local/api/users",
                "http://evil.local/api/hidden",
            ]

        def alerts(self, base_url: str, *, count: int = 100):
            return [
                {"alert": "InScopeAlert", "url": "http://target.local/api/users"},
                {"alert": "OutScopeAlert", "url": "http://evil.local/api/hidden"},
            ]

    result = ZapDiscoveryPassiveAdapter(zap_client=TimeoutWithDiscoveryClient()).execute(
        _command(),
        campaign,
        "toolrun_zap",
    )

    assert result.status == "partial"
    assert any(err.error_type == "zap_passive_timeout" for err in result.errors)
    assert any(obs.observation_type == "discovered_endpoint" for obs in result.observations)
    assert [obs for obs in result.observations if obs.observation_type == "zap_alert"][0].details["alert_name"] == "InScopeAlert"
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    payload = json.dumps(artifact)
    assert "timeout_diagnostic" in payload
    assert "OutScopeAlert" not in payload


def test_invalid_external_zap_base_url_rejected_before_client_call():
    _reset_store()
    _campaign()
    fake = FakeZapClient(ZapPassiveResult(discovered_urls=["http://target.local/api/users"]))
    cmd = _command(inputs={
        "target_url": "http://target.local",
        "zap_base_url": "http://evil.local:8080",
    })

    result = ToolExecutor(zap_passive_client=fake).execute_sync(cmd)

    assert result.status == "failed"
    assert result.errors
    assert result.errors[0].error_type == "validation_failed"
    assert "approved internal ZAP endpoint" in result.errors[0].message
    assert fake.calls == []


def test_valid_internal_zap_base_url_accepted():
    _reset_store()
    _campaign()
    fake = FakeZapClient(ZapPassiveResult(discovered_urls=["http://target.local/api/users"]))
    cmd = _command(inputs={
        "target_url": "http://target.local",
        "zap_base_url": "http://zap:8080",
    })

    result = ToolExecutor(zap_passive_client=fake).execute_sync(cmd)

    assert result.status == "finished"
    assert fake.calls != []


def test_zap_discovery_passive_normalizes_to_observations_without_evidence_or_findings():
    _reset_store()
    campaign = _campaign()
    fake = FakeZapClient(ZapPassiveResult(
        discovered_urls=["http://target.local/api/users"],
        alerts=[{"alert": "Passive Alert", "url": "http://target.local/api/users"}],
    ))
    result = ZapDiscoveryPassiveAdapter(zap_client=fake).execute(
        _command(),
        campaign,
        "toolrun_zap",
    )
    memory_store.store_tool_run("toolrun_zap", campaign.campaign_id, {
        "tool_run_id": "toolrun_zap",
        "campaign_id": campaign.campaign_id,
        "tool_name": "zap_discovery_passive",
        "status": "finished",
    })
    memory_store.store_tool_result("toolrun_zap", result.model_dump(mode="json"))

    observations = ObservationNormalizer().normalize("toolrun_zap")

    assert not isinstance(observations, Exception)
    assert [obs.type.value for obs in observations] == ["discovered_endpoint", "zap_alert"]
    assert memory_store.evidence_packs == {}
    assert memory_store.judge_decisions == {}
    assert memory_store.confirmed_findings == {}
    assert memory_store.findings == []
    assert memory_store.evidence_records == []
