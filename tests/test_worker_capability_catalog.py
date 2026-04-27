"""Phase 17A.1 — WorkerCapabilityCatalog metadata."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.services.tool_registry import ToolRegistry
from backend.services.worker_capability_catalog import WorkerCapabilityCatalog


def test_catalog_has_schema_version_and_counts() -> None:
    resp = WorkerCapabilityCatalog().response()
    assert resp.schema_version == "worker-capability-catalog/v1"
    assert "implemented" in resp.counts
    assert "partial" in resp.counts
    assert "planned" in resp.counts
    assert sum(resp.counts.values()) == len(resp.workers)


def test_catalog_contains_current_implemented_workers() -> None:
    cat = WorkerCapabilityCatalog()
    tools = {w.tool_name for w in cat.list_capabilities() if w.tool_name}
    assert "zap_discovery_passive" in tools
    assert "security_header_validator" in tools
    assert "schemathesis_negative_test" in tools


def test_schemathesis_capability_is_finding_capable() -> None:
    w = WorkerCapabilityCatalog().get_by_tool_name("schemathesis_negative_test")
    assert w is not None
    assert w.evidence_support is True
    assert w.judge_support is True


def test_security_header_capability_is_finding_capable() -> None:
    w = WorkerCapabilityCatalog().get_by_tool_name("security_header_validator")
    assert w is not None
    assert w.evidence_support is True
    assert w.judge_support is True


def test_bola_capability_is_partial_and_requires_auth_seed() -> None:
    w = WorkerCapabilityCatalog().get_by_tool_name("bola_replay_probe")
    assert w is not None
    assert w.status == "partial"
    assert w.requires_auth is True
    assert w.requires_seed is True
    assert w.requires_corpus is True


def test_injection_worker_now_partial_with_adapter() -> None:
    w = WorkerCapabilityCatalog().get_by_tool_name("injection_test")
    assert w is not None
    assert w.status == "partial"
    assert w.risk_level == "high"
    assert w.adapter_available is True
    assert w.execution_mode == "sync"


def test_injection_worker_observation_type_injection_signal() -> None:
    w = WorkerCapabilityCatalog().get_by_tool_name("injection_test")
    assert w is not None
    assert "injection_signal" in w.observation_types
    assert "injection_testing" in w.scenario_types
    assert w.triage_support is True
    assert w.evidence_support is True
    assert w.judge_support is True


def test_filter_by_scenario_type_returns_injection_worker() -> None:
    rows = WorkerCapabilityCatalog().filter_by_scenario_type("injection_testing")
    assert any(w.tool_name == "injection_test" for w in rows)


def test_get_by_tool_name() -> None:
    assert WorkerCapabilityCatalog().get_by_tool_name("nuclei") is not None
    assert WorkerCapabilityCatalog().get_by_tool_name("no_such_tool_xyz") is None


def test_no_duplicate_tool_names_for_non_materialization_workers() -> None:
    skip = frozenset(
        {"auth_materialization_worker", "object_seed_materialization_worker"}
    )
    seen: set[str] = set()
    for w in WorkerCapabilityCatalog().list_capabilities():
        if w.worker_name in skip:
            continue
        t = (w.tool_name or "").strip()
        if not t:
            continue
        assert t not in seen, f"duplicate tool_name: {t}"
        seen.add(t)


def test_adapter_available_matches_known_implemented_workers_semantically() -> None:
    reg = ToolRegistry()
    cat = WorkerCapabilityCatalog()
    for w in cat.list_capabilities():
        if w.status != "implemented":
            continue
        if not w.tool_name:
            continue
        assert w.adapter_available == reg.has_adapter(w.tool_name), w.tool_name
