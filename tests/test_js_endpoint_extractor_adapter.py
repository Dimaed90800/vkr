from __future__ import annotations

import json

import httpx

from backend.models.api_graph import ApiGraph, Operation
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.js_endpoint_extractor_adapter import JsEndpointExtractorAdapter
from backend.services.api_graph_path_matcher import clear_route_fragment_suffix_cache
from backend.services.http.safe_http_client import SafeHttpClient
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    memory_store.artifacts.clear()
    memory_store.artifacts_by_run.clear()
    memory_store.graphs_by_campaign.clear()
    clear_route_fragment_suffix_cache()


def _store_graph(campaign_id: str, path_template: str, operation_id: str = "op_posts_recent") -> None:
    graph = ApiGraph(
        campaign_id=campaign_id,
        operations=[
            Operation(
                operation_id=operation_id,
                method="GET",
                path_template=path_template,
            ),
        ],
    )
    memory_store.store_graph_for_campaign(campaign_id, graph.model_dump(mode="json"))
    clear_route_fragment_suffix_cache()


def _campaign() -> Campaign:
    return Campaign(
        campaign_id="cmp_js",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )


def _command(**input_overrides) -> WorkerCommand:
    inputs = {
        "target_url": "http://target.local",
        "js_url": "http://target.local/static/app.js?token=abc",
        "source_observation_id": "obs_js_1",
        "validation_mode": "static_js_endpoint_extraction",
        "max_js_bytes": 3000000,
        "max_endpoints": 50,
    }
    inputs.update(input_overrides)
    return WorkerCommand(
        campaign_id="cmp_js",
        worker_class="discovery_inventory",
        strategy="extract_js_endpoints",
        tool_name="js_endpoint_extractor",
        inputs=inputs,
        budget=CommandBudget(max_requests=1, timeout_sec=15),
    )


def _discovered(observations: list) -> list:
    return [o for o in observations if str(o.observation_type) == "discovered_endpoint"]


def _marker(observations: list):
    markers = [o for o in observations if str(o.observation_type) == "js_endpoint_extraction_result"]
    return markers[0] if markers else None


def _adapter(js_body: str) -> JsEndpointExtractorAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/javascript"},
            text=js_body,
        )

    return JsEndpointExtractorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )


def test_js_endpoint_extractor_extracts_api_paths_from_sample_js() -> None:
    _reset_store()
    js_body = """
    window.__CFG__ = {
      users: "/api/v1/users?token=abc",
      profile: "/identity/api/profile",
      full: "http://target.local/community/api/feed?page=1"
    };
    """
    result = _adapter(js_body).execute(_command(), _campaign(), "toolrun_js")
    assert result.status == "finished"
    paths = [obs.details.get("path") for obs in _discovered(result.observations)]
    assert paths == ["/api/v1/users", "/identity/api/profile", "/community/api/feed"]
    m = _marker(result.observations)
    assert m is not None
    assert m.details.get("result") == "endpoints_extracted"


def test_js_endpoint_extractor_ignores_static_assets_and_caps_max_endpoints() -> None:
    _reset_store()
    js_body = """
    const a="/static/app.css";
    const b="/v1/one";
    const c="/v1/two";
    const d="/images/logo.png";
    """
    result = _adapter(js_body).execute(
        _command(max_endpoints=1),
        _campaign(),
        "toolrun_js_cap",
    )
    assert result.status == "finished"
    assert [obs.details.get("path") for obs in _discovered(result.observations)] == ["/v1/one"]


def test_js_endpoint_extractor_discards_out_of_scope_full_urls() -> None:
    _reset_store()
    js_body = 'const hidden = "http://evil.local/api/admin"; const local = "/api/local";'
    result = _adapter(js_body).execute(_command(), _campaign(), "toolrun_js_scope")
    assert result.status == "finished"
    assert [obs.details.get("path") for obs in _discovered(result.observations)] == ["/api/local"]


def test_js_endpoint_extractor_has_no_raw_js_leakage_in_result_or_artifact() -> None:
    _reset_store()
    js_body = """
    const secret = "Authorization: Bearer supersecret";
    const cookie = "Cookie: session=abc123";
    const api = "/api/v1/admin?token=abc";
    """
    result = _adapter(js_body).execute(_command(), _campaign(), "toolrun_js_leak")
    assert result.status == "finished"
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    blob = json.dumps(
        {
            "result": result.model_dump(mode="json"),
            "artifact": artifact,
        },
        sort_keys=True,
    ).lower()
    for bad in (
        "authorization",
        "cookie",
        "set-cookie",
        "bearer ",
        "supersecret",
        "abc123",
        "token=abc",
        "request_body",
        "response_body",
        "headers",
        "raw_body",
    ):
        assert bad not in blob


def test_js_endpoint_extractor_emits_marker_only_when_no_api_paths() -> None:
    _reset_store()
    js_body = 'console.log("hello"); const asset="/static/site.css";'
    result = _adapter(js_body).execute(_command(), _campaign(), "toolrun_js_none")
    assert result.status == "finished"
    assert len(result.observations) == 1
    m = _marker(result.observations)
    assert m is not None
    assert m.details.get("result") == "no_api_paths_found"
    assert _discovered(result.observations) == []
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    content = json.loads(str(artifact.get("content") or "{}"))
    assert content.get("result") == "no_api_paths_found"


def test_js_endpoint_extractor_response_too_large_emits_marker_only() -> None:
    _reset_store()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/javascript"},
            text='const x = "Authorization: Bearer supersecret"; const y="/api/hidden";',
        )

    adapter = JsEndpointExtractorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(
        _command(max_js_bytes=8),
        _campaign(),
        "toolrun_js_too_large",
    )
    assert result.status == "finished"
    assert len(result.observations) == 1
    m = _marker(result.observations)
    assert m is not None
    assert m.details.get("result") == "js_too_large_skipped"
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    content = json.loads(str(artifact.get("content") or "{}"))
    assert content.get("js_url_sanitized") == "http://target.local/static/app.js"
    assert isinstance(content.get("source_js_ref"), str) and content["source_js_ref"]
    assert content.get("endpoints_extracted_count") == 0
    assert content.get("endpoints_emitted_count") == 0
    assert content.get("result") == "js_too_large_skipped"
    assert content.get("reason_codes") == ["response_too_large"]
    blob = json.dumps(
        {"result": result.model_dump(mode="json"), "artifact": artifact},
        sort_keys=True,
    ).lower()
    for bad in (
        "authorization",
        "cookie",
        "set-cookie",
        "bearer ",
        "supersecret",
        "token=abc",
        "headers",
        "request_body",
        "response_body",
        "raw_body",
    ):
        assert bad not in blob


def test_js_route_fragment_graph_match_emits_marker_and_discovered() -> None:
    _reset_store()
    _store_graph("cmp_js", "/community/api/v2/community/posts/recent")
    js_body = 'const route = "community/posts/recent";'
    result = _adapter(js_body).execute(_command(), _campaign(), "toolrun_frag")
    assert result.status == "finished"
    assert _marker(result.observations) is not None
    disc = _discovered(result.observations)
    assert len(disc) == 1
    assert disc[0].details.get("path") == "/community/api/v2/community/posts/recent"
    assert disc[0].details.get("operation_id") == "op_posts_recent"
    assert disc[0].details.get("openapi_match_hint") is True
    assert disc[0].details.get("route_fragment") == "community/posts/recent"


def test_js_route_fragment_unmatched_emits_marker_only_zero_emitted() -> None:
    _reset_store()
    _store_graph("cmp_js", "/api/v1/other")
    js_body = 'const route = "community/posts/recent";'
    result = _adapter(js_body).execute(_command(), _campaign(), "toolrun_unmatched")
    assert result.status == "finished"
    assert _discovered(result.observations) == []
    m = _marker(result.observations)
    assert m is not None
    assert int(m.details.get("endpoints_emitted_count") or 0) == 0
    assert m.details.get("result") == "route_fragments_found"


def test_js_route_fragment_multi_match_skips_discovered_endpoint() -> None:
    _reset_store()
    graph = ApiGraph(
        campaign_id="cmp_js",
        operations=[
            Operation(operation_id="op_a", method="GET", path_template="/api/v1/a/posts/recent"),
            Operation(operation_id="op_b", method="GET", path_template="/api/v2/b/posts/recent"),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_js", graph.model_dump(mode="json"))
    clear_route_fragment_suffix_cache()
    js_body = 'const route = "posts/recent";'
    result = _adapter(js_body).execute(_command(), _campaign(), "toolrun_multi")
    assert _discovered(result.observations) == []
    m = _marker(result.observations)
    assert m is not None
    assert int(m.details.get("multi_match_skipped") or 0) >= 1


def test_js_route_fragment_filters_noisy_paths() -> None:
    _reset_store()
    _store_graph("cmp_js", "/community/api/v2/community/posts/recent")
    js_body = """
    const good = "community/posts/recent";
    const bad1 = "static/chunk/main.js";
    const bad2 = "theme/dark/colors";
    """
    result = _adapter(js_body).execute(_command(), _campaign(), "toolrun_noise")
    disc = _discovered(result.observations)
    assert len(disc) == 1
    assert disc[0].details.get("path") == "/community/api/v2/community/posts/recent"
