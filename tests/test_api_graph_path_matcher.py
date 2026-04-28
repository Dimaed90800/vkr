from __future__ import annotations

from backend.models.api_graph import ApiGraph, Operation
from backend.services.api_graph_path_matcher import (
    clear_route_fragment_suffix_cache,
    find_openapi_operation_match,
    is_static_or_service_asset,
    match_route_fragment,
    normalize_api_path,
    template_matches,
)
from backend.storage.memory_store import memory_store


def _reset_graphs() -> None:
    memory_store.graphs_by_campaign.clear()
    clear_route_fragment_suffix_cache()


def test_template_matches_path_params() -> None:
    assert template_matches("/users/{id}", "/users/123") is True
    assert template_matches("/users/{id}/orders/{orderId}", "/users/123/orders/456") is True
    assert template_matches("/users/{id}", "/users/123/orders") is False


def test_normalize_api_path_strips_query_and_trailing_slash() -> None:
    assert normalize_api_path("/users/123?x=1") == "/users/123"
    assert normalize_api_path("/users/123/") == "/users/123"


def test_static_or_service_assets_detected() -> None:
    assert is_static_or_service_asset("/static/app.css") is True
    assert is_static_or_service_asset("/robots.txt") is True
    assert is_static_or_service_asset("/api/v1/users") is False


def test_find_openapi_operation_match_uses_template_matching() -> None:
    _reset_graphs()
    graph = ApiGraph(
        campaign_id="cmp_match",
        operations=[
            Operation(
                operation_id="op_GET_/users/{id}",
                method="GET",
                path_template="/users/{id}",
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_match", graph.model_dump(mode="json"))
    assert find_openapi_operation_match("cmp_match", "GET", "/users/123?view=full") == "op_GET_/users/{id}"


def test_match_route_fragment_maps_nested_suffix() -> None:
    _reset_graphs()
    graph = ApiGraph(
        campaign_id="cmp_frag",
        operations=[
            Operation(
                operation_id="op_posts_recent",
                method="GET",
                path_template="/community/api/v2/community/posts/recent",
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_frag", graph.model_dump(mode="json"))
    matches = match_route_fragment("cmp_frag", "community/posts/recent", None, 3)
    assert len(matches) == 1
    assert matches[0]["path_template"] == "/community/api/v2/community/posts/recent"
    assert matches[0]["matched_suffix"] == "community/posts/recent"
    assert matches[0]["operation_id"] == "op_posts_recent"


def test_match_route_fragment_posts_recent_when_unique() -> None:
    _reset_graphs()
    graph = ApiGraph(
        campaign_id="cmp_frag2",
        operations=[
            Operation(
                operation_id="op_unique_tail",
                method="GET",
                path_template="/api/v1/foo/posts/recent",
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_frag2", graph.model_dump(mode="json"))
    matches = match_route_fragment("cmp_frag2", "posts/recent", None, 3)
    assert len(matches) == 1
    assert matches[0]["path_template"] == "/api/v1/foo/posts/recent"


def test_match_route_fragment_ambiguous_or_capped() -> None:
    _reset_graphs()
    graph = ApiGraph(
        campaign_id="cmp_amb",
        operations=[
            Operation(operation_id="op_a", method="GET", path_template="/api/v1/a/posts/recent"),
            Operation(operation_id="op_b", method="GET", path_template="/api/v2/b/posts/recent"),
            Operation(operation_id="op_c", method="GET", path_template="/api/v3/c/posts/recent"),
            Operation(operation_id="op_d", method="GET", path_template="/api/v4/d/posts/recent"),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_amb", graph.model_dump(mode="json"))
    matches = match_route_fragment("cmp_amb", "posts/recent", None, limit=2)
    assert len(matches) == 2
    oids = {m["operation_id"] for m in matches}
    assert oids <= {"op_a", "op_b", "op_c", "op_d"}


def test_match_route_fragment_empty_graph() -> None:
    _reset_graphs()
    assert match_route_fragment("cmp_empty", "posts/recent", None, 3) == []


def test_match_route_fragment_method_filter() -> None:
    _reset_graphs()
    graph = ApiGraph(
        campaign_id="cmp_meth",
        operations=[
            Operation(operation_id="op_get", method="GET", path_template="/api/items/list"),
            Operation(operation_id="op_post", method="POST", path_template="/api/items/list"),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_meth", graph.model_dump(mode="json"))
    assert len(match_route_fragment("cmp_meth", "items/list", "GET", 3)) == 1
    assert match_route_fragment("cmp_meth", "items/list", "GET", 3)[0]["operation_id"] == "op_get"
    assert len(match_route_fragment("cmp_meth", "items/list", "POST", 3)) == 1
    assert match_route_fragment("cmp_meth", "items/list", "POST", 3)[0]["operation_id"] == "op_post"
