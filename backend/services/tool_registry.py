"""Phase 5 — ToolRegistry stub.

Distinguishes between:
- known tools (from Phase 4 ALL_KNOWN_TOOLS)
- tools with a supported adapter in Phase 5
- async-capable tools

Known but unsupported tools produce a controlled error, not a noop success.
"""
from __future__ import annotations

try:
    from backend.models.worker_command import ALL_KNOWN_TOOLS
except ModuleNotFoundError:  # pragma: no cover
    from models.worker_command import ALL_KNOWN_TOOLS


PHASE5_SUPPORTED_ADAPTERS: dict[str, str] = {
    "noop_tool": "noop",
    "custom_request_executor": "noop",
    "http_replay_executor": "http_replay",
    "bola_replay_probe": "bola_replay",
    "zap_discovery_passive": "zap_discovery_passive",
    "security_header_validator": "security_header_validator",
}

SYNC_ONLY_TOOLS: set[str] = {
    "custom_request_executor",
    "noop_tool",
    "http_replay_executor",
    "bola_replay_probe",
    "zap_discovery_passive",
    "security_header_validator",
    "auth_test_access",
    "replay_http_sequence",
    "property_mutation_test",
}

ASYNC_CAPABLE_TOOLS: set[str] = {
    "schemathesis_negative_test",
    "schemathesis_stateful_test",
    "restler_compile",
    "restler_fuzz",
    "restler_replay",
    "cats_fuzz_test",
    "nuclei",
    "zap",
    "ffuf",
    "kiterunner",
    "httpx",
    "arjun",
    "playwright_capture",
    "akto_inventory_discovery",
    "akto_authz_scan",
    "astf_top10_suite",
}


class ToolRegistry:
    def is_known(self, tool_name: str) -> bool:
        return tool_name in ALL_KNOWN_TOOLS or tool_name in PHASE5_SUPPORTED_ADAPTERS

    def has_adapter(self, tool_name: str) -> bool:
        return tool_name in PHASE5_SUPPORTED_ADAPTERS

    def get_execution_mode(self, tool_name: str) -> str:
        """Return 'sync', 'async', or 'either'."""
        if tool_name in SYNC_ONLY_TOOLS:
            return "sync"
        if tool_name in ASYNC_CAPABLE_TOOLS:
            return "async"
        return "sync"

    def resolve_execution_mode(
        self, tool_name: str, requested_mode: str | None
    ) -> str:
        """Resolve the actual execution mode given an optional caller override."""
        default = self.get_execution_mode(tool_name)
        if requested_mode is None:
            return default
        requested = requested_mode.strip().lower()
        if requested == default:
            return default
        if default == "sync" and requested == "async":
            return "sync"
        if default == "async" and requested == "sync":
            return "async"
        return default

    def list_tools(self) -> list[dict]:
        tools = []
        for name in sorted(ALL_KNOWN_TOOLS | set(PHASE5_SUPPORTED_ADAPTERS)):
            tools.append({
                "tool_name": name,
                "known": True,
                "has_adapter": name in PHASE5_SUPPORTED_ADAPTERS,
                "execution_mode": self.get_execution_mode(name),
            })
        return tools
