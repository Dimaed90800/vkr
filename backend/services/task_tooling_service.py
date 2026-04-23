from __future__ import annotations

from typing import Iterable

try:
    from backend.models.testing import TaskModel
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import TaskModel


DIRECT_TEST_TOOLS_BY_CLASS = {
    "authorization": [
        "akto_authz_scan",
        "akto_inventory_discovery",
        "astf_top10_suite",
        "auth_test_access",
        "property_mutation_test",
        "replay_http_sequence",
    ],
    "injection": [
        "schemathesis_negative_test",
        "cats_fuzz_test",
        "astf_top10_suite",
        "injection_test",
        "reflection_probe",
        "path_fuzz_probe",
        "data_exposure_test",
        "resource_abuse_test",
        "runtime_inventory",
    ],
    "business_logic": [
        "schemathesis_stateful_test",
        "restler_fuzz",
        "restler_replay",
        "restler_compile",
        "akto_authz_scan",
        "akto_inventory_discovery",
        "cats_fuzz_test",
        "astf_top10_suite",
        "logic_test",
        "resource_abuse_test",
        "bounded_burst_helper",
        "replay_http_sequence",
        "runtime_inventory",
        "misconfiguration_test",
        "version_diff_test",
    ],
}

PREPARATION_TOOLS_BY_CLASS = {
    "authorization": ["auto_provision", "auth_probe_entrypoints", "create_test_object"],
    "injection": ["input_shape_probe", "import_har_capture"],
    "business_logic": ["workflow_probe", "import_har_capture"],
}

PREPARATION_TOOLS = {tool for values in PREPARATION_TOOLS_BY_CLASS.values() for tool in values}
WRAPPER_TOOLS = {
    "restler_compile",
    "restler_fuzz",
    "restler_replay",
    "schemathesis_negative_test",
    "schemathesis_stateful_test",
    "cats_fuzz_test",
    "akto_inventory_discovery",
    "akto_authz_scan",
    "astf_top10_suite",
}

DISCOVERY_SUPPORT_TOOLS = {
    "import_har_capture",
    "runtime_inventory",
    "capture_authenticated_traffic",
    "capture_anonymous_traffic",
}

UTILITY_TOOLS = {
    "bounded_burst_helper",
    "replay_http_sequence",
}


def merge_unique(*values: Iterable[str] | None) -> list[str]:
    merged: list[str] = []
    for group in values:
        for item in group or []:
            normalized = str(item or "").strip()
            if normalized and normalized not in merged:
                merged.append(normalized)
    return merged


class TaskToolingService:
    """Keeps agent-facing tool assignments consistent across generation, follow-ups and scheduling."""

    def normalize_task(self, task: TaskModel, *, explicit_allowed_tools: list[str] | None = None) -> TaskModel:
        updated = self.mutable_task_copy(task)
        updated.allowed_tools = self.normalized_allowed_tools(updated, explicit_allowed_tools=explicit_allowed_tools)
        updated.preparation_options = self.normalized_preparation_options(updated)
        updated.recommended_next_step = self.recommended_next_step(updated)
        return updated

    def mutable_task_copy(self, task: TaskModel) -> TaskModel:
        """Copy fields the scheduler mutates without recursively copying arbitrary metadata."""
        return task.model_copy(
            deep=False,
            update={
                "params": task.params.model_copy(deep=True),
                "auth_context": task.auth_context.model_copy(deep=True),
                "prerequisites": task.prerequisites.model_copy(deep=True),
                "tool_preference": task.tool_preference.model_copy(deep=True),
                "allowed_tools": list(task.allowed_tools or []),
                "required_capabilities": list(task.required_capabilities or []),
                "preparation_options": list(task.preparation_options or []),
                "capability_state": dict(task.capability_state or {}),
                "context_hints": dict(task.context_hints or {}),
                "expected_evidence": list(task.expected_evidence or []),
                "fallback_tools": list(task.fallback_tools or []),
                "artifact_requirements": list(task.artifact_requirements or []),
            },
        )

    def normalized_allowed_tools(self, task: TaskModel, *, explicit_allowed_tools: list[str] | None = None) -> list[str]:
        class_name = str(task.class_name or "").strip().lower()
        readiness = str(task.readiness or "ready_to_test").strip().lower()
        preferred_tool = str(task.preferred_tool or (task.tool_preference.preferred_tool if task.tool_preference else "") or "").strip()
        fallback_tools = list(task.fallback_tools or (task.tool_preference.fallback_tools if task.tool_preference else []) or [])
        allowed_tools = list(explicit_allowed_tools if explicit_allowed_tools is not None else (task.allowed_tools or []))

        if readiness == "needs_preparation":
            return merge_unique(
                [item for item in allowed_tools if item in PREPARATION_TOOLS],
                task.preparation_options,
                [preferred_tool] if preferred_tool in PREPARATION_TOOLS else [],
                [item for item in fallback_tools if item in PREPARATION_TOOLS],
                PREPARATION_TOOLS_BY_CLASS.get(class_name, []),
            )

        return merge_unique(
            [preferred_tool] if preferred_tool else [],
            allowed_tools,
            fallback_tools,
            DIRECT_TEST_TOOLS_BY_CLASS.get(class_name, []),
        )

    def normalized_preparation_options(self, task: TaskModel) -> list[str]:
        class_name = str(task.class_name or "").strip().lower()
        readiness = str(task.readiness or "ready_to_test").strip().lower()
        if readiness != "needs_preparation":
            return []
        preferred_tool = str(task.preferred_tool or (task.tool_preference.preferred_tool if task.tool_preference else "") or "").strip()
        fallback_tools = list(task.fallback_tools or (task.tool_preference.fallback_tools if task.tool_preference else []) or [])
        return merge_unique(
            task.preparation_options,
            [preferred_tool] if preferred_tool in PREPARATION_TOOLS else [],
            [item for item in fallback_tools if item in PREPARATION_TOOLS],
            PREPARATION_TOOLS_BY_CLASS.get(class_name, []),
        )

    def recommended_next_step(self, task: TaskModel) -> str | None:
        readiness = str(task.readiness or "ready_to_test").strip().lower()
        preferred_tool = str(task.preferred_tool or (task.tool_preference.preferred_tool if task.tool_preference else "") or "").strip()
        if readiness == "needs_preparation":
            options = self.normalized_preparation_options(task)
            if preferred_tool in options:
                return preferred_tool
            return options[0] if options else (task.recommended_next_step or None)

        options = self.normalized_allowed_tools(task)
        if preferred_tool in options:
            return preferred_tool
        return options[0] if options else (task.recommended_next_step or None)


DEFAULT_TASK_TOOLING = TaskToolingService()
