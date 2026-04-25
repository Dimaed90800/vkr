from pathlib import Path


WORKFLOW_PATH = Path(__file__).resolve().parents[1] / "dify" / "wf-multiagent-dast-multiworker.yml"


def test_dispatcher_falls_back_when_scheduler_omits_next_task_but_tasks_are_runnable() -> None:
    workflow = WORKFLOW_PATH.read_text()

    assert 'state["scheduler_selection_missing_next_task"] = True' in workflow
    assert 'active, remaining, fallback_reason = _local_fallback_selection(pending_tasks)' in workflow


def test_dispatcher_persists_selected_task_snapshot_for_every_active_handoff() -> None:
    workflow = WORKFLOW_PATH.read_text()

    assert "def _dispatch_payload(state: dict, active: dict) -> dict:" in workflow
    assert 'execution_context["current_task_snapshot"] = active' in workflow
    assert 'state["active_task_snapshot"] = active' in workflow
    assert "return _dispatch_payload(state, active)" in workflow


def test_noop_active_task_does_not_exit_when_pending_tasks_remain_executable() -> None:
    workflow = WORKFLOW_PATH.read_text()

    assert "def _has_executable_pending_tasks(tasks) -> bool:" in workflow
    assert 'if _has_executable_pending_tasks(state.get("pending_tasks") or []):' in workflow
    assert '"noop_active_task_ignored"' in workflow
    assert '"should_exit_loop": False' in workflow


def test_noop_rescue_does_not_override_hard_stop_reasons() -> None:
    workflow = WORKFLOW_PATH.read_text()

    assert 'hard_stop_reasons = {"budget_exceeded", "timeout", "no_tasks", "max_requests_exhausted", "max_duration_exceeded"}' in workflow
    assert "and not stop_reason" in workflow
    assert "noop_active_task_ignored_count" in workflow
    assert 'state["stop_reason"] = stop_reason' in workflow


def test_business_parser_overrides_weak_legacy_tools_with_stateful_wrappers() -> None:
    workflow = WORKFLOW_PATH.read_text()

    assert "wrapper_first_tools = ['schemathesis_stateful_test', 'restler_fuzz', 'restler_replay', 'schemathesis_negative_test']" in workflow
    assert "class_name == 'business_logic' and not needs_preparation" in workflow
    assert "wrapper_first_override" in workflow
    assert "{'bounded_burst_helper', 'workflow_probe', 'logic_test', 'replay_http_sequence'}" in workflow


def test_parser_rescue_treats_object_replay_strategies_as_preparation_tasks() -> None:
    workflow = WORKFLOW_PATH.read_text()

    assert "def _task_requires_preparation(active_task):" in workflow
    assert "'create_object_then_replay'" in workflow
    assert "'object_specific_auth_probe'" in workflow
    assert "needs_preparation = bool(payload.get('needs_preparation') or _task_requires_preparation(active_task))" in workflow
