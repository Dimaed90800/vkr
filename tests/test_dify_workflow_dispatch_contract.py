from pathlib import Path


WORKFLOW_PATH = Path(__file__).resolve().parents[1] / "dify" / "wf-multiagent-dast-multiworker.yml"


def test_dispatcher_falls_back_when_scheduler_omits_next_task_but_tasks_are_runnable() -> None:
    workflow = WORKFLOW_PATH.read_text()

    assert 'state["scheduler_selection_missing_next_task"] = True' in workflow
    assert 'active, remaining, fallback_reason = _local_fallback_selection(pending_tasks)' in workflow


def test_parser_rescue_treats_object_replay_strategies_as_preparation_tasks() -> None:
    workflow = WORKFLOW_PATH.read_text()

    assert "def _task_requires_preparation(active_task):" in workflow
    assert "'create_object_then_replay'" in workflow
    assert "'object_specific_auth_probe'" in workflow
    assert "needs_preparation = bool(payload.get('needs_preparation') or _task_requires_preparation(active_task))" in workflow
