# CLAUDE_REFACTOR_PROMPT.md

Use this prompt when giving the repository to Claude/Codex.

---

You are refactoring an existing diploma project backend for an adaptive multi-agent REST API DAST system.

First read:

1. `CLAUDE.md`
2. `docs/BACKEND_CURRENT_STATE.md`
3. `docs/REFACTOR_ROADMAP.md`
4. `docs/ARCHITECTURE_DATA_CONTRACTS.md`
5. `docs/DIFY_BACKEND_CONTRACT.md`
6. `docs/TESTING_STRATEGY.md`
7. Existing `README.md`, `README_ARCHITECTURE_AGENTIC.md`, `MIGRATION_NOTES.md`
8. Current Dify workflow: `dify/wf-multiagent-dast-multiworker.yml`

Task:

Refactor incrementally toward the campaign-based architecture.

Do not do a big-bang rewrite.

Start with Phase 1 from `docs/REFACTOR_ROADMAP.md`:

- add campaign compatibility model and service;
- keep existing `run_id` compatibility;
- expose create/summary endpoints if missing;
- do not break existing Dify workflow;
- add tests.

Important constraints:

- Do not remove working BOLA/object replay/judge logic.
- Do not remove legacy experiment/report endpoints.
- Dify must remain thin and pass `campaign_id`.
- Backend must own state, graph, corpus, queue, evidence and findings.
- One loop iteration must execute one bounded task.
- Findings can be written only from confirmed judge verdicts.

After Phase 1, stop and summarize:

- files changed;
- tests added;
- tests run;
- next recommended phase.
