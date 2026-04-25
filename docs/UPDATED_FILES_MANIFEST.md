# UPDATED_FILES_MANIFEST.md

These files were updated after the architecture discussion about:

```text
- agents as verification/exploitation planners, not just tool launchers;
- long-running fuzzers/scanners as ToolRun jobs;
- observations/signals separated from judge-ready EvidencePacks;
- no Judge call while tools are running;
- replay/minimization/proof steps before confirmation.
```

Updated files:

```text
schema_compact_layers.html
ARCHITECTURE_DATA_CONTRACTS.md
DIFY_BACKEND_CONTRACT.md
TOOL_EXECUTION_ARCHITECTURE.md
README_detailed_algorithmic_architecture.md
REFACTOR_ROADMAP.md
TESTING_STRATEGY.md
e2e_run.md
```

Recommended placement in project:

```text
schema_compact_layers.html                  -> docs/schema_compact_layers.html or root if currently there
ARCHITECTURE_DATA_CONTRACTS.md              -> docs/ARCHITECTURE_DATA_CONTRACTS.md
DIFY_BACKEND_CONTRACT.md                    -> docs/DIFY_BACKEND_CONTRACT.md
TOOL_EXECUTION_ARCHITECTURE.md              -> docs/TOOL_EXECUTION_ARCHITECTURE.md
README_detailed_algorithmic_architecture.md -> docs/README_detailed_algorithmic_architecture.md
REFACTOR_ROADMAP.md                         -> docs/REFACTOR_ROADMAP.md
TESTING_STRATEGY.md                         -> docs/TESTING_STRATEGY.md
e2e_run.md                                  -> docs/e2e_run.md or existing location
```
