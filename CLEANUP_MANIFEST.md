# CLEANUP_MANIFEST.md

This archive was created as a conservative cleaned copy of the project.

## Removed categories

- macOS metadata: `__MACOSX/`, `.DS_Store`
- local IDE/cache artifacts: `.idea/`, `.pytest_cache/`, `.hypothesis/`, `__pycache__/`, `*.pyc`
- local run logs: `logs/`
- committed secret file: `.env` replaced by `.env.example`
- temporary/diagnostic root markdown files superseded by `CLAUDE.md` and `docs/*`
- unused sample `examples/` directory
- temporary script/file: `tmp_auth_check.py`, `1`

## Kept categories

- `backend/`
- `tests/`
- `scripts/` without bytecode caches
- `dify/`
- `docker-compose.yml`
- `demo_target/`
- `zap/`
- `sql/`
- `README.md`
- `.gitignore`

## Added architecture/refactor docs

- `CLAUDE.md`
- `CLAUDE_REFACTOR_PROMPT.md`
- `docs/BACKEND_CURRENT_STATE.md`
- `docs/REFACTOR_ROADMAP.md`
- `docs/ARCHITECTURE_DATA_CONTRACTS.md`
- `docs/DIFY_BACKEND_CONTRACT.md`
- `docs/TESTING_STRATEGY.md`
- `docs/README_detailed_algorithmic_architecture.md`
- `docs/schema_compact_layers.html`

## Security note

The original archive contained `.env` with API keys. Rotate those keys if they were real.
