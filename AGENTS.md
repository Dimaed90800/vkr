# AGENTS.md

## Project
Adaptive REST API pentest platform for a diploma project.

## Goal
Develop and compare two strategy arbitration modes:
- rule_based
- dify

Main practical goals:
- detect possible BOLA
- extend to BOPLA / excessive data exposure
- run experiments
- compare results across judge modes

## Stack
- FastAPI backend
- PostgreSQL
- Docker / docker compose
- OWASP ZAP
- Dify
- Target app: OWASP crAPI

## Important conventions
- Keep business logic in services whenever possible
- Routers should stay thin
- Do not remove working BOLA pipeline
- Prefer incremental changes
- Preserve experiment endpoints and metrics
- Keep fallback logic for Dify judge
- Use TestSession model name, not Session
- Use db.py / SessionLocal, not database.py

## Current priorities
1. Stabilize experiment runner
2. Add BOPLA support
3. Improve reporting/export
4. Add n8n integration later as orchestration layer above backend

## Safety
- Do not hardcode secrets
- Use .env for keys
- Do not remove recovery/fallback behavior