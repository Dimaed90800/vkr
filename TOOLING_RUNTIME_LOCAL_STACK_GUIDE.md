# Local Runtime Stack Guide

This project now treats the local runtime stack as:
- live: ZAP, Schemathesis, RESTler compile/fuzz, CATS blackbox, ASTF basic scan, Playwright runner, mitmproxy, nuclei/httpx/ffuf
- optional: Akto (requires dashboard URL, API key, and collection context)

## Build and start

```bash
docker compose build toolbox
docker compose up -d
```

## Check tool health

```bash
curl http://localhost:8000/v1/tools/preflight | jq
curl http://localhost:8000/v1/tools/capabilities | jq
curl http://localhost:8000/health | jq
```

Expected states after a successful build:
- `schemathesis_*`: `available`
- `restler_*`: `available`
- `cats_fuzz_test`: `available`
- `astf_top10_suite`: `available`
- `akto_*`: `planner_only` or `available` only if Akto env is set

## Notes

### RESTler
This image copies the official Microsoft RESTler runtime from `mcr.microsoft.com/restlerfuzzer/restler:v8.5.0` and exposes it as `/usr/local/bin/restler`.
The adapter runs:
- `restler compile --api_spec <spec>`
- `restler fuzz-lean --grammar_file ... --dictionary_file ... --settings ...`

### CATS
CATS is built from source in Docker and exposed as `/usr/local/bin/cats`.
The adapter runs CATS in blackbox mode against the target URL:
- `cats -c openapi.json -s http://target -b`

### ASTF
ASTF is built from source in Docker and exposed as `/usr/local/bin/astf`.
The adapter runs the documented basic scan form:
- `astf scan --target http://target --auth-header "Authorization: Bearer ..."`

### Akto
Akto is not in the critical path. To make it fully live, set:
- `AKTO_BIN`
- `AKTO_DASHBOARD_URL`
- `AKTO_API_KEY`
- `AKTO_API_COLLECTION_NAME` or `AKTO_API_COLLECTION_ID`

Without those variables Akto remains optional and should not be preferred by the workflow.
