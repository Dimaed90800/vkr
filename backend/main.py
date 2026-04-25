from fastapi import FastAPI

try:
    from backend.api.routes_campaigns import router as campaigns_router
    from backend.api.routes_corpus import router as corpus_router
    from backend.api.routes_graph import router as graph_router
    from backend.api.routes_discovery import router as discovery_router
    from backend.api.routes_planning import router as planning_router
    from backend.api.routes_recon import router as recon_router
    from backend.api.routes_scheduling import router as scheduling_router
    from backend.api.routes_surface_acquisition import router as surface_acquisition_router
    from backend.api.routes_store import router as store_router
    from backend.api.routes_tests import router as tests_router
    from backend.api.routes_tool_wrappers import router as tool_wrappers_router
    from backend.api.routes_traffic_discovery import router as traffic_discovery_router
    from backend.models.common import HealthResponse
    from backend.storage.memory_store import memory_store
    from backend.services.tool_wrappers import ToolWrapperService
except ModuleNotFoundError:  # pragma: no cover
    from api.routes_campaigns import router as campaigns_router
    from api.routes_corpus import router as corpus_router
    from api.routes_graph import router as graph_router
    from api.routes_discovery import router as discovery_router
    from api.routes_planning import router as planning_router
    from api.routes_recon import router as recon_router
    from api.routes_scheduling import router as scheduling_router
    from api.routes_surface_acquisition import router as surface_acquisition_router
    from api.routes_store import router as store_router
    from api.routes_tests import router as tests_router
    from api.routes_tool_wrappers import router as tool_wrappers_router
    from api.routes_traffic_discovery import router as traffic_discovery_router
    from models.common import HealthResponse
    from storage.memory_store import memory_store
    from services.tool_wrappers import ToolWrapperService


app = FastAPI(
    title="Multi-Agent DAST Toolbox MVP",
    version="0.1.0",
    description="Minimal FastAPI toolbox backend for Dify multi-agent REST API DAST workflows.",
)

app.include_router(campaigns_router, prefix="/v1")
app.include_router(corpus_router, prefix="/v1")
app.include_router(graph_router, prefix="/v1")
app.include_router(recon_router, prefix="/v1")
app.include_router(discovery_router, prefix="/v1")
app.include_router(traffic_discovery_router, prefix="/v1")
app.include_router(surface_acquisition_router, prefix="/v1")
app.include_router(planning_router, prefix="/v1")
app.include_router(scheduling_router, prefix="/v1")
app.include_router(tests_router, prefix="/v1")
app.include_router(tool_wrappers_router, prefix="/v1")
app.include_router(store_router, prefix="/v1")


@app.get("/", response_model=HealthResponse)
def root() -> HealthResponse:
    return HealthResponse(status="ok", message="Multi-Agent DAST Toolbox MVP is running.")


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        message="healthy",
        details={
            "evidence_count": len(memory_store.evidence_records),
            "finding_count": len(memory_store.findings),
            "tool_preflight": ToolWrapperService().preflight_summary(),
        },
    )
