"""Phase 5 — In-memory ArtifactStore.

Stores tool run artifacts in memory with virtual paths.
No real file I/O in Phase 5; file-backed storage is deferred.
"""
from __future__ import annotations

import json
from uuid import uuid4

try:
    from backend.models.tool_run import ToolArtifactRef
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.tool_run import ToolArtifactRef
    from storage.memory_store import memory_store


class ArtifactStore:
    def save_artifact(
        self,
        campaign_id: str,
        tool_run_id: str,
        artifact_type: str,
        content: str | dict,
    ) -> ToolArtifactRef:
        artifact_id = f"art_{uuid4().hex[:16]}"
        serialized = content if isinstance(content, str) else json.dumps(content, default=str)
        path = f"storage/campaigns/{campaign_id}/artifacts/{tool_run_id}/{artifact_type}.json"
        data = {
            "artifact_id": artifact_id,
            "artifact_type": artifact_type,
            "path": path,
            "size_bytes": len(serialized.encode("utf-8")),
            "campaign_id": campaign_id,
            "tool_run_id": tool_run_id,
            "content": serialized,
        }
        memory_store.store_artifact(artifact_id, tool_run_id, data)
        return ToolArtifactRef(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            path=path,
            size_bytes=data["size_bytes"],
        )

    def get_artifact(self, artifact_id: str) -> dict | None:
        return memory_store.get_artifact(artifact_id)

    def list_by_tool_run(self, tool_run_id: str) -> list[ToolArtifactRef]:
        raw = memory_store.list_artifacts_by_run(tool_run_id)
        return [
            ToolArtifactRef(
                artifact_id=item["artifact_id"],
                artifact_type=item.get("artifact_type", ""),
                path=item.get("path", ""),
                size_bytes=item.get("size_bytes", 0),
            )
            for item in raw
        ]
