import threading
import uuid

try:
    from backend.models.storage import EvidenceRecord, FindingRecord
except ModuleNotFoundError:  # pragma: no cover
    from models.storage import EvidenceRecord, FindingRecord


class MemoryStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.evidence_records: dict[str, dict] = {}
        self.findings: dict[str, dict] = {}

    def store_evidence(self, session_id: int | str | None, evidence: EvidenceRecord) -> str:
        evidence_id = f"ev_{uuid.uuid4().hex[:10]}"
        payload = evidence.model_dump()
        payload["session_id"] = session_id
        with self._lock:
            self.evidence_records[evidence_id] = payload
        return evidence_id

    def store_finding(self, session_id: int | str | None, finding: FindingRecord) -> str:
        finding_id = finding.id or f"finding_{uuid.uuid4().hex[:10]}"
        payload = finding.model_dump()
        payload["id"] = finding_id
        payload["session_id"] = session_id
        with self._lock:
            self.findings[finding_id] = payload
        return finding_id


memory_store = MemoryStore()
