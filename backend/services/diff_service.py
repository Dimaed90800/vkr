import json
from difflib import SequenceMatcher
from typing import Any


class DiffService:
    def similarity(self, left_body: str, right_body: str) -> float:
        left_json = self._try_json(left_body)
        right_json = self._try_json(right_body)

        if left_json is not None and right_json is not None:
            left_norm = json.dumps(left_json, sort_keys=True, ensure_ascii=False)
            right_norm = json.dumps(right_json, sort_keys=True, ensure_ascii=False)
            return round(SequenceMatcher(a=left_norm, b=right_norm).ratio(), 4)

        if not left_body and not right_body:
            return 1.0

        return round(SequenceMatcher(a=left_body or "", b=right_body or "").ratio(), 4)

    def shared_json_keys(self, left_body: str, right_body: str) -> list[str]:
        left_json = self._try_json(left_body)
        right_json = self._try_json(right_body)
        if not isinstance(left_json, dict) or not isinstance(right_json, dict):
            return []
        return sorted(set(left_json.keys()) & set(right_json.keys()))

    def _try_json(self, body: str) -> Any | None:
        try:
            return json.loads(body)
        except Exception:
            return None
