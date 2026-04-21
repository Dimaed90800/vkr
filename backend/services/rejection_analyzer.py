from collections.abc import Iterable
from typing import Any


GUESSED_OBJECT_IDS = {
    "1",
    "123",
    "test",
    "sample",
    "example",
    "demo",
}

PLACEHOLDER_OBJECT_IDS = {
    "id",
    "{id}",
    "video_id",
    "{video_id}",
    "vehicleid",
    "{vehicleid}",
    "vehicle_id",
    "{vehicle_id}",
    "orderid",
    "{orderid}",
    "order_id",
    "{order_id}",
    "postid",
    "{postid}",
    "post_id",
    "{post_id}",
    "reportid",
    "{reportid}",
    "report_id",
    "{report_id}",
    "userid",
    "{userid}",
    "user_id",
    "{user_id}",
}

INVALID_OBJECT_MARKERS = (
    "failed to convert",
    "invalid",
    "bad request",
)

OBJECT_PARAM_MARKERS = (
    "carid",
    "vehicleid",
    "orderid",
    "accountid",
    "userid",
    "id",
)


class RejectionAnalyzer:
    def is_guessed_object_id(self, value: str | int | None) -> bool:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return True
        return normalized in GUESSED_OBJECT_IDS or normalized in PLACEHOLDER_OBJECT_IDS

    def classify_auth_failure(
        self,
        *,
        owner_status: int | None,
        other_status: int | None,
        owner_body: str,
        other_body: str,
        similarity: float,
    ) -> dict[str, Any]:
        owner_text = (owner_body or "").lower()
        other_text = (other_body or "").lower()
        combined = f"{owner_text} {other_text}"

        if (
            owner_status == 400
            and other_status == 400
            and similarity >= 0.99
            and any(marker in combined for marker in INVALID_OBJECT_MARKERS)
            and any(marker in combined for marker in OBJECT_PARAM_MARKERS)
        ):
            return {
                "failure_type": "invalid_object_id",
                "should_retry": True,
                "requires_new_object_id": True,
                "reason": "Both roles failed on the same invalid object ID conversion or validation error.",
            }

        if owner_status == 400 and other_status == 400 and similarity >= 0.99:
            return {
                "failure_type": "validation_failure",
                "should_retry": False,
                "requires_new_object_id": False,
                "reason": "Both roles received the same validation error, which is not useful authorization evidence.",
            }

        return {
            "failure_type": "unknown",
            "should_retry": False,
            "requires_new_object_id": False,
            "reason": "",
        }

    def controlled_replan(
        self,
        *,
        retry_count: int,
        current_object_id: str | int | None,
        candidate_ids: Iterable[str | int] | None,
        failure_classification: dict[str, Any],
    ) -> dict[str, Any]:
        normalized_candidates = []
        seen: set[str] = set()
        current_normalized = str(current_object_id or "").strip()

        for candidate in candidate_ids or []:
            value = str(candidate or "").strip()
            if not value or value == current_normalized or self.is_guessed_object_id(value):
                continue
            if value in seen:
                continue
            seen.add(value)
            normalized_candidates.append(value)

        if failure_classification.get("failure_type") != "invalid_object_id":
            return {
                "decision": "stop",
                "reason": "replan_not_applicable",
                "retry_count": retry_count,
                "candidate_pool": normalized_candidates,
            }

        if retry_count >= 1:
            return {
                "decision": "stop",
                "reason": "retry_limit_reached",
                "retry_count": retry_count,
                "candidate_pool": normalized_candidates,
            }

        if normalized_candidates:
            return {
                "decision": "retry_with_updated_inputs",
                "reason": "better_object_id_available",
                "retry_count": retry_count + 1,
                "selected_object_id": normalized_candidates[0],
                "candidate_pool": normalized_candidates,
            }

        return {
            "decision": "stop",
            "reason": "no_valid_object_id_available",
            "retry_count": retry_count,
            "candidate_pool": normalized_candidates,
        }
