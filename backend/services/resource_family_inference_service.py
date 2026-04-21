from __future__ import annotations

from collections.abc import Iterable
import re


class ResourceFamilyInferenceService:
    FAMILY_KEYWORDS = {
        "auth_identity": ("auth", "login", "signin", "signup", "register", "identity", "password", "otp", "token"),
        "vehicle": ("vehicle", "vehicles", "vin", "car", "location"),
        "order": ("order", "orders", "checkout", "return_order", "return", "cart"),
        "post": ("post", "posts", "comment", "community"),
        "video": ("video", "videos", "profilevideo", "conversion"),
        "report": ("report", "reports", "mechanic_report", "service_request", "service_requests"),
        "mechanic": ("mechanic", "workshop", "merchant", "receive_report"),
        "coupon": ("coupon", "redeem", "discount"),
        "product": ("product", "products", "shop", "inventory"),
        "user_profile": ("user", "users", "profile", "dashboard", "account", "accounts", "customer", "customers"),
    }

    def infer(
        self,
        *,
        path: str,
        method: str = "GET",
        tags: Iterable[str] | None = None,
        operation_id: str = "",
        summary: str = "",
        body_fields: Iterable[str] | None = None,
        query_params: Iterable[str] | None = None,
        response_fields: Iterable[str] | None = None,
    ) -> str:
        normalized_path = str(path or "").lower()
        path_segments = [segment for segment in re.split(r"[^a-z0-9_]+", normalized_path) if segment]
        tag_tokens = [str(item or "").lower() for item in (tags or [])]
        body_tokens = [str(item or "").lower() for item in (body_fields or [])]
        query_tokens = [str(item or "").lower() for item in (query_params or [])]
        response_tokens = [str(item or "").lower() for item in (response_fields or [])]
        operation_tokens = re.split(r"[^a-z0-9_]+", f"{operation_id} {summary}".lower())
        haystack = " ".join(
            [
                normalized_path,
                str(method or ""),
                str(operation_id or ""),
                str(summary or ""),
                *tag_tokens,
                *body_tokens,
                *query_tokens,
                *response_tokens,
            ]
        ).lower()

        if not haystack.strip():
            return "generic_resource"

        scored: list[tuple[int, str]] = []
        for family, keywords in self.FAMILY_KEYWORDS.items():
            score = 0
            for keyword in keywords:
                normalized_keyword = str(keyword or "").lower()
                singular = normalized_keyword[:-1] if normalized_keyword.endswith("s") else normalized_keyword
                variants = {normalized_keyword, singular}
                if any(token in path_segments for token in variants):
                    score += 5
                elif f"/{normalized_keyword}/" in normalized_path or normalized_path.endswith(f"/{normalized_keyword}"):
                    score += 4
                elif any(normalized_keyword in token for token in path_segments):
                    score += 3
                if any(token == normalized_keyword for token in tag_tokens):
                    score += 2
                if any(normalized_keyword in token for token in operation_tokens):
                    score += 2
                if any(token == normalized_keyword for token in body_tokens):
                    score += 1
                if any(token == normalized_keyword for token in response_tokens):
                    score += 2
                if normalized_keyword in haystack:
                    score += 1
            if family == "order" and any(token in path_segments for token in ("order", "orders", "return_order")):
                score += 4
            if family == "video" and any(token in path_segments for token in ("video", "videos")):
                score += 4
            if family == "post" and any(token in path_segments for token in ("post", "posts", "comment", "community")):
                score += 4
            if family == "report" and any(token in path_segments for token in ("report", "reports", "mechanic_report", "service_request", "service_requests")):
                score += 4
            if score > 0:
                scored.append((score, family))

        if not scored:
            return "generic_resource"
        scored.sort(reverse=True)
        return scored[0][1]
