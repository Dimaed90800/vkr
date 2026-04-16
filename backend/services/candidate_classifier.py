try:
    from backend.models.api_surface import CandidateScores, NormalizedEndpoint
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import CandidateScores, NormalizedEndpoint


OBJECT_ID_KEYWORDS = {
    "id",
    "userid",
    "user_id",
    "accountid",
    "account_id",
    "orderid",
    "order_id",
    "vehicleid",
    "vehicle_id",
    "carid",
    "car_id",
    "paymentid",
    "payment_id",
    "reportid",
    "report_id",
}

ROLE_FIELD_KEYWORDS = {
    "role",
    "roles",
    "owner",
    "ownerid",
    "owner_id",
    "userid",
    "user_id",
    "accountid",
    "account_id",
}

SENSITIVE_KEYWORDS = {
    "admin",
    "user",
    "account",
    "profile",
    "vehicle",
    "location",
    "payment",
    "invoice",
    "order",
    "balance",
    "report",
    "email",
    "phone",
}

INJECTION_INPUT_KEYWORDS = {
    "q",
    "query",
    "search",
    "filter",
    "sort",
    "name",
    "description",
    "comment",
    "message",
    "text",
    "keyword",
}

BUSINESS_FLOW_KEYWORDS = {
    "workflow",
    "approve",
    "approval",
    "transfer",
    "order",
    "payment",
    "checkout",
    "purchase",
    "credit",
    "refund",
    "balance",
    "limit",
    "price",
    "status",
}


class CandidateClassifier:
    def classify(self, endpoint: NormalizedEndpoint) -> NormalizedEndpoint:
        auth_score = self._authorization_score(endpoint)
        injection_score = self._injection_score(endpoint)
        business_score = self._business_logic_score(endpoint)

        endpoint.candidate_scores = CandidateScores(
            authorization=round(min(auth_score, 1.0), 2),
            injection=round(min(injection_score, 1.0), 2),
            business_logic=round(min(business_score, 1.0), 2),
        )
        endpoint.candidate_classes = self._candidate_classes(endpoint.candidate_scores)
        return endpoint

    def _authorization_score(self, endpoint: NormalizedEndpoint) -> float:
        score = 0.0
        lowered_path = endpoint.path.lower()
        all_fields = self._all_field_names(endpoint)

        if endpoint.resource_signals.has_object_id:
            score += 0.35
        if endpoint.auth_required:
            score += 0.2
        if endpoint.method.upper() in {"GET", "PUT", "PATCH", "DELETE"}:
            score += 0.15
        if any(token in lowered_path for token in ("user", "account", "vehicle", "profile", "order")):
            score += 0.2
        if endpoint.resource_signals.has_sensitive_keywords:
            score += 0.1
        if any(self._normalize_name(name) in ROLE_FIELD_KEYWORDS for name in all_fields):
            score += 0.05
        return score

    def _injection_score(self, endpoint: NormalizedEndpoint) -> float:
        score = 0.0
        query_fields = [self._normalize_name(item) for item in endpoint.query_params]
        body_fields = [self._normalize_name(item) for item in endpoint.body_fields]
        all_fields = query_fields + body_fields

        if query_fields:
            score += 0.15
        if any(name in INJECTION_INPUT_KEYWORDS for name in query_fields):
            score += 0.3
        if body_fields:
            score += 0.2
        if any(name in INJECTION_INPUT_KEYWORDS for name in all_fields):
            score += 0.25
        if endpoint.method.upper() in {"POST", "PUT", "PATCH"}:
            score += 0.1
        return score

    def _business_logic_score(self, endpoint: NormalizedEndpoint) -> float:
        score = 0.0
        lowered_path = endpoint.path.lower()
        all_fields = [self._normalize_name(item) for item in self._all_field_names(endpoint)]

        if endpoint.method.upper() in {"POST", "PUT", "PATCH"}:
            score += 0.25
        if any(name in BUSINESS_FLOW_KEYWORDS or name in ROLE_FIELD_KEYWORDS for name in all_fields):
            score += 0.35
        if any(keyword in lowered_path for keyword in BUSINESS_FLOW_KEYWORDS):
            score += 0.3
        if endpoint.auth_required:
            score += 0.1
        return score

    def _candidate_classes(self, scores: CandidateScores) -> list[str]:
        classes: list[str] = []
        if scores.authorization >= 0.55:
            classes.append("authorization")
        if scores.injection >= 0.45:
            classes.append("injection")
        if scores.business_logic >= 0.5:
            classes.append("business_logic")
        if not classes:
            best = max(
                [
                    ("authorization", scores.authorization),
                    ("injection", scores.injection),
                    ("business_logic", scores.business_logic),
                ],
                key=lambda item: item[1],
            )
            if best[1] > 0:
                classes.append(best[0])
        return classes

    def _all_field_names(self, endpoint: NormalizedEndpoint) -> list[str]:
        return [*endpoint.path_params, *endpoint.query_params, *endpoint.body_fields]

    def _normalize_name(self, value: str) -> str:
        return str(value or "").strip().lower().replace("-", "").replace("_", "")
