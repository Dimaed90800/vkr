import json
from urllib.parse import urlparse

try:
    from backend.models.testing import TaskModel
    from backend.services.auth_finding_classifier import finding_type_label
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import TaskModel
    from services.auth_finding_classifier import finding_type_label


class TaskFingerprintService:
    def task_fingerprint(self, task: TaskModel) -> str:
        task_class = str(task.class_name or "").lower()
        payload = {
            "class": task_class,
            "subtype": str(task.subtype or "").lower(),
            "method": str(task.method or "").upper(),
            "endpoint": self._normalize_endpoint(task.endpoint),
            "readiness": str(task.readiness or "").lower(),
            "test_strategy": str(task.test_strategy or "").lower(),
            "strategy_family": str(task.strategy_family or "").lower(),
            "payload_family": str(task.payload_family or "").lower(),
            "resource_family": str(
                task.resource_family or ((task.context_hints or {}).get("resource_family") if isinstance(task.context_hints, dict) else "") or ""
            ).lower(),
            "allowed_tools": sorted(str(item or "").lower() for item in (task.allowed_tools or [])),
        }

        if task_class == "authorization":
            payload["selected_object_id"] = self._normalize_value(task.params.selected_object_id)
            payload["owner_role"] = self._normalize_value(task.auth_context.owner_role)
            payload["other_role"] = self._normalize_value(task.auth_context.other_role)
            payload["object_param_name"] = self._normalize_value(task.params.object_param_name)
        else:
            payload["path_params"] = sorted(self._normalize_value(item) for item in task.params.path_params)
            payload["query_params"] = sorted(self._normalize_value(item) for item in task.params.query_params)
            payload["body_fields"] = sorted(self._normalize_value(item) for item in task.params.body_fields)
            payload["selected_object_id"] = self._normalize_value(task.params.selected_object_id)
            payload["hypothesis"] = self._normalize_value(task.hypothesis)

        return self._serialize(payload)

    def finding_fingerprint(self, task: TaskModel, verdict: str) -> str:
        task_class = str(task.class_name or "").lower()
        vuln_type = self._finding_type(task, verdict)
        endpoint = self._materialized_endpoint(task)
        payload = {
            "vuln_type": vuln_type,
            "subtype": str(task.subtype or "").lower(),
            "hypothesis_family": str(task.hypothesis_family or "").lower(),
            "method": str(task.method or "").upper(),
            "endpoint": endpoint,
        }
        selected_object_id = self._normalize_value(task.params.selected_object_id)
        if selected_object_id:
            payload["selected_object_id"] = selected_object_id
        owner_role = self._normalize_value(task.auth_context.owner_role)
        other_role = self._normalize_value(task.auth_context.other_role)
        if owner_role:
            payload["owner_role"] = owner_role
        if other_role:
            payload["other_role"] = other_role
        return self._serialize(payload)

    def _finding_type(self, task: TaskModel, verdict: str) -> str:
        task_class = str(task.class_name or "").lower()
        if task_class == "authorization":
            return finding_type_label(str(task.subtype or "").lower())
        if task_class == "business_logic":
            return "BUSINESS_LOGIC"
        if task_class == "injection":
            return "INJECTION"
        return str(verdict or "UNKNOWN").upper()

    def _materialized_endpoint(self, task: TaskModel) -> str:
        endpoint = self._normalize_endpoint(task.endpoint)
        selected_object_id = self._normalize_value(task.params.selected_object_id)
        if not selected_object_id:
            return endpoint
        for placeholder in self._extract_placeholders(endpoint):
            endpoint = endpoint.replace("{" + placeholder + "}", selected_object_id)
        return endpoint

    def _extract_placeholders(self, endpoint: str) -> list[str]:
        placeholders: list[str] = []
        current = ""
        in_placeholder = False
        for char in str(endpoint or ""):
            if char == "{":
                current = ""
                in_placeholder = True
            elif char == "}":
                if current:
                    placeholders.append(current)
                in_placeholder = False
            elif in_placeholder:
                current += char
        return placeholders

    def _normalize_endpoint(self, endpoint: str) -> str:
        value = str(endpoint or "").strip()
        if not value:
            return ""
        parsed = urlparse(value)
        path = parsed.path if parsed.scheme or parsed.netloc else value
        normalized = "/" + "/".join(part for part in path.split("/") if part)
        return normalized.lower() if normalized != "/" else normalized

    def _normalize_value(self, value) -> str | None:
        normalized = str(value).strip().lower() if value not in (None, "") else ""
        return normalized or None

    def _serialize(self, payload: dict) -> str:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
