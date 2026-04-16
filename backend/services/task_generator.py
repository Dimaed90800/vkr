try:
    from backend.models.api_surface import NormalizedApiSurface
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface


class TaskGenerator:
    CONTROLLED_AUTH_OBJECTS = {
        "/identity/api/v2/vehicle/{id}/location": {
            "object_param_name": "carId",
            "object_id_candidates": ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
        }
    }

    TOOL_BY_CLASS = {
        "authorization": "auth_test_access",
        "injection": "injection_test",
        "business_logic": "logic_test",
    }

    def generate(self, surface: NormalizedApiSurface, roles: list[dict] | None = None) -> list[dict]:
        role_names = self._role_names(roles or [])
        owner_role = role_names[0]
        other_role = role_names[1]

        tasks: list[dict] = []
        counters = {
            "authorization": 0,
            "injection": 0,
            "business_logic": 0,
        }

        for endpoint in surface.endpoints:
            for candidate_class in endpoint.candidate_classes:
                counters[candidate_class] += 1
                task_id = f"task_{candidate_class}_{counters[candidate_class]:03d}"
                task = {
                    "id": task_id,
                    "class": candidate_class,
                    "subtype": self._subtype(candidate_class, endpoint),
                    "endpoint": endpoint.path,
                    "method": endpoint.method,
                    "params": {
                        "path_params": endpoint.path_params,
                        "query_params": endpoint.query_params,
                        "body_fields": endpoint.body_fields,
                        "object_id_candidates": self._object_id_candidates(endpoint),
                        "selected_object_id": self._selected_object_id(endpoint),
                        "requires_object_id_enrichment": self._requires_object_id_enrichment(candidate_class, endpoint),
                        "object_param_name": self._object_param_name(endpoint) or None,
                    },
                    "auth_context": {
                        "owner_role": owner_role,
                        "other_role": other_role,
                        "token_strategy": "cross_role_replay",
                    },
                    "hypothesis": self._hypothesis(candidate_class, endpoint),
                    "priority": self._priority(candidate_class, endpoint),
                    "retry_count": 0,
                    "rework_hint": None,
                    "status": "pending",
                    "allowed_tools": [self.TOOL_BY_CLASS[candidate_class]],
                }
                tasks.append(task)

        return sorted(tasks, key=lambda item: int(item.get("priority", 0) or 0), reverse=True)

    def _priority(self, candidate_class: str, endpoint) -> int:
        score = getattr(endpoint.candidate_scores, candidate_class)
        priority = max(1, min(100, int(round(score * 100))))
        if candidate_class == "authorization" and self._requires_object_id_enrichment(candidate_class, endpoint):
            return max(1, priority - 40)
        return priority

    def _subtype(self, candidate_class: str, endpoint) -> str:
        if candidate_class == "authorization":
            return "bola" if endpoint.resource_signals.has_object_id else "access_control"
        if candidate_class == "injection":
            return "input_injection"
        return "workflow_bypass"

    def _hypothesis(self, candidate_class: str, endpoint) -> str:
        if candidate_class == "authorization":
            if self._requires_object_id_enrichment(candidate_class, endpoint):
                return "Authorization testing requires a valid object ID before cross-role replay can be assessed."
            return "Cross-role access to the same object may be possible."
        if candidate_class == "injection":
            return "User-controlled input may reach an unsafe sink without proper validation."
        return "The endpoint may allow an unintended state transition or workflow bypass."

    def _role_names(self, roles: list[dict]) -> tuple[str, str]:
        names = []
        for item in roles:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or item.get("role") or "").strip()
            if name:
                names.append(name)
        if len(names) >= 2:
            return names[0], names[1]
        if len(names) == 1:
            return names[0], "user_b"
        return "user_a", "user_b"

    def _requires_object_id_enrichment(self, candidate_class: str, endpoint) -> bool:
        if candidate_class != "authorization":
            return False
        if not endpoint.resource_signals.has_object_id:
            return False
        return self._selected_object_id(endpoint) is None

    def _selected_object_id(self, endpoint) -> str | None:
        candidates = self._object_id_candidates(endpoint)
        return candidates[0] if candidates else None

    def _object_id_candidates(self, endpoint) -> list[str]:
        candidates = [str(item).strip() for item in (endpoint.object_id_candidates or []) if str(item).strip()]
        controlled = self.CONTROLLED_AUTH_OBJECTS.get(endpoint.path, {})
        for item in controlled.get("object_id_candidates", []):
            value = str(item).strip()
            if value:
                candidates.append(value)
        return [item for item in candidates if not self._is_guessed_object_id(item)]

    def _object_param_name(self, endpoint) -> str:
        controlled = self.CONTROLLED_AUTH_OBJECTS.get(endpoint.path, {})
        return str(controlled.get("object_param_name") or endpoint.object_param_name or "")

    def _is_guessed_object_id(self, value: str) -> bool:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return True
        if normalized in {"1", "123", "test", "sample", "example", "demo", "foo", "bar"}:
            return True
        return False
