import json
import os
import requests


DIFY_API_URL = os.getenv("DIFY_API_URL", "http://host.docker.internal/v1/workflows/run")
DIFY_API_KEY = os.getenv("DIFY_API_KEY", "")


def _normalize_possible_json_string(value):
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        value = value.strip()
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None

    return None


def _parse_outputs(outputs: dict) -> dict:
    if not isinstance(outputs, dict):
        raise Exception(f"Dify outputs is not an object: {outputs}")

    # 1. Уже нормальный structured output
    if "selected_key" in outputs:
        return {
            "selected_key": outputs["selected_key"],
            "score": outputs.get("score", 0.5),
            "reason": outputs.get("reason", "Dify workflow selection"),
        }

    # 2. Одно из полей содержит JSON-строку
    for key in ("text", "result", "answer", "output"):
        value = outputs.get(key)
        parsed = _normalize_possible_json_string(value)
        if parsed and "selected_key" in parsed:
            return {
                "selected_key": parsed["selected_key"],
                "score": parsed.get("score", 0.5),
                "reason": parsed.get("reason", "Dify workflow selection"),
            }

    raise Exception(f"Could not extract selected_key from Dify workflow outputs: {outputs}")


def call_dify_judge(hypotheses: list, context: dict) -> dict:
    payload = {
        "inputs": {
            "hypotheses": json.dumps(hypotheses, ensure_ascii=False),
            "context": json.dumps(context, ensure_ascii=False),
        },
        "response_mode": "blocking",
        "user": "judge-agent",
    }

    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        DIFY_API_URL,
        json=payload,
        headers=headers,
        timeout=60,
    )

    if response.status_code != 200:
        raise Exception(f"Dify error: {response.status_code} {response.text}")

    raw = response.json()
    data = raw.get("data")
    if not isinstance(data, dict):
        raise Exception(f"Dify workflow response missing data object: {raw}")

    outputs = data.get("outputs", {})
    parsed = _parse_outputs(outputs)

    # Финальная нормализация типов
    selected_key = str(parsed.get("selected_key", "")).strip()
    reason = str(parsed.get("reason", "Dify workflow selection")).strip()

    try:
        score = float(parsed.get("score", 0.5))
    except (TypeError, ValueError):
        score = 0.5

    return {
        "selected_key": selected_key,
        "score": score,
        "reason": reason,
    }