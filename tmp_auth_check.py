import json

import requests


BASE = "http://localhost:8000"


def post(path, payload):
    response = requests.post(f"{BASE}{path}", json=payload, timeout=120)
    return response.status_code, response.text


def post_json(path, payload):
    response = requests.post(f"{BASE}{path}", json=payload, timeout=120)
    response.raise_for_status()
    return response.json()


session = post_json(
    "/session/create",
    {
        "target_name": "crapi",
        "target_url": "http://host.docker.internal:8888",
        "max_rounds": 8,
        "allowed_test_classes": ["auth"],
    },
)
session_id = session["id"]

for role_name in ["user_a", "user_b"]:
    post_json("/roles/create", {"session_id": session_id, "role_name": role_name})
    post_json("/roles/register", {"session_id": session_id, "role_name": role_name})
    post_json("/roles/login", {"session_id": session_id, "role_name": role_name})

post_json(
    "/observations/probe",
    {
        "session_id": session_id,
        "role_name": "user_a",
        "endpoint": "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
        "method": "GET",
        "use_role_token": True,
    },
)

steps = []
for _ in range(8):
    status_code, text = post("/campaign/step", {"session_id": session_id, "judge_mode": "unified"})
    if status_code != 200:
        steps.append({"status_code": status_code, "error": text[:1000]})
        break
    step = json.loads(text)
    steps.append(
        {
            "status_code": status_code,
            "selected_hypothesis_type": step.get("selected_hypothesis", {}).get("type"),
            "selected_agent": step.get("selected_hypothesis", {}).get("agent_name"),
            "selected_endpoint": step.get("selected_hypothesis", {}).get("target_endpoint"),
            "selected_logical_agent": step.get("agent_orchestration", {}).get("selected_logical_agent"),
            "generated_finding_type": step.get("execution_result", {}).get("generated_finding_type"),
            "generated_finding_status": step.get("execution_result", {}).get("generated_finding_status"),
            "action_executed": step.get("execution_result", {}).get("action_executed"),
            "execution_status_code": step.get("execution_result", {}).get("status_code"),
        }
    )
    if step.get("status") == "stopped":
        break

report = requests.get(f"{BASE}/report/session/{session_id}", timeout=120).json()

print(
    json.dumps(
        {
            "session_id": session_id,
            "steps": steps,
            "summary": report.get("summary"),
            "key_conclusion": report.get("key_conclusion"),
            "findings": report.get("findings", []),
            "agent_orchestration": report.get("agent_orchestration"),
        },
        ensure_ascii=False,
    )
)
