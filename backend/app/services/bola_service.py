import json


def _try_parse_json(text: str):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _extract_candidate_object_id(body_text: str):
    data = _try_parse_json(body_text)
    if not isinstance(data, dict):
        return None

    for key in ("id", "vehicleId", "orderId", "video_id", "videoId"):
        if key in data:
            return data.get(key)

    return None


def infer_bola_from_observations(obs_a, obs_b) -> dict:
    """
    obs_a: доступ владельца/первой роли
    obs_b: доступ второй роли к тому же объекту
    """

    result = {
        "observation_owner_id": obs_a.id,
        "observation_other_id": obs_b.id,
        "owner_role": obs_a.role_name,
        "other_role": obs_b.role_name,
        "endpoint_owner": obs_a.endpoint,
        "endpoint_other": obs_b.endpoint,
        "status_owner": obs_a.status_code,
        "status_other": obs_b.status_code,
        "signals": [],
        "inference": "inconclusive"
    }

    same_endpoint = obs_a.endpoint == obs_b.endpoint
    same_method = obs_a.method == obs_b.method

    if same_endpoint:
        result["signals"].append("same_endpoint_targeted")
    if same_method:
        result["signals"].append("same_method_used")

    owner_json = _try_parse_json(obs_a.body_preview or "")
    other_json = _try_parse_json(obs_b.body_preview or "")

    owner_obj_id = _extract_candidate_object_id(obs_a.body_preview or "")
    other_obj_id = _extract_candidate_object_id(obs_b.body_preview or "")

    result["owner_object_id"] = owner_obj_id
    result["other_object_id"] = other_obj_id

    if obs_a.status_code == 200:
        result["signals"].append("owner_access_ok")

    if obs_b.status_code in (401, 403):
        result["signals"].append("other_access_denied")

    if obs_b.status_code == 404:
        result["signals"].append("other_object_not_found_or_hidden")

    if obs_b.status_code == 200:
        result["signals"].append("other_access_ok")

    if owner_obj_id is not None and other_obj_id is not None and owner_obj_id == other_obj_id:
        result["signals"].append("same_object_id_in_both_responses")

    if owner_json is not None and other_json is not None and owner_json == other_json:
        result["signals"].append("identical_json_response")

    if (
        same_endpoint
        and same_method
        and obs_a.status_code == 200
        and obs_b.status_code == 200
        and (
            "same_object_id_in_both_responses" in result["signals"]
            or "identical_json_response" in result["signals"]
        )
        and obs_a.role_name != obs_b.role_name
    ):
        result["inference"] = "possible_bola"
    elif (
        same_endpoint
        and same_method
        and obs_a.status_code == 200
        and obs_b.status_code in (401, 403)
    ):
        result["inference"] = "access_denied_expected"
    elif (
        same_endpoint
        and same_method
        and obs_a.status_code == 200
        and obs_b.status_code == 404
    ):
        result["inference"] = "object_hidden_or_not_found_for_other_role"
    else:
        result["inference"] = "different_object_or_safe_response"

    return result