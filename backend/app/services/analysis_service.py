import json


def _try_parse_json(text: str):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _json_keys(value, prefix=""):
    keys = set()

    if isinstance(value, dict):
        for k, v in value.items():
            current = f"{prefix}.{k}" if prefix else k
            keys.add(current)
            keys.update(_json_keys(v, current))
    elif isinstance(value, list):
        for item in value[:5]:
            keys.update(_json_keys(item, prefix))

    return keys


def _extract_top_id(value):
    if isinstance(value, dict):
        for key in ("id", "vehicleId", "orderId", "video_id", "videoId"):
            if key in value:
                return value.get(key)
    return None


def compare_observation_bodies(body_a: str, body_b: str) -> dict:
    json_a = _try_parse_json(body_a)
    json_b = _try_parse_json(body_b)

    result = {
        "body_a_is_json": json_a is not None,
        "body_b_is_json": json_b is not None,
        "same_raw_body": body_a == body_b,
        "same_json_structure": False,
        "same_top_level_keys": False,
        "keys_only_in_a": [],
        "keys_only_in_b": [],
        "length_a": len(body_a or ""),
        "length_b": len(body_b or ""),
        "length_delta": abs(len(body_a or "") - len(body_b or "")),
        "top_id_a": _extract_top_id(json_a),
        "top_id_b": _extract_top_id(json_b),
        "signals": []
    }

    if json_a is not None and json_b is not None:
        keys_a = sorted(_json_keys(json_a))
        keys_b = sorted(_json_keys(json_b))

        result["same_json_structure"] = set(keys_a) == set(keys_b)

        top_a = sorted(json_a.keys()) if isinstance(json_a, dict) else []
        top_b = sorted(json_b.keys()) if isinstance(json_b, dict) else []
        result["same_top_level_keys"] = set(top_a) == set(top_b)

        result["keys_only_in_a"] = sorted(list(set(keys_a) - set(keys_b)))
        result["keys_only_in_b"] = sorted(list(set(keys_b) - set(keys_a)))

        if not result["same_json_structure"]:
            result["signals"].append("json_structure_diff_detected")

        if not result["same_top_level_keys"]:
            result["signals"].append("top_level_key_diff_detected")

        if result["top_id_a"] is not None and result["top_id_b"] is not None and result["top_id_a"] == result["top_id_b"]:
            result["signals"].append("same_top_object_id_detected")

    if not result["same_raw_body"]:
        result["signals"].append("body_content_diff_detected")

    if result["length_delta"] > 20:
        result["signals"].append("response_length_diff_detected")

    return result


def compare_observations(obs_a, obs_b) -> dict:
    comparison = {
        "observation_a_id": obs_a.id,
        "observation_b_id": obs_b.id,
        "status_code_a": obs_a.status_code,
        "status_code_b": obs_b.status_code,
        "same_status_code": obs_a.status_code == obs_b.status_code,
        "same_endpoint": obs_a.endpoint == obs_b.endpoint,
        "same_method": obs_a.method == obs_b.method,
        "role_a": obs_a.role_name,
        "role_b": obs_b.role_name,
        "signals": [],
        "body_comparison": compare_observation_bodies(
            obs_a.body_preview or "",
            obs_b.body_preview or ""
        )
    }

    if obs_a.status_code != obs_b.status_code:
        comparison["signals"].append("status_code_diff_detected")

    comparison["signals"].extend(comparison["body_comparison"]["signals"])

    unique_signals = []
    for s in comparison["signals"]:
        if s not in unique_signals:
            unique_signals.append(s)
    comparison["signals"] = unique_signals

    if (
        comparison["same_status_code"]
        and "body_content_diff_detected" in comparison["signals"]
        and comparison["role_a"] != comparison["role_b"]
    ):
        comparison["inference"] = "possible_role_based_response_difference"
    elif (
        not comparison["same_status_code"]
        and comparison["role_a"] != comparison["role_b"]
    ):
        comparison["inference"] = "possible_access_control_difference"
    elif (
        comparison["same_status_code"]
        and "same_top_object_id_detected" in comparison["signals"]
        and comparison["role_a"] != comparison["role_b"]
    ):
        comparison["inference"] = "possible_shared_object_access"
    else:
        comparison["inference"] = "no_clear_role_based_issue"

    return comparison