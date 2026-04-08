from __future__ import annotations

from .judge_service import calculate_dynamic_priority


ATTACK_HYPOTHESIS_TYPES = {"bola_probe", "verify_bola", "bopla_probe", "verify_bopla"}
SUPPORT_HYPOTHESIS_TYPES = {"compare_roles", "authenticated_probe", "discovery"}

DEFAULT_UNIFIED_WEIGHTS = {
    "rule_weight": 0.65,
    "dify_weight": 0.35,
    "repeat_penalty_per_repeat": 0.04,
    "repeat_penalty_cap": 0.18,
    "late_round_bonus": 0.18,
    "support_chain_penalty": 0.12,
    "support_chain_bonus": 0.18,
}


def safe_dify_score(value) -> float:
    try:
        raw_score = float(value)
    except (TypeError, ValueError):
        raw_score = 0.5
    if raw_score == 0:
        return 0.5
    return raw_score


def normalize_key(value) -> str:
    return str(value or "").strip().lower()


def _hypothesis_type(h) -> str:
    return str(getattr(h, "hypothesis_type", "") or "")


def _is_attack_hypothesis(h) -> bool:
    return _hypothesis_type(h) in ATTACK_HYPOTHESIS_TYPES


def _is_support_hypothesis(h) -> bool:
    return _hypothesis_type(h) in SUPPORT_HYPOTHESIS_TYPES


def _count_recent_key_repeats(recent_selected_keys, selected_key: str) -> int:
    key_norm = normalize_key(selected_key)
    if not key_norm:
        return 0
    return sum(1 for item in recent_selected_keys or [] if normalize_key(item) == key_norm)


def _count_recent_type_repeats(recent_selected_hypothesis_types, hypothesis_type: str) -> int:
    type_norm = normalize_key(hypothesis_type)
    if not type_norm:
        return 0
    return sum(1 for item in recent_selected_hypothesis_types or [] if normalize_key(item) == type_norm)


def _count_recent_support_actions(recent_selected_hypothesis_types, window_size: int = 5) -> int:
    recent_items = list(recent_selected_hypothesis_types or [])[-window_size:]
    return sum(1 for item in recent_items if normalize_key(item) in SUPPORT_HYPOTHESIS_TYPES)


def _should_accept_dify_nomination(
    top_rule,
    top_rule_score,
    selected,
    selected_rule_score,
    dify_score,
    blended_score,
    current_round,
    recent_support_count,
):
    if getattr(selected, "id", None) == getattr(top_rule, "id", None):
        return True

    if blended_score + 0.02 >= top_rule_score:
        return True

    # Let unified trust a strong Dify attack nomination over a support/analysis action
    # when the candidate still has solid local priority and Dify confidence is high.
    if (
        _is_attack_hypothesis(selected)
        and _is_support_hypothesis(top_rule)
        and dify_score >= 0.9
        and selected_rule_score >= 0.72
        and blended_score + 0.12 >= top_rule_score
    ):
        return True

    # Verification candidates deserve a slight edge because they reduce uncertainty
    # and typically cost less than opening another exploratory branch.
    if (
        _hypothesis_type(selected) in {"verify_bola", "verify_bopla"}
        and dify_score >= 0.9
        and selected_rule_score >= 0.85
        and blended_score + 0.08 >= top_rule_score
    ):
        return True

    # In late rounds, prefer taking one more strong security action over repeating
    # support work if Dify is confident and the local score is still plausible.
    if (
        current_round >= 11
        and _is_attack_hypothesis(selected)
        and _is_support_hypothesis(top_rule)
        and dify_score >= 0.95
        and selected_rule_score >= 0.45
        and blended_score + 0.08 >= top_rule_score
    ):
        return True

    if (
        current_round >= 14
        and recent_support_count >= 3
        and _is_attack_hypothesis(selected)
        and _is_support_hypothesis(top_rule)
        and dify_score >= 0.95
        and selected_rule_score >= 0.5
        and blended_score + 0.04 >= top_rule_score
    ):
        return True

    return False


def resolve_dify_candidate(saved_candidates, hypotheses_json, selected_key, reason_text, recent_observations=None):
    recent_observations = recent_observations or []
    key_norm = normalize_key(selected_key)
    reason_text = str(reason_text or "").lower()

    for h, serialized in zip(saved_candidates, hypotheses_json):
        if normalize_key(serialized["candidate_key"]) == key_norm:
            return h, "direct_match"

    if key_norm:
        type_matches = [
            h for h, s in zip(saved_candidates, hypotheses_json)
            if normalize_key(s["type"]) == key_norm
        ]
        if type_matches:
            ranked = [(h, calculate_dynamic_priority(h, recent_observations=recent_observations)) for h in type_matches]
            ranked.sort(key=lambda x: x[1], reverse=True)
            return ranked[0][0], "type_recovery"

        known_type_prefixes = [
            "bootstrap_roles",
            "discovery",
            "register_role",
            "login_role",
            "authenticated_probe",
            "anonymous_probe",
            "tokenless_replay_probe",
            "auth_boundary_probe",
            "compare_roles",
            "bola_probe",
            "verify_bola",
            "bopla_probe",
            "verify_bopla",
        ]
        for prefix in known_type_prefixes:
            if key_norm.startswith(prefix):
                type_matches = [
                    h for h, s in zip(saved_candidates, hypotheses_json)
                    if normalize_key(s["type"]) == prefix
                ]
                if type_matches:
                    ranked = [(h, calculate_dynamic_priority(h, recent_observations=recent_observations)) for h in type_matches]
                    ranked.sort(key=lambda x: x[1], reverse=True)
                    return ranked[0][0], "type_recovery"

    semantic_recoveries = [
        ("bootstrap", {"bootstrap_roles"}, "reason_bootstrap_recovery"),
        (
            "auth",
            {
                "login_role",
                "register_role",
                "anonymous_probe",
                "tokenless_replay_probe",
                "auth_boundary_probe",
            },
            "reason_auth_recovery",
        ),
        ("verify", {"verify_bola", "verify_bopla"}, "reason_verify_recovery"),
        ("bola", {"bola_probe"}, "reason_bola_recovery"),
        ("bopla", {"bopla_probe"}, "reason_bopla_recovery"),
    ]

    semantic_hits = {
        "bootstrap": "bootstrap" in reason_text,
        "auth": any(token in reason_text for token in ["login", "authentication", "token"]),
        "verify": "verify" in reason_text,
        "bola": any(token in reason_text for token in ["bola", "object", "authorization"]),
        "bopla": any(
            token in reason_text
            for token in ["bopla", "property", "field", "fields", "sensitive", "exposure", "data exposure"]
        ),
    }

    for semantic_key, candidate_types, resolution_mode in semantic_recoveries:
        if not semantic_hits[semantic_key]:
            continue
        type_matches = [
            h for h, s in zip(saved_candidates, hypotheses_json)
            if s["type"] in candidate_types
        ]
        if type_matches:
            ranked = [(h, calculate_dynamic_priority(h, recent_observations=recent_observations)) for h in type_matches]
            ranked.sort(key=lambda x: x[1], reverse=True)
            return ranked[0][0], resolution_mode

    return None, "no_match"


def choose_unified_candidate(
    saved_candidates,
    hypotheses_json,
    dify_response,
    recent_observations=None,
    recent_selected_keys=None,
    recent_selected_hypothesis_types=None,
    weight_config=None,
):
    recent_observations = recent_observations or []
    config = {**DEFAULT_UNIFIED_WEIGHTS, **(weight_config or {})}
    scored = [(h, calculate_dynamic_priority(h, recent_observations=recent_observations)) for h in saved_candidates]
    scored.sort(key=lambda x: x[1], reverse=True)
    top_rule, top_rule_score = scored[0]

    if not dify_response:
        return (
            top_rule,
            top_rule_score,
            "unified_no_dify_fallback",
            "Unified mode fallback to rule-based scoring because Dify judge response was unavailable.",
        )

    selected, recovery_mode = resolve_dify_candidate(
        saved_candidates,
        hypotheses_json,
        dify_response.get("selected_key"),
        dify_response.get("reason", ""),
        recent_observations=recent_observations,
    )

    if selected is None:
        return (
            top_rule,
            top_rule_score,
            "unified_invalid_selection_fallback",
            f"Unified mode could not resolve Dify selection '{dify_response.get('selected_key')}'.",
        )

    dify_score = safe_dify_score(dify_response.get("score"))
    selected_rule_score = calculate_dynamic_priority(selected, recent_observations=recent_observations)
    blended_score = round(
        (float(config["rule_weight"]) * selected_rule_score)
        + (float(config["dify_weight"]) * dify_score),
        4,
    )
    repeated_nomination_count = _count_recent_key_repeats(recent_selected_keys, dify_response.get("selected_key"))
    repeated_nomination_penalty = round(
        min(float(config["repeat_penalty_cap"]), repeated_nomination_count * float(config["repeat_penalty_per_repeat"])),
        4,
    )
    adjusted_blended_score = round(blended_score - repeated_nomination_penalty, 4)
    repeated_top_rule_type_count = _count_recent_type_repeats(
        recent_selected_hypothesis_types,
        _hypothesis_type(top_rule),
    )
    recent_support_count = _count_recent_support_actions(recent_selected_hypothesis_types)
    repeated_top_rule_penalty = 0.0
    adjusted_top_rule_score = top_rule_score
    if _is_support_hypothesis(top_rule) and repeated_top_rule_type_count >= 2:
        repeated_top_rule_penalty = round(min(0.16, (repeated_top_rule_type_count - 1) * 0.04), 4)
        adjusted_top_rule_score = round(top_rule_score - repeated_top_rule_penalty, 4)
    current_round = len(recent_selected_hypothesis_types or []) + 1
    late_round_bonus = 0.0
    if (
        current_round >= 11
        and _is_attack_hypothesis(selected)
        and _is_support_hypothesis(top_rule)
        and dify_score >= 0.95
        and repeated_top_rule_type_count >= 2
    ):
        late_round_bonus = float(config["late_round_bonus"])
        adjusted_blended_score = round(adjusted_blended_score + late_round_bonus, 4)
    support_chain_penalty = 0.0
    if current_round >= 14 and _is_support_hypothesis(top_rule) and recent_support_count >= 3:
        support_chain_penalty = float(config["support_chain_penalty"])
        adjusted_top_rule_score = round(adjusted_top_rule_score - support_chain_penalty, 4)
    support_chain_bonus = 0.0
    if (
        current_round >= 14
        and recent_support_count >= 4
        and _is_attack_hypothesis(selected)
        and _is_support_hypothesis(top_rule)
        and dify_score >= 0.95
    ):
        support_chain_bonus = float(config["support_chain_bonus"])
        adjusted_blended_score = round(adjusted_blended_score + support_chain_bonus, 4)

    if _should_accept_dify_nomination(
        top_rule,
        adjusted_top_rule_score,
        selected,
        selected_rule_score,
        dify_score,
        adjusted_blended_score,
        current_round,
        recent_support_count,
    ):
        return (
            selected,
            adjusted_blended_score,
            f"unified_{recovery_mode}",
            (
                f"Unified mode accepted Dify nomination using blended score. "
                f"rule_based={selected_rule_score}, dify={dify_score}, blended={blended_score}, "
                f"repeat_penalty={repeated_nomination_penalty}, adjusted_blended={adjusted_blended_score}, "
                f"top_rule_penalty={repeated_top_rule_penalty}, adjusted_rule_top={adjusted_top_rule_score}, "
                f"late_round_bonus={late_round_bonus}, support_chain_penalty={support_chain_penalty}, "
                f"support_chain_bonus={support_chain_bonus}, recent_support_count={recent_support_count}, "
                f"weight_config={config}, "
                f"current_round={current_round}."
            ),
        )

    return (
        top_rule,
        top_rule_score,
        "unified_rule_based_override",
        (
            f"Unified mode kept rule-based winner over Dify nomination. "
            f"rule_top={top_rule_score}, dify_candidate_rule={selected_rule_score}, dify={dify_score}, "
            f"dify_blended={blended_score}, repeat_penalty={repeated_nomination_penalty}, "
            f"adjusted_blended={adjusted_blended_score}, top_rule_penalty={repeated_top_rule_penalty}, "
            f"adjusted_rule_top={adjusted_top_rule_score}, late_round_bonus={late_round_bonus}, "
            f"support_chain_penalty={support_chain_penalty}, support_chain_bonus={support_chain_bonus}, "
            f"weight_config={config}, "
            f"recent_support_count={recent_support_count}, "
            f"current_round={current_round}."
        ),
    )
