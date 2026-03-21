import json
import time
import uuid


def generate_unique_identity(role_name: str) -> dict:
    suffix = f"{int(time.time())}-{uuid.uuid4().hex[:6]}"
    email = f"{role_name}-{suffix}@example.com"
    phone = f"555{str(int(time.time()))[-6:]}{uuid.uuid4().hex[:2]}"
    phone = "".join(ch for ch in phone if ch.isdigit())[:10]
    if len(phone) < 10:
        phone = phone.ljust(10, "7")

    return {
        "email": email,
        "password": "Test1234!",
        "phone_number": phone,
        "name": f"{role_name}-{suffix}"
    }


def extract_tokens_from_response_text(response_text: str) -> dict:
    try:
        data = json.loads(response_text)
    except Exception:
        return {}

    token_candidates = {
        "access_token": data.get("access_token") or data.get("token") or data.get("jwt"),
        "refresh_token": data.get("refresh_token"),
        "token_type": data.get("token_type") or "Bearer"
    }

    if token_candidates["access_token"]:
        return token_candidates

    # Иногда токен лежит глубже
    for key in ("data", "result", "response"):
        value = data.get(key)
        if isinstance(value, dict):
            access_token = value.get("access_token") or value.get("token") or value.get("jwt")
            refresh_token = value.get("refresh_token")
            token_type = value.get("token_type") or "Bearer"
            if access_token:
                return {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "token_type": token_type
                }

    return {}