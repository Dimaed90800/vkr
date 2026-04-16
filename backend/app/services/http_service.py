import requests
import time


def send_request(
    method: str,
    url: str,
    headers=None,
    params=None,
    json_body=None,
    timeout: int = 30
):
    started = time.perf_counter()
    resp = requests.request(
        method=method.upper(),
        url=url,
        headers=headers or {},
        params=params or {},
        json=json_body,
        timeout=timeout
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000, 2)

    return {
        "status_code": resp.status_code,
        "text": resp.text[:12000],
        "headers": dict(resp.headers),
        "elapsed_ms": elapsed_ms,
    }
