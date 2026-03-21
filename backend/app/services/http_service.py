import requests


def send_request(
    method: str,
    url: str,
    headers=None,
    params=None,
    json_body=None,
    timeout: int = 30
):
    resp = requests.request(
        method=method.upper(),
        url=url,
        headers=headers or {},
        params=params or {},
        json=json_body,
        timeout=timeout
    )

    return {
        "status_code": resp.status_code,
        "text": resp.text[:12000],
        "headers": dict(resp.headers)
    }