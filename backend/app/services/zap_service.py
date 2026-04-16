import os
import requests
import time
from typing import Optional, Union

ZAP_BASE_URL = os.getenv("ZAP_BASE_URL", "http://localhost:8080")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "changeme")

def start_spider(target_url: str):
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/spider/action/scan/",
        params={
            "apikey": ZAP_API_KEY,
            "url": target_url,
            "maxChildren": 20,
            "recurse": True,
            "contextName": "",
            "subtreeOnly": False
        },
        timeout=30
    )
    resp.raise_for_status()
    return resp.json()

def spider_status():
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/spider/view/status/",
        params={"apikey": ZAP_API_KEY},
        timeout=30
    )
    resp.raise_for_status()
    return resp.json()

def spider_results():
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/core/view/urls/",
        params={"apikey": ZAP_API_KEY},
        timeout=30
    )
    resp.raise_for_status()
    return resp.json()


def start_ajax_spider(target_url: str):
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/ajaxSpider/action/scan/",
        params={
            "apikey": ZAP_API_KEY,
            "url": target_url,
            "inScope": "",
            "contextName": "",
            "subtreeOnly": False
        },
        timeout=30
    )
    resp.raise_for_status()
    return resp.json()


def ajax_spider_status():
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/ajaxSpider/view/status/",
        params={"apikey": ZAP_API_KEY},
        timeout=30
    )
    resp.raise_for_status()
    return resp.json()

def run_spider_and_wait(target_url: str, max_wait_sec: int = 120):
    start_spider(target_url)

    waited = 0
    while waited < max_wait_sec:
        status = spider_status()
        progress = int(status.get("status", 0))
        if progress >= 100:
            break
        time.sleep(2)
        waited += 2

    return spider_results()


def run_ajax_spider_and_wait(target_url: str, max_wait_sec: int = 120):
    start_ajax_spider(target_url)

    waited = 0
    while waited < max_wait_sec:
        status = ajax_spider_status()
        if str(status.get("status", "")).lower() == "stopped":
            break
        time.sleep(2)
        waited += 2

    return spider_results()


def import_openapi_url(openapi_url: str, target: str = ""):
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/openapi/action/importUrl/",
        params={
            "apikey": ZAP_API_KEY,
            "url": openapi_url,
            "target": target,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def start_active_scan(target_url: str, recurse: bool = True):
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/ascan/action/scan/",
        params={
            "apikey": ZAP_API_KEY,
            "url": target_url,
            "recurse": str(bool(recurse)).lower(),
            "inScopeOnly": "false",
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def active_scan_status(scan_id: Optional[Union[str, int]] = None):
    params = {"apikey": ZAP_API_KEY}
    if scan_id is not None:
        params["scanId"] = str(scan_id)
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/ascan/view/status/",
        params=params,
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def run_active_scan_and_wait(target_url: str, max_wait_sec: int = 300, recurse: bool = True):
    scan = start_active_scan(target_url, recurse=recurse)
    scan_id = scan.get("scan")

    waited = 0
    while waited < max_wait_sec:
        status = active_scan_status(scan_id)
        progress = int(status.get("status", 0))
        if progress >= 100:
            break
        time.sleep(2)
        waited += 2

    return {"scan_id": scan_id, "status": active_scan_status(scan_id)}


def list_alerts(base_url: str, start: int = 0, count: int = 9999):
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/alert/view/alerts/",
        params={
            "apikey": ZAP_API_KEY,
            "baseurl": base_url,
            "start": start,
            "count": count,
        },
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def number_of_messages():
    resp = requests.get(
        f"{ZAP_BASE_URL}/JSON/core/view/numberOfMessages/",
        params={"apikey": ZAP_API_KEY},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()
