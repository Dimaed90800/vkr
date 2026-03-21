import os
import requests
import time

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