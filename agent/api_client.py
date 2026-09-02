"""Thin wrapper around requests for talking to the backend, with basic
retry/backoff so a transient backend restart doesn't crash the agent."""
import logging
import time
import requests

from config import BACKEND_URL

logger = logging.getLogger("edr.agent.api")


def _post(path: str, json_body, retries: int = 2):
    url = f"{BACKEND_URL}{path}"
    for attempt in range(retries + 1):
        try:
            resp = requests.post(url, json=json_body, timeout=5)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            if attempt == retries:
                logger.warning("POST %s failed after %d retries: %s", path, retries, e)
                return None
            time.sleep(1 * (attempt + 1))


def _get(path: str, params=None):
    url = f"{BACKEND_URL}{path}"
    try:
        resp = requests.get(url, params=params, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        logger.warning("GET %s failed: %s", path, e)
        return None


def send_processes(items: list[dict]):
    return _post("/events/process", items)


def send_network(items: list[dict]):
    return _post("/events/network", items)


def send_file_event(item: dict):
    return _post("/events/file", item)


def send_persistence(item: dict):
    return _post("/events/persistence", item)


def send_log(item: dict):
    return _post("/events/log", item)


def send_hash(item: dict):
    return _post("/events/hash", item)


def get_pending_actions():
    return _get("/response/pending") or []


def ack_action(action_id: int):
    return _post(f"/response/{action_id}/ack", {})


def complete_action(action_id: int, success: bool, detail: str = ""):
    url = f"/response/{action_id}/complete"
    try:
        resp = requests.post(
            f"{BACKEND_URL}{url}",
            params={"success": success, "detail": detail},
            timeout=5,
        )
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        logger.warning("complete_action failed: %s", e)
        return None
