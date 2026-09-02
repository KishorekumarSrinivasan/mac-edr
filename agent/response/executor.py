"""Executes response actions queued by the backend's detection engine.

Design notes:
- Actions are queued by the backend (which has no privileged access) and
  polled/executed here on the agent, which runs on the actual endpoint
  and can act on it. This mirrors how real EDR agents receive commands
  from a cloud console and execute them locally.
- ENABLE_AUTO_RESPONSE gates whether queued actions execute automatically
  or just sit as "pending" for a human to approve via the dashboard/API
  (manual triggers always execute once queued, regardless of this flag --
  a human already made the call).
- Every action is logged to the ResponseAction table via complete_action,
  success or failure, so there's always an audit trail.
"""
import logging
import os
import shutil
import subprocess
import threading

import psutil

import api_client
from config import RESPONSE_POLL_INTERVAL_SEC, ENABLE_AUTO_RESPONSE, QUARANTINE_DIR

logger = logging.getLogger("edr.agent.response")


def kill_process(target: str) -> tuple[bool, str]:
    try:
        pid = int(target)
    except ValueError:
        return False, f"invalid pid: {target}"
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        try:
            p.wait(timeout=3)
        except psutil.TimeoutExpired:
            p.kill()
        return True, f"killed pid {pid} ({name})"
    except psutil.NoSuchProcess:
        return True, f"pid {pid} already gone"
    except psutil.AccessDenied:
        return False, f"access denied killing pid {pid} (needs elevated privileges)"


def quarantine_file(target: str) -> tuple[bool, str]:
    if not os.path.isfile(target):
        return False, f"file not found: {target}"
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    dest = os.path.join(QUARANTINE_DIR, os.path.basename(target) + ".quarantined")
    try:
        # chmod 000 + move rather than delete: preserves the sample for
        # later analysis while removing execute/read access in place.
        os.chmod(target, 0o000)
        shutil.move(target, dest)
        return True, f"quarantined to {dest}"
    except OSError as e:
        return False, f"quarantine failed: {e}"


def block_connection(target: str) -> tuple[bool, str]:
    """Blocks outbound traffic to `ip:port` using pfctl. Requires sudo --
    if the agent isn't running with sufficient privilege this will fail
    cleanly and the failure is recorded, not silently swallowed."""
    if ":" not in target:
        return False, f"expected ip:port, got: {target}"
    ip, _, port = target.rpartition(":")
    rule = f"block drop out proto tcp from any to {ip} port {port}\n"
    anchor_file = "/tmp/mac_edr_pf.conf"
    try:
        with open(anchor_file, "a") as f:
            f.write(rule)
        subprocess.run(
            ["pfctl", "-f", anchor_file], check=True,
            capture_output=True, timeout=5,
        )
        return True, f"blocked {target} via pfctl"
    except (subprocess.CalledProcessError, PermissionError, FileNotFoundError) as e:
        return False, f"pfctl block failed (needs sudo): {e}"


ACTIONS = {
    "kill_process": kill_process,
    "quarantine_file": quarantine_file,
    "block_connection": block_connection,
}


def _execute(action: dict):
    action_id = action["id"]
    action_type = action["action_type"]
    target = action["target"]
    triggered_by = action.get("triggered_by", "auto")

    if triggered_by == "auto" and not ENABLE_AUTO_RESPONSE:
        api_client.ack_action(action_id)
        logger.info(
            "Auto-response disabled (EDR_ENABLE_AUTO_RESPONSE=0) -- "
            "action %s (%s on %s) left pending for manual approval",
            action_id, action_type, target,
        )
        return

    handler = ACTIONS.get(action_type)
    if not handler:
        api_client.complete_action(action_id, False, f"unknown action_type {action_type}")
        return

    api_client.ack_action(action_id)
    success, detail = handler(target)
    api_client.complete_action(action_id, success, detail)
    level = logging.INFO if success else logging.WARNING
    logger.log(level, "Response action %s (%s on %s): %s", action_id, action_type, target, detail)


def run(stop_event: threading.Event):
    logger.info(
        "Response executor started (auto-response=%s)",
        "ON" if ENABLE_AUTO_RESPONSE else "OFF, actions require manual approval",
    )
    while not stop_event.is_set():
        for action in api_client.get_pending_actions():
            _execute(action)
        stop_event.wait(RESPONSE_POLL_INTERVAL_SEC)
