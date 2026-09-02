"""Persistence monitor: baseline-diffs LaunchAgents/LaunchDaemons plist
directories to catch new or changed auto-run entries."""
import logging
import os
import plistlib
import threading

import api_client
from config import PERSISTENCE_DIRS, PERSISTENCE_POLL_INTERVAL_SEC

logger = logging.getLogger("edr.agent.persistence")


def _scan() -> dict[str, float]:
    """Returns {full_path: mtime} for every .plist in the watched dirs."""
    state = {}
    for d in PERSISTENCE_DIRS:
        if not os.path.isdir(d):
            continue
        try:
            for name in os.listdir(d):
                if not name.endswith(".plist"):
                    continue
                full = os.path.join(d, name)
                try:
                    state[full] = os.path.getmtime(full)
                except OSError:
                    continue
        except PermissionError:
            logger.debug("No permission to list %s", d)
    return state


def _read_label_and_program(path: str) -> tuple[str | None, str | None]:
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
        label = data.get("Label")
        program = data.get("Program") or " ".join(data.get("ProgramArguments", []) or [])
        return label, program
    except Exception:
        return None, None


def run(stop_event: threading.Event):
    logger.info("Persistence monitor started")
    baseline = _scan()
    while not stop_event.is_set():
        stop_event.wait(PERSISTENCE_POLL_INTERVAL_SEC)
        if stop_event.is_set():
            break
        current = _scan()
        new_or_changed = [
            p for p, mtime in current.items()
            if p not in baseline or baseline[p] != mtime
        ]
        for path in new_or_changed:
            label, program = _read_label_and_program(path)
            api_client.send_persistence({
                "entry_path": path, "label": label, "program": program,
            })
            logger.info("Persistence change: %s (%s)", path, label)
        baseline = current
