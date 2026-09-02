"""Auth/log monitor: tails `log stream` (macOS Unified Logging) for
authentication-relevant lines using simple keyword matching.

Known limitation (documented, not silently hidden): keyword matching can
false-positive on unrelated system messages that happen to contain a
matched substring. A real implementation would use `log stream --predicate`
with a structured subsystem/category filter instead of grepping text.
"""
import logging
import re
import subprocess
import threading

import api_client

logger = logging.getLogger("edr.agent.log")

# (category, compiled pattern) -- checked in order, first match wins.
PATTERNS = [
    ("auth_failure", re.compile(r"authentication failure|Failed password|incorrect password", re.I)),
    ("auth_success", re.compile(r"session opened for user|Authentication succeeded", re.I)),
    ("sudo", re.compile(r"\bsudo\b", re.I)),
    ("login", re.compile(r"\blogin\b", re.I)),
    ("logout", re.compile(r"\blogout\b", re.I)),
]

USER_PATTERN = re.compile(r"user[= ]([\w.\-]+)", re.I)


def _classify(line: str) -> tuple[str, str | None] | None:
    for category, pattern in PATTERNS:
        if pattern.search(line):
            user_match = USER_PATTERN.search(line)
            return category, (user_match.group(1) if user_match else None)
    return None


def run(stop_event: threading.Event):
    logger.info("Log monitor started")
    cmd = [
        "log", "stream",
        "--style", "compact",
        "--predicate",
        'eventMessage CONTAINS "authentication" OR eventMessage CONTAINS "sudo" '
        'OR eventMessage CONTAINS "login" OR eventMessage CONTAINS "password"',
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except FileNotFoundError:
        logger.error("`log` command not found -- log monitor requires macOS")
        return

    try:
        while not stop_event.is_set():
            line = proc.stdout.readline()
            if not line:
                break
            result = _classify(line)
            if result:
                category, user = result
                api_client.send_log({
                    "category": category, "user": user, "raw_message": line.strip()[:500],
                })
    finally:
        proc.terminate()
