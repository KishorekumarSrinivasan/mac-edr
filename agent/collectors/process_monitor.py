"""Process & network collector. Iterates per-process rather than calling
psutil.net_connections() globally — that call crashes the whole scan the
moment it hits one process it isn't allowed to inspect (macOS SIP/TCC
restrictions). Skipping just the inaccessible process is the v1 fix,
kept here from the start.
"""
import logging
import threading

import psutil

import api_client
from config import PROCESS_POLL_INTERVAL_SEC

logger = logging.getLogger("edr.agent.process")


def _collect_processes() -> list[dict]:
    items = []
    for p in psutil.process_iter(["pid", "name", "username", "exe", "cmdline"]):
        try:
            info = p.info
            items.append({
                "pid": info["pid"],
                "name": info["name"] or "",
                "user": info["username"] or "",
                "path": info["exe"] or "",
                "cmdline": " ".join(info["cmdline"] or []),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return items


def _collect_network() -> list[dict]:
    items = []
    for p in psutil.process_iter(["pid"]):
        pid = p.info["pid"]
        try:
            conns = p.net_connections(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            # Defensive: some macOS versions raise generic OSError for
            # permission issues here rather than psutil.AccessDenied.
            continue
        for c in conns:
            laddr = c.laddr
            raddr = c.raddr
            if not laddr:
                continue
            items.append({
                "pid": pid,
                "local_addr": laddr.ip,
                "local_port": laddr.port,
                "remote_addr": raddr.ip if raddr else None,
                "remote_port": raddr.port if raddr else None,
                "status": c.status,
            })
    return items


def run(stop_event: threading.Event):
    logger.info("Process & network monitor started")
    while not stop_event.is_set():
        procs = _collect_processes()
        if procs:
            api_client.send_processes(procs)
        conns = _collect_network()
        if conns:
            api_client.send_network(conns)
        stop_event.wait(PROCESS_POLL_INTERVAL_SEC)
