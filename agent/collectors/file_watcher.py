"""Filesystem watcher using watchdog (wraps native FSEvents on macOS).

Wires straight into hash_monitor on file *creation* -- v1's documented
detection gap: overwriting an existing file (create stub, later overwrite
with real payload -- a common dropper pattern) is NOT re-hashed here,
because watchdog reports that as a `modified` event, not `created`. Track
this as a known gap (see README) rather than silently "fixing" it by
hashing on every modify, which would hammer the CPU on large downloads.
"""
import logging
import threading

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import api_client
from collectors import hash_monitor
from config import WATCHED_DIRS

logger = logging.getLogger("edr.agent.filewatch")


class Handler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        self._emit(event.src_path, "created")
        # Key integration point: instant hash check on new files.
        hit = hash_monitor.check_file(event.src_path)
        if hit:
            api_client.send_hash(hit)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._emit(event.src_path, "modified")

    def on_deleted(self, event):
        if event.is_directory:
            return
        self._emit(event.src_path, "deleted")

    def _emit(self, path: str, event_type: str):
        api_client.send_file_event({"path": path, "event_type": event_type})


def run(stop_event: threading.Event):
    observer = Observer()
    handler = Handler()
    watched_any = False
    for d in WATCHED_DIRS:
        try:
            observer.schedule(handler, d, recursive=False)
            watched_any = True
            logger.info("Watching %s", d)
        except FileNotFoundError:
            logger.warning("Watch dir does not exist, skipping: %s", d)
    if not watched_any:
        logger.error("No watchable directories found; file watcher idle")
        return
    observer.start()
    logger.info("Filesystem watcher started")
    try:
        stop_event.wait()
    finally:
        observer.stop()
        observer.join()
