"""Mac EDR agent entrypoint: launches all collectors + the response
executor as daemon threads and waits for Ctrl-C."""
import logging
import signal
import threading

from collectors import process_monitor, file_watcher, persistence_monitor, log_monitor
from response import executor

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("edr.agent")

WORKERS = [
    ("process_monitor", process_monitor.run),
    ("file_watcher", file_watcher.run),
    ("persistence_monitor", persistence_monitor.run),
    ("log_monitor", log_monitor.run),
    ("response_executor", executor.run),
]


def main():
    stop_event = threading.Event()
    threads = []
    for name, target in WORKERS:
        t = threading.Thread(target=target, args=(stop_event,), name=name, daemon=True)
        t.start()
        threads.append(t)
        logger.info("Started worker: %s", name)

    def handle_sigint(signum, frame):
        logger.info("Shutting down...")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    while not stop_event.is_set():
        stop_event.wait(1)

    for t in threads:
        t.join(timeout=5)
    logger.info("Agent stopped")


if __name__ == "__main__":
    main()
