import os

BACKEND_URL = os.environ.get("EDR_BACKEND_URL", "http://127.0.0.1:8000")

WATCHED_DIRS = [
    os.path.expanduser("~/Downloads"),
    "/tmp",
    os.path.expanduser("~/Library/LaunchAgents"),
]

PERSISTENCE_DIRS = [
    os.path.expanduser("~/Library/LaunchAgents"),
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
]

PROCESS_POLL_INTERVAL_SEC = 15
PERSISTENCE_POLL_INTERVAL_SEC = 30
RESPONSE_POLL_INTERVAL_SEC = 5

# Response actions require explicit opt-in: set EDR_ENABLE_AUTO_RESPONSE=1
# to let the agent actually kill/quarantine/block on its own. Off by
# default so a false positive during testing can't take a real action.
ENABLE_AUTO_RESPONSE = os.environ.get("EDR_ENABLE_AUTO_RESPONSE", "0") == "1"

QUARANTINE_DIR = os.path.expanduser("~/.mac_edr_quarantine")
