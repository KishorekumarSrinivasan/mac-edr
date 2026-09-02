"""FastAPI app entrypoint: wires routers + runs the detection engine on a
background thread every 30s."""
import logging
import threading

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlmodel import Session

from app.database import init_db, engine
from app.detection import run_detection_cycle
from app.routers import events, telemetry, response

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("edr")

DETECTION_INTERVAL_SEC = 30

app = FastAPI(title="Mac EDR Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local single-user tool; tighten if ever exposed
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(events.router)
app.include_router(telemetry.router)
app.include_router(response.router)

_stop_event = threading.Event()


def _detection_loop():
    while not _stop_event.is_set():
        try:
            with Session(engine) as session:
                raised = run_detection_cycle(session)
                if raised:
                    logger.info("Detection cycle raised %d alert(s)", raised)
        except Exception:
            logger.exception("Detection cycle crashed")
        _stop_event.wait(DETECTION_INTERVAL_SEC)


@app.on_event("startup")
def on_startup():
    init_db()
    thread = threading.Thread(target=_detection_loop, daemon=True)
    thread.start()
    logger.info("Detection engine started (interval=%ss)", DETECTION_INTERVAL_SEC)


@app.get("/")
def health():
    return {"status": "ok", "service": "mac-edr-backend"}
