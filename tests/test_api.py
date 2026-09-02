"""Integration tests through FastAPI's TestClient -- covers ingestion,
alert retrieval, and the manual response trigger endpoint."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))


@pytest.fixture
def client(session):
    """Reuses the truncated-per-test DB from the `session` fixture (see
    conftest.py) so app.main's module-level engine matches what the
    session fixture just cleared."""
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


def test_health_check(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_ingest_and_read_processes(client):
    resp = client.post("/events/process", json=[
        {"pid": 1, "name": "init", "user": "root", "path": "/sbin/init", "cmdline": ""}
    ])
    assert resp.status_code == 200
    assert resp.json()["received"] == 1

    resp = client.get("/processes")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_ingest_hash_alert_and_manual_response_trigger(client):
    resp = client.post("/events/hash", json={
        "path": "/tmp/evil.txt", "sha256": "b" * 64, "signature_name": "Test-Sig",
    })
    assert resp.status_code == 200

    # Trigger detection manually rather than waiting on the 30s loop.
    from app.database import engine
    from app.detection import run_detection_cycle
    from sqlmodel import Session
    with Session(engine) as s:
        run_detection_cycle(s)

    alerts = client.get("/alerts").json()
    assert len(alerts) == 1
    alert_id = alerts[0]["id"]

    resp = client.post("/response/trigger", params={
        "alert_id": alert_id, "action_type": "quarantine_file", "target": "/tmp/evil.txt",
    })
    assert resp.status_code == 200
    assert resp.json()["triggered_by"] == "manual"


def test_response_trigger_rejects_unknown_action(client):
    client.post("/events/hash", json={
        "path": "/tmp/x", "sha256": "c" * 64, "signature_name": "Test",
    })
    from app.database import engine
    from app.detection import run_detection_cycle
    from sqlmodel import Session
    with Session(engine) as s:
        run_detection_cycle(s)
    alert_id = client.get("/alerts").json()[0]["id"]

    resp = client.post("/response/trigger", params={
        "alert_id": alert_id, "action_type": "format_disk", "target": "x",
    })
    assert resp.status_code == 400
