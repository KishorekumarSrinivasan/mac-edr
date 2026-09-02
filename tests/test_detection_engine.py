"""Targets the exact bug classes v1 actually hit: dedup flooding, cooldown
behavior, and each rule's basic trigger condition."""
import time
from datetime import datetime, timedelta, timezone


def test_suspicious_process_path_triggers_alert(session):
    from app.models import ProcessSnapshot, Alert
    from app.detection import run_detection_cycle

    session.add(ProcessSnapshot(pid=999, name="evil", user="kishore", path="/tmp/evil"))
    session.commit()

    raised = run_detection_cycle(session)
    assert raised == 1
    from sqlmodel import select
    alerts = session.exec(select(Alert)).all()
    assert len(alerts) == 1
    assert alerts[0].rule == "SUSPICIOUS_PROCESS_PATH"
    assert alerts[0].severity == "MEDIUM"


def test_script_run_via_interpreter_still_triggers(session):
    """Regression test: a script run as `bash /tmp/payload.sh` reports
    /bin/bash as its `path` (the interpreter), not the script -- this bit
    us running a real /tmp/*.sh test file and produced no alert. The rule
    must also check `cmdline` to catch this."""
    from app.models import ProcessSnapshot, Alert
    from app.detection import run_detection_cycle
    from sqlmodel import select

    session.add(ProcessSnapshot(
        pid=1234, name="bash", user="kishore", path="/bin/bash",
        cmdline="/bin/bash /tmp/payload.sh",
    ))
    session.commit()

    raised = run_detection_cycle(session)
    assert raised == 1
    alerts = session.exec(select(Alert)).all()
    assert len(alerts) == 1
    assert alerts[0].rule == "SUSPICIOUS_PROCESS_PATH"
    assert "/tmp/payload.sh" in alerts[0].message


def test_normal_process_path_does_not_trigger(session):
    from app.models import ProcessSnapshot, Alert
    from app.detection import run_detection_cycle
    from sqlmodel import select

    session.add(ProcessSnapshot(pid=1, name="Finder", user="kishore", path="/System/Library/Finder"))
    session.commit()

    run_detection_cycle(session)
    assert session.exec(select(Alert)).all() == []


def test_dedup_prevents_duplicate_alert_within_cooldown(session):
    """This is the exact bug class from v1: REPEATED_AUTH_FAILURE fired a
    near-duplicate alert every cycle. Running the same rule twice in a row
    on unchanged data must not double the alert count."""
    from app.models import ProcessSnapshot, Alert
    from app.detection import run_detection_cycle
    from sqlmodel import select

    session.add(ProcessSnapshot(pid=999, name="evil", user="kishore", path="/tmp/evil"))
    session.commit()

    run_detection_cycle(session)
    run_detection_cycle(session)
    run_detection_cycle(session)

    alerts = session.exec(select(Alert)).all()
    assert len(alerts) == 1, "rule fired more than once within the dedup cooldown"


def test_repeated_auth_failure_threshold(session):
    from app.models import LogEvent, Alert
    from app.detection import run_detection_cycle
    from sqlmodel import select

    for _ in range(2):
        session.add(LogEvent(category="auth_failure", user="kishore", raw_message="failed"))
    session.commit()
    run_detection_cycle(session)
    assert session.exec(select(Alert)).all() == [], "should not fire below threshold"

    session.add(LogEvent(category="auth_failure", user="kishore", raw_message="failed"))
    session.commit()
    run_detection_cycle(session)
    alerts = session.exec(select(Alert)).all()
    assert len(alerts) == 1
    assert alerts[0].rule == "REPEATED_AUTH_FAILURE"


def test_malware_hash_match_queues_quarantine_response(session):
    from app.models import HashAlert, Alert, ResponseAction
    from app.detection import run_detection_cycle
    from sqlmodel import select

    session.add(HashAlert(path="/tmp/evil.txt", sha256="a" * 64, signature_name="EICAR-Test-File"))
    session.commit()

    run_detection_cycle(session)

    alerts = session.exec(select(Alert)).all()
    assert len(alerts) == 1
    assert alerts[0].severity == "CRITICAL"

    actions = session.exec(select(ResponseAction)).all()
    assert len(actions) == 1
    assert actions[0].action_type == "quarantine_file"
    assert actions[0].status == "pending"
    assert actions[0].alert_id == alerts[0].id


def test_new_persistence_does_not_auto_respond(session):
    """Policy check: HIGH severity but not in the auto-response allowlist
    -- should raise an alert without queuing an action."""
    from app.models import PersistenceAlert, Alert, ResponseAction
    from app.detection import run_detection_cycle
    from sqlmodel import select

    session.add(PersistenceAlert(entry_path="/tmp/x.plist", label="com.evil.x"))
    session.commit()
    run_detection_cycle(session)

    assert len(session.exec(select(Alert)).all()) == 1
    assert session.exec(select(ResponseAction)).all() == []


def test_suspicious_network_port_queues_block_response(session):
    from app.models import NetworkConnection, ResponseAction
    from app.detection import run_detection_cycle
    from sqlmodel import select

    session.add(NetworkConnection(
        pid=123, local_addr="127.0.0.1", local_port=5000,
        remote_addr="10.0.0.5", remote_port=4444, status="ESTABLISHED",
    ))
    session.commit()
    run_detection_cycle(session)

    actions = session.exec(select(ResponseAction)).all()
    assert len(actions) == 1
    assert actions[0].action_type == "block_connection"
