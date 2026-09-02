"""Detection engine: runs every 30s, applies rules to stored telemetry,
writes deduplicated Alert rows, and (for rules configured to auto-respond)
queues a ResponseAction for the agent to execute.
"""
import logging
from datetime import datetime, timedelta, timezone
from sqlmodel import Session, select

from app.models import (
    ProcessSnapshot,
    NetworkConnection,
    PersistenceAlert,
    LogEvent,
    HashAlert,
    Alert,
    ResponseAction,
)

logger = logging.getLogger("edr.detection")

SUSPICIOUS_PATHS = ("/tmp/", "/Downloads/", "/private/tmp/")
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 8081}
AUTH_FAILURE_WINDOW_MIN = 5
AUTH_FAILURE_THRESHOLD = 3
DEDUP_COOLDOWN_MIN = 5

# Which rules are allowed to trigger an automated response, and which
# action to queue. Kept as an explicit allowlist rather than "respond to
# everything" — auto-killing on a MEDIUM heuristic would be too aggressive.
AUTO_RESPONSE_POLICY = {
    "MALWARE_HASH_MATCH": "quarantine_file",
    "NEW_PERSISTENCE_DETECTED": None,  # HIGH but needs human review by default
    "SUSPICIOUS_NETWORK_PORT": "block_connection",
    "SUSPICIOUS_PROCESS_PATH": None,
    "REPEATED_AUTH_FAILURE": None,
}


def _recently_fired(session: Session, dedup_key: str) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=DEDUP_COOLDOWN_MIN)
    existing = session.exec(
        select(Alert).where(Alert.dedup_key == dedup_key, Alert.timestamp >= cutoff)
    ).first()
    return existing is not None


def _raise_alert(session: Session, rule: str, severity: str, message: str,
                  dedup_key: str, source_pid: int | None = None,
                  source_path: str | None = None) -> Alert | None:
    if _recently_fired(session, dedup_key):
        return None
    alert = Alert(
        rule=rule, severity=severity, message=message, dedup_key=dedup_key,
        source_pid=source_pid, source_path=source_path,
    )
    session.add(alert)
    session.commit()
    session.refresh(alert)
    logger.info("ALERT [%s] %s: %s", severity, rule, message)

    action_type = AUTO_RESPONSE_POLICY.get(rule)
    if action_type:
        target = source_path or (str(source_pid) if source_pid else "")
        action = ResponseAction(
            alert_id=alert.id, action_type=action_type, target=target,
            triggered_by="auto", status="pending",
        )
        session.add(action)
        session.commit()
        logger.info("QUEUED response action %s for alert %s", action_type, alert.id)
    return alert


def rule_suspicious_process_path(session: Session) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    procs = session.exec(
        select(ProcessSnapshot).where(ProcessSnapshot.timestamp >= cutoff)
    ).all()
    for p in procs:
        if p.path and any(sp in p.path for sp in SUSPICIOUS_PATHS):
            _raise_alert(
                session, "SUSPICIOUS_PROCESS_PATH", "MEDIUM",
                f"Process '{p.name}' (pid {p.pid}) running from {p.path}",
                dedup_key=f"SUSPICIOUS_PROCESS_PATH:{p.pid}:{p.path}",
                source_pid=p.pid, source_path=p.path,
            )


def rule_new_persistence(session: Session) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    entries = session.exec(
        select(PersistenceAlert).where(PersistenceAlert.timestamp >= cutoff)
    ).all()
    for e in entries:
        _raise_alert(
            session, "NEW_PERSISTENCE_DETECTED", "HIGH",
            f"New persistence entry: {e.entry_path} ({e.label or 'unknown'})",
            dedup_key=f"NEW_PERSISTENCE_DETECTED:{e.entry_path}",
            source_path=e.entry_path,
        )


def rule_malware_hash_match(session: Session) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    hits = session.exec(
        select(HashAlert).where(HashAlert.timestamp >= cutoff)
    ).all()
    for h in hits:
        _raise_alert(
            session, "MALWARE_HASH_MATCH", "CRITICAL",
            f"File {h.path} matches known-bad signature '{h.signature_name}' ({h.sha256[:12]}...)",
            dedup_key=f"MALWARE_HASH_MATCH:{h.sha256}:{h.path}",
            source_path=h.path,
        )


def rule_repeated_auth_failure(session: Session) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=AUTH_FAILURE_WINDOW_MIN)
    failures = session.exec(
        select(LogEvent).where(
            LogEvent.category == "auth_failure", LogEvent.timestamp >= cutoff
        )
    ).all()
    by_user: dict[str, int] = {}
    for f in failures:
        key = f.user or "unknown"
        by_user[key] = by_user.get(key, 0) + 1
    for user, count in by_user.items():
        if count >= AUTH_FAILURE_THRESHOLD:
            # Cooldown-based dedup key (no timestamp component) — the v1 bug
            # was building this key from a shifting time window, which
            # produced a near-duplicate alert every cycle. The 5-minute
            # _recently_fired() cooldown check is what actually prevents
            # re-firing, not the key itself.
            _raise_alert(
                session, "REPEATED_AUTH_FAILURE", "HIGH",
                f"{count} failed login attempts for user '{user}' in {AUTH_FAILURE_WINDOW_MIN} min",
                dedup_key=f"REPEATED_AUTH_FAILURE:{user}",
            )


def rule_suspicious_network_port(session: Session) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    conns = session.exec(
        select(NetworkConnection).where(NetworkConnection.timestamp >= cutoff)
    ).all()
    for c in conns:
        if c.remote_port in SUSPICIOUS_PORTS:
            _raise_alert(
                session, "SUSPICIOUS_NETWORK_PORT", "HIGH",
                f"Connection to {c.remote_addr}:{c.remote_port} (pid {c.pid})",
                dedup_key=f"SUSPICIOUS_NETWORK_PORT:{c.remote_addr}:{c.remote_port}:{c.pid}",
                source_pid=c.pid,
                source_path=f"{c.remote_addr}:{c.remote_port}",
            )


RULES = [
    rule_suspicious_process_path,
    rule_new_persistence,
    rule_malware_hash_match,
    rule_repeated_auth_failure,
    rule_suspicious_network_port,
]


def run_detection_cycle(session: Session) -> int:
    """Runs all rules once. Returns number of alerts raised."""
    raised = 0
    for rule_fn in RULES:
        try:
            before = session.exec(select(Alert)).all()
            rule_fn(session)
            after = session.exec(select(Alert)).all()
            raised += max(0, len(after) - len(before))
        except Exception:
            logger.exception("Detection rule %s failed", rule_fn.__name__)
    return raised
