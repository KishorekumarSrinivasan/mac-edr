"""Read endpoints the dashboard polls."""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from app.database import get_session
from app.models import ProcessSnapshot, NetworkConnection, Alert

router = APIRouter(tags=["telemetry"])


@router.get("/processes")
def get_processes(session: Session = Depends(get_session)):
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    rows = session.exec(
        select(ProcessSnapshot)
        .where(ProcessSnapshot.timestamp >= cutoff)
        .order_by(ProcessSnapshot.timestamp.desc())
    ).all()
    return rows


@router.get("/network")
def get_network(session: Session = Depends(get_session)):
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=60)
    rows = session.exec(
        select(NetworkConnection)
        .where(NetworkConnection.timestamp >= cutoff)
        .order_by(NetworkConnection.timestamp.desc())
    ).all()
    return rows


@router.get("/alerts")
def get_alerts(session: Session = Depends(get_session)):
    rows = session.exec(select(Alert).order_by(Alert.timestamp.desc()).limit(200)).all()
    return rows
