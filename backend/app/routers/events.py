"""Ingestion endpoints the agent POSTs telemetry to."""
from fastapi import APIRouter, Depends
from sqlmodel import Session
from app.database import get_session
from app.models import (
    ProcessSnapshot, NetworkConnection, FileEvent,
    PersistenceAlert, LogEvent, HashAlert,
)

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/process")
def post_process(items: list[ProcessSnapshot], session: Session = Depends(get_session)):
    for item in items:
        item.id = None
        session.add(item)
    session.commit()
    return {"received": len(items)}


@router.post("/network")
def post_network(items: list[NetworkConnection], session: Session = Depends(get_session)):
    for item in items:
        item.id = None
        session.add(item)
    session.commit()
    return {"received": len(items)}


@router.post("/file")
def post_file(item: FileEvent, session: Session = Depends(get_session)):
    item.id = None
    session.add(item)
    session.commit()
    return {"received": 1}


@router.post("/persistence")
def post_persistence(item: PersistenceAlert, session: Session = Depends(get_session)):
    item.id = None
    session.add(item)
    session.commit()
    return {"received": 1}


@router.post("/log")
def post_log(item: LogEvent, session: Session = Depends(get_session)):
    item.id = None
    session.add(item)
    session.commit()
    return {"received": 1}


@router.post("/hash")
def post_hash(item: HashAlert, session: Session = Depends(get_session)):
    item.id = None
    session.add(item)
    session.commit()
    return {"received": 1}
