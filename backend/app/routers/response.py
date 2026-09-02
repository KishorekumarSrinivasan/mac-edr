"""Response-action endpoints: manual triggering by an analyst, plus the
poll/ack/complete cycle the agent uses to execute queued actions locally.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from app.database import get_session
from app.models import ResponseAction, Alert

router = APIRouter(prefix="/response", tags=["response"])

ALLOWED_ACTIONS = {"kill_process", "quarantine_file", "block_connection"}


@router.post("/trigger")
def trigger_response(alert_id: int, action_type: str, target: str,
                      session: Session = Depends(get_session)):
    """Analyst-initiated response, e.g. from a dashboard button."""
    if action_type not in ALLOWED_ACTIONS:
        raise HTTPException(400, f"Unknown action_type: {action_type}")
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    action = ResponseAction(
        alert_id=alert_id, action_type=action_type, target=target,
        triggered_by="manual", status="pending",
    )
    session.add(action)
    session.commit()
    session.refresh(action)
    return action


@router.get("/pending")
def get_pending(session: Session = Depends(get_session)):
    """The agent polls this to learn what it should execute locally."""
    rows = session.exec(
        select(ResponseAction).where(ResponseAction.status == "pending")
    ).all()
    return rows


@router.post("/{action_id}/ack")
def ack_action(action_id: int, session: Session = Depends(get_session)):
    action = session.get(ResponseAction, action_id)
    if not action:
        raise HTTPException(404, "Action not found")
    action.status = "acknowledged"
    session.add(action)
    session.commit()
    return action


@router.post("/{action_id}/complete")
def complete_action(action_id: int, success: bool, detail: str = "",
                     session: Session = Depends(get_session)):
    action = session.get(ResponseAction, action_id)
    if not action:
        raise HTTPException(404, "Action not found")
    action.status = "completed" if success else "failed"
    action.detail = detail
    session.add(action)
    session.commit()
    return action


@router.get("")
def list_actions(session: Session = Depends(get_session)):
    rows = session.exec(
        select(ResponseAction).order_by(ResponseAction.timestamp.desc()).limit(200)
    ).all()
    return rows
