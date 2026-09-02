"""SQLModel table definitions for all telemetry, alerts, and response actions."""
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field


def now() -> datetime:
    return datetime.now(timezone.utc)


class ProcessSnapshot(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=now, index=True)
    pid: int = Field(index=True)
    name: str
    user: str
    path: Optional[str] = None
    cmdline: Optional[str] = None


class NetworkConnection(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=now, index=True)
    pid: Optional[int] = None
    local_addr: str
    local_port: int
    remote_addr: Optional[str] = None
    remote_port: Optional[int] = None
    status: str


class FileEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=now, index=True)
    path: str
    event_type: str  # created | modified | deleted


class PersistenceAlert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=now, index=True)
    entry_path: str
    label: Optional[str] = None
    program: Optional[str] = None


class LogEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=now, index=True)
    category: str  # auth_failure | auth_success | sudo | login | logout
    user: Optional[str] = None
    raw_message: str


class HashAlert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=now, index=True)
    path: str
    sha256: str
    signature_name: str


class Alert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=now, index=True)
    rule: str = Field(index=True)
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    message: str
    dedup_key: str = Field(index=True)
    source_pid: Optional[int] = None
    source_path: Optional[str] = None
    status: str = Field(default="open")  # open | responded | dismissed


class ResponseAction(SQLModel, table=True):
    """Records every automated/manual response action taken, and its result."""
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=now, index=True)
    alert_id: Optional[int] = Field(default=None, index=True)
    action_type: str  # kill_process | quarantine_file | block_connection
    target: str  # pid, file path, or ip:port depending on action_type
    triggered_by: str = "auto"  # auto | manual
    status: str = "pending"  # pending | acknowledged | completed | failed
    detail: Optional[str] = None
