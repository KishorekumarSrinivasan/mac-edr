"""Database engine + session management."""
import os
from sqlmodel import SQLModel, Session, create_engine

DB_PATH = os.environ.get("EDR_DB_PATH", "edr.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

# check_same_thread=False: FastAPI may use the connection from different
# threads (request handlers + background detection loop). We serialize
# writes ourselves rather than relying on SQLite's default thread guard.
engine = create_engine(
    DATABASE_URL,
    echo=False,
    connect_args={"check_same_thread": False},
)


def init_db() -> None:
    # WAL mode lets readers (dashboard polling) proceed while a writer
    # (agent ingestion / detection engine) is mid-transaction, instead of
    # blocking each other on the single-file journal — this is the fix
    # for the SQLite read/write contention hit in v1.
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
        conn.exec_driver_sql("PRAGMA busy_timeout=5000;")
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
