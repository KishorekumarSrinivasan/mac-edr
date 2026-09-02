import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

_fd, _path = tempfile.mkstemp(suffix=".db")
os.close(_fd)
os.environ["EDR_DB_PATH"] = _path

from app.database import engine, init_db  # noqa: E402
from sqlmodel import Session as SQLSession, SQLModel  # noqa: E402

init_db()


@pytest.fixture
def session():
    """Truncates all tables before each test so tests stay isolated
    without re-registering SQLModel classes (which SQLAlchemy forbids)."""
    with engine.begin() as conn:
        for table in reversed(SQLModel.metadata.sorted_tables):
            conn.execute(table.delete())
    with SQLSession(engine) as s:
        yield s
