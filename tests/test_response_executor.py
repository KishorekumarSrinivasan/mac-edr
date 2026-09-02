"""Unit tests for response actions -- pure logic, no real kill/quarantine
against the test-runner's own filesystem/processes."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))


def test_kill_process_invalid_target():
    from response.executor import kill_process
    success, detail = kill_process("not-a-pid")
    assert success is False
    assert "invalid pid" in detail


def test_kill_process_already_gone():
    from response.executor import kill_process
    # PID unlikely to exist
    success, detail = kill_process("999999")
    assert success is True
    assert "already gone" in detail


def test_quarantine_missing_file():
    from response.executor import quarantine_file
    success, detail = quarantine_file("/nonexistent/file/path.txt")
    assert success is False
    assert "not found" in detail


def test_quarantine_moves_file(monkeypatch, tmp_path):
    import response.executor as executor
    monkeypatch.setattr(executor, "QUARANTINE_DIR", str(tmp_path / "quarantine"))

    src = tmp_path / "malicious.txt"
    src.write_text("bad stuff")

    success, detail = executor.quarantine_file(str(src))
    assert success is True
    assert not src.exists()
    assert os.path.isdir(str(tmp_path / "quarantine"))


def test_block_connection_rejects_bad_target():
    from response.executor import block_connection
    success, detail = block_connection("not-an-ip-port")
    assert success is False
