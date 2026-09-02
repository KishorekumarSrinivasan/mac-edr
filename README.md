# Mac EDR

A from-scratch Endpoint Detection & Response system for macOS: a Python agent
with 5 collectors, a FastAPI/SQLModel backend with a rule-based detection
engine, automated response actions (kill / quarantine / block), and a React
dashboard.

This is v2 of the project — rebuilt from the v1 design doc with two additions
scoped in from the start: **automated response** and a **test suite / CI**.
Apple's Endpoint Security Framework (ESF) is scoped as phase 2 (see below).

## Architecture

```
Mac Agent (Python)  --HTTP-->  Backend (FastAPI)  --SQLite-->  edr.db
  5 collectors                   Detection Engine (5 rules, every 30s)
  + response executor            queues ResponseAction on match
        ^                               |
        |--- polls /response/pending ---|
        |                               v
                                  Dashboard (React, polls 5s)
                                  /alerts /processes /network /response
```

New in v2: the detection engine can queue a `ResponseAction` (kill process /
quarantine file / block connection). The **agent**, not the backend, executes
it — the backend has no privileged access to the endpoint, only the agent
running on the Mac does. This mirrors how real EDR consoles issue commands
that the endpoint agent carries out locally.

## Project layout

```
backend/    FastAPI app, SQLModel tables, detection engine, response API
agent/      Collectors + response executor, runs directly on your Mac
dashboard/  React + Vite dashboard
tests/      pytest suite covering detection rules, hashing, response actions
.github/workflows/ci.yml   GitHub Actions: lint + test on push
```

## Setup (run this on your Mac, not in a cloud sandbox — the agent needs
real macOS APIs)

### 1. Backend

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend runs at `http://127.0.0.1:8000`. Visit `/` for a health check, `/docs`
for the interactive API.

### 2. Agent

In a second terminal:

```bash
cd agent
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

The agent starts all 5 collectors + the response executor. You'll likely be
prompted by macOS for permissions (Full Disk Access for `log stream`,
possibly others) — grant them to your terminal app in
System Settings → Privacy & Security.

Automated response is **off by default**. To let the agent actually execute
queued kill/quarantine/block actions automatically:

```bash
EDR_ENABLE_AUTO_RESPONSE=1 python3 main.py
```

With it off, actions still get queued and acknowledged, but wait for you to
trigger them manually via the dashboard or `/response/trigger`.
`block_connection` uses `pfctl` and needs `sudo`; run the agent with
`sudo -E python3 main.py` if you want that action to actually work.

### 3. Dashboard

In a third terminal:

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:5173`.

### 4. Verify end-to-end (EICAR test)

```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar_test.txt
```

Use `printf`, not `echo` — `echo` interprets backslashes and adds a trailing
newline, silently changing the file's bytes so the hash won't match (this bit
v1; there's a regression test for it in `tests/test_hash_monitor.py`).

Within ~1s you should see a CRITICAL `MALWARE_HASH_MATCH` alert on the
dashboard, and — if auto-response is on — the file quarantined to
`~/.mac_edr_quarantine/`.

## Tests

```bash
pip install -r backend/requirements.txt -r agent/requirements.txt
python3 -m pytest tests/ -v
```

19 tests covering: each detection rule's trigger/non-trigger condition, the
dedup/cooldown behavior (the exact bug class v1 hit — a rule re-firing every
cycle), the auto-response policy allowlist, hash matching (including the
`echo`-byte-mangling regression), and the response executor's action logic.

CI (`.github/workflows/ci.yml`) runs lint (`ruff`) + this suite on every push.

## What's new vs. v1

- **Automated response.** The detection engine now queues actions
  (`kill_process`, `quarantine_file`, `block_connection`) via an explicit
  per-rule allowlist (`AUTO_RESPONSE_POLICY` in `backend/app/detection/engine.py`)
  — not every alert auto-responds, only the ones deliberately opted in
  (malware hash match → quarantine, suspicious port → block). Everything else
  stays alert-only pending human review. All actions are logged to a
  `ResponseAction` table with full audit trail (pending → acknowledged →
  completed/failed), whether triggered automatically or manually from the
  dashboard.
- **Tests + CI.** 19 pytest tests target the specific bug classes v1 hit in
  practice (dedup flooding, hash byte-mangling), not just happy-path coverage.
- **WAL mode from day one** for the SQLite connection, since v1 hit
  read/write contention between the agent's writes and the dashboard's polls.

## Phase 2 (not built yet): Apple Endpoint Security Framework

Right now, like v1, this uses `psutil`/`watchdog`/`log stream` — user-space
APIs layered on `ps`/`lsof`/FSEvents/Unified Logging. The single change that
would make this closest to how a real EDR vendor's agent works is swapping
to Apple's **Endpoint Security Framework (ESF)**: a kernel-level API that
delivers process exec/fork/exit, file, and other security events directly,
with far fewer blind spots than polling.

This needs, and is blocked on:

1. **An Apple Developer Program account** ($99/year) — required to request
   the `com.apple.developer.endpoint-security.client` entitlement from Apple,
   and to code-sign the resulting binary (ESF clients must be signed).
2. **A native helper**, since ESF has no Python bindings — either a small
   signed Swift/Objective-C binary that streams events to the Python agent
   over a local socket, or `pyEndpointSecurity`-style bindings if we decide
   that path is stable enough.
3. Design decision: keep the Python agent as the "brain" (backend
   communication, detection triggers) and have it shell out to / read from
   a thin native ESF listener process, rather than rewriting the whole agent
   in Swift.

Not started — flagging it here so it's an explicit next milestone once you
have (or decide to get) the developer account, rather than something we
silently deferred.
