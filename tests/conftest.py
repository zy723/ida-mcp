from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest

_STATE_DIR = Path(tempfile.mkdtemp(prefix="ida-mcp-tests-"))
_NEXUS_STATE_DIR = _STATE_DIR / "nexus"
_MCP_STATE_DIR = _STATE_DIR / "mcp"
os.environ["IDA_NEXUS_STATE_DIR"] = str(_NEXUS_STATE_DIR)
os.environ["IDA_MCP_STATE_DIR"] = str(_MCP_STATE_DIR)


@pytest.fixture(autouse=True)
def clean_session_state() -> Iterator[None]:
    dirs = [
        _NEXUS_STATE_DIR / name for name in ("instances", "spawn", "logs", "sessions")
    ]
    dirs.append(_MCP_STATE_DIR / "sessions")
    for directory in dirs:
        shutil.rmtree(directory, ignore_errors=True)
    yield
    for directory in dirs:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.fixture
def _quiet_trace(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep the mcp.py TRACE singleon from touching disk in pro tests.

    clean_session_state wipes the sessions dir after each test; the TRACE
    singleon's _TraceLogger keeps one fixed path under it, so a tool_call
    emitted from a later test falls into a FileNotFoundError on os.open.
    The wrapper tests (and test_mcp.py) stub TRACE the same way.
    """
    import ida_mcp.mcp as mcp_api

    monkeypatch.setattr(
        mcp_api, "TRACE", type("T", (), {"emit": staticmethod(lambda *a, **k: None)})()
    )
    yield


def pytest_sessionfinish(session: object, exitstatus: int) -> None:
    del session, exitstatus
    shutil.rmtree(_STATE_DIR, ignore_errors=True)
