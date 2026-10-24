"""idb_open returns a pending session while a slow analysis carries on."""

import threading

import pytest

from ida_pro_mcp import idalib_supervisor as supmod
from test_idalib_supervisor import _FakeSupervisor


class _SlowSupervisor(_FakeSupervisor):
    """The worker's idb_open blocks until the test releases it."""

    def __init__(self, fail: str | None = None):
        super().__init__()
        self.release = threading.Event()
        self.fail = fail

    def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
        if name == "idb_open":
            assert self.release.wait(10), "test never released the open"
            if self.fail:
                raise RuntimeError(self.fail)
        return super().call_worker_tool(worker, name, arguments, timeout=timeout)


@pytest.fixture
def slow(monkeypatch):
    def make(fail=None, wait=0.05):
        sup = _SlowSupervisor(fail)
        monkeypatch.setattr(supmod, "supervisor", sup)
        monkeypatch.setattr(supmod, "OPEN_WAIT_SEC", wait)
        return sup

    return make


def _call(database):
    return supmod._handle_tools_call(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "decompile",
                "arguments": {"addr": "0x1000", "database": database},
            },
        }
    )


def _wait_done(sup, session_id):
    pending = sup.find_pending(session_id)
    if pending is not None:
        assert pending.done.wait(5)


def test_slow_open_returns_pending_then_ready(slow, tmp_path):
    sample = tmp_path / "big.exe"
    sample.write_bytes(b"x")
    sup = slow()

    first = supmod.idb_open(str(sample), preferred_session_id="big")
    assert first["success"] is True and first["pending"] is True
    assert first["session"]["session_id"] == "big"

    busy = _call("big")
    assert busy["result"]["isError"] is True
    assert "still analyzing" in busy["result"]["content"][0]["text"]

    listed = supmod.idb_list()["sessions"]
    assert [s["session_id"] for s in listed if s["is_analyzing"]] == ["big"]

    # A second idb_open for the same path joins the running open.
    again = supmod.idb_open(str(sample))
    assert again["pending"] is True and again["session"]["session_id"] == "big"

    sup.release.set()
    _wait_done(sup, "big")

    ready = supmod.idb_open(str(sample))
    assert ready["success"] is True and "pending" not in ready
    assert ready["session"]["session_id"] == "big"
    assert _call("big")["result"] == {"ok": True}
    assert sum(1 for name, _ in sup.tool_calls if name == "idb_open") == 1


def test_failed_background_open_reports_error_once(slow, tmp_path):
    sample = tmp_path / "bad.exe"
    sample.write_bytes(b"x")
    sup = slow(fail="Failed to open database")

    assert supmod.idb_open(str(sample), preferred_session_id="bad")["pending"] is True
    sup.release.set()
    _wait_done(sup, "bad")

    failed = _call("bad")
    assert failed["result"]["isError"] is True
    assert "Failed to open database" in failed["result"]["content"][0]["text"]
    # Reported once; afterwards the ID is simply unknown.
    assert "Session not found" in _call("bad")["result"]["content"][0]["text"]


def test_fast_open_returns_session_directly(slow, tmp_path):
    sample = tmp_path / "small.exe"
    sample.write_bytes(b"x")
    sup = slow(wait=5)
    sup.release.set()

    result = supmod.idb_open(str(sample), preferred_session_id="small")
    assert result["success"] is True and "pending" not in result
    assert result["session"]["session_id"] == "small"


def test_close_refuses_a_session_still_opening(slow, tmp_path):
    sample = tmp_path / "big.exe"
    sample.write_bytes(b"x")
    sup = slow()
    supmod.idb_open(str(sample), preferred_session_id="big")
    try:
        assert "still opening" in supmod.idb_close("big")["error"]
    finally:
        sup.release.set()
        _wait_done(sup, "big")


def test_idb_open_uses_idle_timeout_env_default(slow, tmp_path, monkeypatch):
    sample = tmp_path / "small.exe"
    sample.write_bytes(b"x")
    monkeypatch.setenv("IDA_MCP_IDLE_TIMEOUT", "1234")
    sup = slow(wait=5)
    sup.release.set()
    supmod.idb_open(str(sample))
    assert sup.opened[0][1]["idle_ttl_sec"] == 1234
