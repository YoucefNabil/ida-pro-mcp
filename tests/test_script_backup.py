"""Script tools save a backup of the database before the first script in a session."""

from pathlib import Path

import pytest

from ida_pro_mcp import idalib_supervisor as supmod
from test_idalib_supervisor import _FakeSupervisor


class _BackupSupervisor(_FakeSupervisor):
    def __init__(self, save_ok=True):
        super().__init__()
        self.save_ok = save_ok

    def call_worker_tool(self, worker, name, arguments=None, *, timeout=None):
        if name == "idb_save" and arguments and arguments.get("path"):
            self.tool_calls.append((name, arguments))
            if not self.save_ok:
                return {"ok": False, "path": arguments["path"], "error": "disk full"}
            Path(arguments["path"]).write_bytes(b"idb")
            return {"ok": True, "path": arguments["path"]}
        return super().call_worker_tool(worker, name, arguments, timeout=timeout)

    def _worker_rpc(self, worker, payload, *, timeout=None):
        if payload.get("method") == "tools/call":
            self.forwarded.append(payload)
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "result": {"content": [{"type": "text", "text": "{}"}], "isError": False},
            }
        return super()._worker_rpc(worker, payload, timeout=timeout)


@pytest.fixture
def opened(monkeypatch, tmp_path):
    def make(save_ok=True):
        sample = tmp_path / "game.exe"
        sample.write_bytes(b"x")
        sup = _BackupSupervisor(save_ok)
        sup.open_session(str(sample), session_id="g")
        monkeypatch.setattr(supmod, "supervisor", sup)
        return sup, tmp_path / supmod.SCRIPT_BACKUP_DIRNAME

    return make


def _call(name, database="g"):
    return supmod._handle_tools_call(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": {"code": "1", "database": database}},
        }
    )["result"]


def _saves(sup):
    return [a for n, a in sup.tool_calls if n == "idb_save" and a and a.get("path")]


def test_first_script_backs_up_once(opened):
    sup, folder = opened()
    first = _call("py_eval")
    backups = list(folder.glob("game.exe.*.i64"))
    assert len(backups) == 1
    assert str(backups[0]) in first["content"][-1]["text"]

    second = _call("exec_idapython")
    assert len(_saves(sup)) == 1
    assert "backed up" not in second["content"][-1]["text"]
    assert len(sup.forwarded) == 2


def test_other_tools_never_back_up(opened):
    sup, folder = opened()
    _call("decompile")
    assert _saves(sup) == []
    assert not folder.exists()


def test_failed_backup_blocks_the_script(opened):
    sup, _ = opened(save_ok=False)
    result = _call("py_eval")
    assert result["isError"] is True
    assert "Script not run" in result["content"][0]["text"]
    assert "disk full" in result["content"][0]["text"]
    assert sup.forwarded == []


def test_backup_can_be_disabled(opened, monkeypatch):
    monkeypatch.setenv("IDA_MCP_SCRIPT_BACKUP", "0")
    sup, _ = opened()
    assert _call("py_eval")["isError"] is False
    assert _saves(sup) == []


def test_old_backups_are_pruned(opened, monkeypatch):
    monkeypatch.setenv("IDA_MCP_SCRIPT_BACKUP_KEEP", "2")
    sup, folder = opened()
    folder.mkdir()
    for stamp in ("20260101-000000", "20260102-000000", "20260103-000000"):
        (folder / f"game.exe.{stamp}.i64").write_bytes(b"old")
    _call("py_eval")
    names = sorted(p.name for p in folder.glob("game.exe.*.i64"))
    assert len(names) == 2
    assert names[0] == "game.exe.20260103-000000.i64"


def test_idb_input_path_is_backed_up_by_its_own_name(tmp_path):
    assert supmod.IdalibSupervisor._idb_path_for(str(tmp_path / "a.i64")).name == "a.i64"
    assert supmod.IdalibSupervisor._idb_path_for(str(tmp_path / "EBOOT.elf")).name == "EBOOT.elf.i64"
