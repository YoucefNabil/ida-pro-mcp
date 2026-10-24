# Fork notes

Private fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) for headless use (`idalib-mcp --stdio`) with IDA Professional 9.3. The official Hex-Rays server needs IDA 9.4+, so this fork stays on mrexodia's code. Keep it headless: don't make GUI modes the default or add GUI-only features.

Base: upstream `c133c38` (2026-09-26).

## Upstream PRs merged (open upstream when merged here)
- #543 empty batch stays empty
- #537 JSON-string arguments decoded for dict/list parameters (rename batches)
- #541 stdio proxy answers malformed JSON-RPC instead of dropping the connection
- #527 Windows: `stop()` no longer blocks on an idle keep-alive connection
- #554 `idb_close(save=false)` really discards
- #555 call edges found on any processor (PS3 PowerPC, ARM), not just x86
- #556 `set_name` never opens a modal dialog; mutation lock; `exec_idapython` (unsafe, off without `--unsafe`)
- #484 `list_funcs` / `func_query` / `entity_query` page without scanning the whole database
- #501 `--idle-timeout` / `IDA_MCP_IDLE_TIMEOUT`
- #473 `struct_member_upsert`
- #451 relocation tools (runtime base vs IDB base, for ASLR)

## Own changes
- `rename(func=...)` rejects an address inside a function (it used to rename the containing function). `containing=true` allows it.
- `idb_open` returns `pending=true` with the session ID after `IDA_MCP_OPEN_WAIT` seconds (default 20) while analysis continues. Calls on a pending session say "still analyzing"; `idb_list` shows it.
- Workers idle for `IDA_MCP_IDLE_TIMEOUT` seconds (default 7200, was 600) before exiting.
- `analyze_component` no longer fails on an address outside any function (regression from #555).
- Windows-safe liveness check in `tests/test_idalib_close.py`; `find_bytes` wildcard test.

## Install
```
uv tool install --force --editable "G:\_CLAUDE\ida-pro-mcp"
```
The MCP server entry is `idalib-mcp.exe --stdio` with `IDADIR=C:\Program Files\IDA Professional 9.3`.

## Tests
```
uv run --with pytest python -m pytest tests -q            # set IDADIR for test_idalib_close.py
uv run ida-mcp-test tests/crackme03.elf -q
uv run ida-mcp-test tests/typed_fixture.elf -q
```

## Syncing upstream
```
git fetch upstream && git merge upstream/main
```
Drop a PR's commit from this list once upstream merges it.
