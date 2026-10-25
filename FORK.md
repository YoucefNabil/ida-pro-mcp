# Fork notes

Fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) for headless use (`idalib-mcp --stdio`). Needs IDA Professional 9.4 or later: importing the plugin on an older IDA raises an ImportError. 9.3 support was dropped. Keep it headless: don't make GUI modes the default or add GUI-only features.

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
- #542 `idb_save` stays available when a worker profile is applied
- #444 less timing flakiness in the worker lifecycle tests
- #544 `import_type_header` (parse a C header into local types)
- #469 `organize_functions` (put functions into folders)
- #456 `delete_stack` / `declare_stack` validate names, types and sizes before changing the frame. Fixed here: `get_udm_by_tid` returns an index (-1 on failure), not a bool, so deleting the first frame member failed.
- #500 `set_ignore_micro` (mark instructions the decompiler should skip). Fixed here: removing the backup comment passed `None` to `set_cmt`, which 9.4 rejects; docstring trimmed under the length limit. New tests in `test_api_modify.py`.
- #475 headless debugger: `--ext dbg` (or `IDA_MCP_EXT=dbg`) enables the `dbg_*` tools under idalib; `dbg_start` launches the database's input file with the local debugger (args from `IDA_MCP_DBG_ARGS`). Fixed here: `dbg_start` returned "running" before the entry breakpoint hit, so registers and stepping failed. It now waits until the process suspends at the entry point, on both start paths. Tested on whoami.exe: start, regs, step, exit.

Skipped: #551 (supervisor rewrite, +1484 lines, conflicts with the close-path changes here).

## Own changes
- `rename(func=...)` rejects an address inside a function (it used to rename the containing function). `containing=true` allows it.
- `idb_open` returns `pending=true` with the session ID after `IDA_MCP_OPEN_WAIT` seconds (default 20) while analysis continues. Calls on a pending session say "still analyzing"; `idb_list` shows it.
- Workers idle for `IDA_MCP_IDLE_TIMEOUT` seconds (default 7200, was 600) before exiting.
- With `--unsafe`, the first script tool call (`py_eval`, `exec_idapython`, `py_exec_file`) in a session first saves a copy of the database to `<idb folder>/ida-mcp-backups/<name>.<timestamp>.i64`. If the save fails, the script doesn't run. `IDA_MCP_SCRIPT_BACKUP=0` turns the backup off, and `IDA_MCP_SCRIPT_BACKUP_KEEP` sets how many copies to keep per database (default 5).
- `analyze_component` no longer fails on an address outside any function (regression from #555).
- IDA 9.4: workers open databases with `-dENABLE_INDEXER=YES` (9.4 turns the Jump Anywhere index off under idalib). `IDA_MCP_INDEXER=0` keeps it off. The index builds on the first search, so opening is not slower.
- IDA 9.4 tools (`api_ida94.py`): `fuzzy_search` (ranked search over functions, names, types, segments and function comments through `ida_indexer`) and `source_files` (compilation units from debug info, or which file holds an address). Databases built by 9.3 have no compilation units until reanalysed in 9.4.
- Deprecated IDA calls moved to the 9.4 APIs: frame calls take `func.start_ea` (`get_func_frame_ea`, `define_stkvar_ea`...), `get/set_func_cmt_ea`, `decompile_function`, and segments go through `utils.segment_at(ea)` / `segments()` (built on `segment_info_t`) in place of `getseg`. Still deprecated: `get_func()` / `func_t` (62 sites; IDA's own `idautils` uses it too) and calls made inside IDA's `idautils` / `idc`.
- Windows-safe liveness check in `tests/test_idalib_close.py`; `find_bytes` wildcard test.

## Install
```
uv tool install --force --editable "G:\_CLAUDE\ida-pro-mcp"
```
The MCP server entry is `idalib-mcp.exe --stdio --unsafe` with `IDADIR=C:\Program Files\IDA Professional 9.4`.

The official Hex-Rays server ([HexRaysSA/ida-mcp](https://github.com/HexRaysSA/ida-mcp)) is installed next to it as `hexrays-ida`: `uv tool install ida-mcp --python 3.11`, entry `ida-mcp.exe stdio --agent=claude` with `IDADIR` 9.4 and `IDA_NEXUS_IDALIB_ONLY=1` (headless, never starts the GUI). It saves the database when it closes it, and the two servers can't open the same IDB at once.

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
