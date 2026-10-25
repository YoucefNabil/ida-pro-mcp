"""Switches passed to idapro.open_database. Imports nothing from ida_mcp, so it
is safe to use before a database is open."""

import os


def idalib_open_args() -> str | None:
    """Extra IDA switches for idapro.open_database.

    IDA turns its name/type index (Jump Anywhere, used by fuzzy_search) off in
    batch mode, which includes idalib. Turn it back on; the index is built on
    the first search, so opening is not slower. IDA_MCP_INDEXER=0 keeps it off.
    """
    if os.environ.get("IDA_MCP_INDEXER", "1").strip().lower() in ("0", "false", "no", "off"):
        return None
    return "-dENABLE_INDEXER=YES"
