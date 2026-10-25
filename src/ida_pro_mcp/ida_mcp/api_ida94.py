"""Tools built on IDA 9.4 APIs: the Jump Anywhere index and compilation units."""

from typing import Annotated, NotRequired, TypedDict

import ida_funcs
import ida_idaapi
import ida_indexer
import ida_lines
import ida_range
import idautils

from .rpc import tool
from .sync import idasync
from .utils import normalize_list_input, paginate, parse_address, pattern_filter

# Sub-index names accepted by fuzzy_search, mapped to ida_indexer constants.
_KIND_ATTRS = {
    "functions": "SUBIDX_FUNCTIONS",
    "names": "SUBIDX_NAMES",
    "types": "SUBIDX_LTYPES",
    "segments": "SUBIDX_SEGMENTS",
    "func_comments": "SUBIDX_FUNCTION_COMMENTS",
    "rep_func_comments": "SUBIDX_REPEATABLE_FUNCTION_COMMENTS",
}


def _kind_ids() -> dict[str, int]:
    return {k: getattr(ida_indexer, a) for k, a in _KIND_ATTRS.items()}


class FuzzyHit(TypedDict):
    kind: str
    name: str
    score: int
    addr: NotRequired[str]
    type_ordinal: NotRequired[int]


class FuzzySearchResult(TypedDict):
    query: str
    hits: list[FuzzyHit]
    error: NotRequired[str]


def indexer_available() -> tuple[bool, str | None]:
    if not ida_indexer.indexer_is_enabled():
        return False, (
            "The IDA indexer is off for this database. idalib workers turn it on "
            "when they open a database unless IDA_MCP_INDEXER=0; "
            "reopen the database (idb_close, then idb_open) to enable it."
        )
    return True, None


@tool
@idasync
def fuzzy_search(
    queries: Annotated[list[str] | str, "Search text(s), e.g. 'ragdoll' or 'CPed::Update'"],
    kinds: Annotated[
        list[str] | str | None,
        "Limit to: functions, names, types, segments, func_comments, rep_func_comments (default: all)",
    ] = None,
    fuzzy: Annotated[bool, "Subsequence matching (finds 'sumpt' in sum_point); default is ranked substring matching"] = False,
    limit: Annotated[int, "Max hits per query (default 20, max 500)"] = 20,
    min_score: Annotated[int, "Drop hits scoring below this (0-100)"] = 0,
) -> list[FuzzySearchResult]:
    """Ranked search across function names, global names, local types, segments
    and function comments, using IDA 9.4's Jump Anywhere index. Best hits come
    first with a 0-100 score. Use it when you only know part of a name; use
    lookup_funcs or entity_query when you need exact or regex matching.
    """
    ok, why = indexer_available()
    query_list = [q for q in normalize_list_input(queries) if str(q).strip()]
    if not ok:
        return [{"query": q, "hits": [], "error": why} for q in query_list]

    ids = _kind_ids()
    names_by_id = {v: k for k, v in ids.items()}
    wanted = normalize_list_input(kinds) if kinds else []
    bad = [k for k in wanted if k not in ids]
    if bad:
        err = f"Unknown kind(s) {bad}; use {sorted(ids)}"
        return [{"query": q, "hits": [], "error": err} for q in query_list]

    cfg = ida_indexer.match_config_t()
    cfg.mode = ida_indexer.FUZZY if fuzzy else ida_indexer.STR_MATCH
    cfg.max_results = max(1, min(int(limit), 500))
    cfg.score_cutoff = max(0, min(int(min_score), 100))

    results: list[FuzzySearchResult] = []
    for q in query_list:
        q = str(q)
        sets = (
            [ida_indexer.indexer_match(ids[k], q, cfg) for k in wanted]
            if wanted
            else [ida_indexer.indexer_match_all(q, cfg)]
        )
        hits: list[FuzzyHit] = []
        for rs in sets:
            if rs is None:
                continue
            for i in range(rs.size()):
                kind = names_by_id.get(rs.get_subindex(i), str(rs.get_subindex(i)))
                hit: FuzzyHit = {"kind": kind, "name": rs.get_name(i), "score": rs.get_score(i)}
                if kind == "types":
                    hit["type_ordinal"] = rs.get_ltype_ordinal(i)
                else:
                    ea = rs.get_ea(i)
                    if ea != ida_idaapi.BADADDR:
                        hit["addr"] = hex(ea)
                hits.append(hit)
        hits.sort(key=lambda h: -h["score"])
        results.append({"query": q, "hits": hits[: cfg.max_results]})
    return results


class SourceFile(TypedDict):
    file: str
    ranges: int
    bytes: int
    funcs: int
    first: str


class SourceFileLookup(TypedDict):
    addr: str
    file: str | None
    start: NotRequired[str]
    end: NotRequired[str]
    func: NotRequired[str]
    error: NotRequired[str]


class SourceFilesResult(TypedDict, total=False):
    total_files: int
    files: list[SourceFile]
    next_offset: int | None
    lookups: list[SourceFileLookup]
    error: str


def _collect_source_files() -> dict[str, dict]:
    files: dict[str, dict] = {}
    info = ida_lines.sourcefile_info_t()
    for n in range(ida_lines.get_sourcefiles_qty()):
        if not ida_lines.getn_sourcefile(info, n):
            continue
        r = info.range
        f = files.setdefault(info.filename, {"ranges": 0, "bytes": 0, "funcs": 0, "first": r.start_ea})
        f["ranges"] += 1
        f["bytes"] += r.end_ea - r.start_ea
        f["first"] = min(f["first"], r.start_ea)
    for ea in idautils.Functions():
        name = ida_lines.get_sourcefile_by_ea(ea)
        if name in files:
            files[name]["funcs"] += 1
    return files


@tool
@idasync
def source_files(
    filter: Annotated[str, "Substring, glob (*.cpp) or /regex/ on the file path; empty = all"] = "",
    addrs: Annotated[list[str] | str | None, "Instead of listing, report which source file contains each address"] = None,
    offset: Annotated[int, "Pagination offset"] = 0,
    count: Annotated[int, "Files per page (0 = all, default 100)"] = 100,
) -> SourceFilesResult:
    """List the compilation units (source files) the loader recovered from debug
    info (DWARF, PDB, COFF, TDS, OMF, PSX, Go), with range, byte and function
    counts per file, or find the source file containing given addresses. Empty
    when the binary has no such info. IDA 9.4 groups the Functions list by these.
    """
    if addrs:
        lookups: list[SourceFileLookup] = []
        for a in normalize_list_input(addrs):
            try:
                ea = parse_address(a)
            except Exception as e:
                lookups.append({"addr": str(a), "file": None, "error": str(e)})
                continue
            r = ida_range.range_t()
            name = ida_lines.get_sourcefile_by_ea(ea, r)
            item: SourceFileLookup = {"addr": hex(ea), "file": name}
            if name:
                item["start"] = hex(r.start_ea)
                item["end"] = hex(r.end_ea)
            fn = ida_funcs.get_func(ea)
            if fn:
                item["func"] = ida_funcs.get_func_name(fn.start_ea) or hex(fn.start_ea)
            lookups.append(item)
        return {"lookups": lookups}

    files = _collect_source_files()
    rows: list[SourceFile] = [
        {"file": k, "ranges": v["ranges"], "bytes": v["bytes"], "funcs": v["funcs"], "first": hex(v["first"])}
        for k, v in sorted(files.items(), key=lambda kv: kv[1]["first"])
    ]
    rows = pattern_filter(rows, "" if filter in ("", "*") else filter, "file")
    page = paginate(rows, max(0, offset), max(0, count))
    return {"total_files": len(rows), "files": page["data"], "next_offset": page["next_offset"]}
