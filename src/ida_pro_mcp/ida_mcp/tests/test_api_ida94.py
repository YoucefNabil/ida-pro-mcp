"""Tests for api_ida94 (IDA 9.4 indexer and compilation units)."""

from ..api_ida94 import fuzzy_search, indexer_available, source_files
from ..framework import assert_error, skip_test, test


def _need_indexer():
    ok, why = indexer_available()
    if not ok:
        skip_test(why)


@test()
def test_fuzzy_search_finds_main():
    _need_indexer()
    [res] = fuzzy_search("main")
    assert "error" not in res, res
    top = res["hits"][0]
    assert top["name"] == "main" and top["kind"] == "functions", top
    assert top["addr"].startswith("0x")
    scores = [h["score"] for h in res["hits"]]
    assert scores == sorted(scores, reverse=True)


@test()
def test_fuzzy_search_kind_filter_and_limit():
    _need_indexer()
    [res] = fuzzy_search(["main"], kinds="names", limit=2)
    assert len(res["hits"]) <= 2
    assert all(h["kind"] == "names" for h in res["hits"]), res


@test()
def test_fuzzy_search_batch_and_bad_kind():
    _need_indexer()
    out = fuzzy_search(["main", "start"])
    assert [r["query"] for r in out] == ["main", "start"]
    [bad] = fuzzy_search("main", kinds=["nope"])
    assert_error(bad, contains="Unknown kind")


@test(binary="typed_fixture.elf")
def test_fuzzy_search_types_have_ordinal():
    _need_indexer()
    [res] = fuzzy_search("Point", kinds="types")
    hit = next(h for h in res["hits"] if h["name"] == "Point")
    assert hit["type_ordinal"] > 0 and "addr" not in hit


@test()
def test_fuzzy_search_fuzzy_mode():
    _need_indexer()
    [res] = fuzzy_search("mn", kinds="functions", fuzzy=True, limit=50)
    assert "error" not in res and isinstance(res["hits"], list)


@test(binary="typed_fixture.elf")
def test_source_files_lists_dwarf_units():
    res = source_files(count=5)
    assert res["total_files"] > 0, res
    assert 0 < len(res["files"]) <= 5
    row = res["files"][0]
    assert row["ranges"] > 0 and row["bytes"] > 0 and row["first"].startswith("0x")
    one = source_files(filter="*start*", count=0)
    assert all("start" in r["file"] for r in one["files"])


@test(binary="typed_fixture.elf")
def test_source_files_lookup():
    first = source_files(count=1)["files"][0]
    res = source_files(addrs=[first["first"], "not_a_symbol_xyz"])
    hit, bad = res["lookups"]
    assert hit["file"] == first["file"] and hit["start"] == first["first"], hit
    assert bad["file"] is None and "error" in bad
