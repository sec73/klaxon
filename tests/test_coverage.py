# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Coverage against two denominators, because one of them always misleads.

Measured on a live instance: `event.action` covered 8.1% of the whole
network-activity datastream, 71.0% of the last 24 hours and 100% of the last
12 — a decoder fix had landed that morning. Every number correct, and any one
of them alone a false report. These tests pin that both are always shown, that
a divergence is called out, and that a field at 0% survives every filter and
sort on its way to the output.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from klaxon_mcp import coverage, server
from klaxon_mcp.clients import Response
from klaxon_mcp.coverage import (
    CATEGORY_COMPLETE,
    CATEGORY_NEVER,
    CATEGORY_PARTIAL,
    CATEGORY_SPARSE,
    CoverageRow,
    apply_min_docs,
    build_rows,
    drift_notice,
    sort_rows,
    window_query,
)
from klaxon_mcp.fields import (
    FieldInfo,
    count_documents,
    parse_field_mappings,
    parse_total,
    source_has_path,
)
from klaxon_mcp.server import field_coverage

INDEX = "wazuh-events-v5-network-activity*"

# The live measurement this tool was built from.
DATASTREAM_DOCS = 10_238_381
WINDOW_DOCS = 348_247


def row(
    name: str = "event.action",
    type_label: str = "keyword",
    window_docs: int = 0,
    window_total: int = WINDOW_DOCS,
    total_docs: int = 0,
    grand_total: int = DATASTREAM_DOCS,
    unindexed: bool = False,
    partially_indexed: bool = False,
    doc_values_disabled: bool = False,
    sample_hits: int | None = None,
    sample_size: int | None = None,
) -> CoverageRow:
    return CoverageRow(
        name=name,
        type_label=type_label,
        window_docs=window_docs,
        window_total=window_total,
        total_docs=total_docs,
        grand_total=grand_total,
        unindexed=unindexed,
        partially_indexed=partially_indexed,
        doc_values_disabled=doc_values_disabled,
        sample_hits=sample_hits,
        sample_size=sample_size,
    )


# --------------------------------------------------------------------------- #
# The two denominators
# --------------------------------------------------------------------------- #


class TestTwoMeasurements:
    def test_the_live_case_is_reproduced(self) -> None:
        """8.1% overall and 71.0% in the window, from the same field."""
        measured = row(
            window_docs=247_255, total_docs=829_309
        )  # 71.0% and 8.1% respectively
        assert measured.window_pct is not None
        assert measured.total_pct is not None
        assert round(measured.window_pct, 1) == 71.0
        assert round(measured.total_pct, 1) == 8.1

    def test_both_reach_the_table(self) -> None:
        out = coverage.render_rows([row(window_docs=247_255, total_docs=829_309)], True)
        assert "71.0%" in out
        assert "8.1%" in out

    def test_drift_is_the_difference_in_points(self) -> None:
        measured = row(window_docs=WINDOW_DOCS, total_docs=829_309)
        assert measured.drift is not None
        assert round(measured.drift, 1) == 91.9

    def test_an_empty_window_yields_no_percentage(self) -> None:
        """No denominator, no number — and above all no division by zero."""
        measured = row(window_total=0, total_docs=100)
        assert measured.window_pct is None
        assert measured.drift is None
        assert measured.total_pct is not None


class TestPercentageLabels:
    def test_near_total_never_prints_as_complete(self) -> None:
        """10,238,000 of 10,238,381 is 99.996% — printing 100.0% is a claim."""
        measured = row(total_docs=10_238_000, grand_total=DATASTREAM_DOCS)
        assert measured.total_label == "99.9%"

    def test_exactly_total_prints_as_complete(self) -> None:
        measured = row(total_docs=DATASTREAM_DOCS, grand_total=DATASTREAM_DOCS)
        assert measured.total_label == "100.0%"

    def test_a_present_value_never_prints_as_zero(self) -> None:
        """0.0% is this table's notation for 'never populated'."""
        measured = row(
            window_docs=12,
            window_total=DATASTREAM_DOCS,
            total_docs=12,
            grand_total=DATASTREAM_DOCS,
        )
        assert measured.window_label == "<0.1%"
        assert measured.total_label == "<0.1%"
        # Twelve documents is a populated field, however thin.
        assert measured.category == CATEGORY_SPARSE

    def test_a_thin_field_is_not_categorised_as_never(self) -> None:
        """The category reads the float, not the rounded label."""
        assert row(window_docs=1, window_total=10_000_000).category == CATEGORY_SPARSE

    def test_a_true_zero_prints_as_zero(self) -> None:
        assert row(total_docs=0).total_label == "0.0%"

    def test_an_absent_denominator_prints_as_missing(self) -> None:
        assert row(window_total=0).window_label == coverage.MISSING


class TestDriftNotice:
    def test_full_in_window_but_low_overall_is_flagged(self) -> None:
        """The required case: 100% now, 8.1% historically."""
        notice = drift_notice(
            [row(window_docs=WINDOW_DOCS, total_docs=829_309)], hours=24
        )
        assert notice is not None
        assert "[COVERAGE DRIFT]" in notice
        assert "event.action" in notice
        assert "100.0%" in notice
        assert "8.1%" in notice
        assert "change in normalisation" in notice

    def test_identical_numbers_produce_no_notice(self) -> None:
        """A window older than the datastream measures the same thing twice."""
        measured = row(
            window_docs=100, window_total=1000, total_docs=100, grand_total=1000
        )
        assert measured.drift == 0.0
        assert drift_notice([measured], hours=99_999) is None

    def test_a_small_difference_is_not_flagged(self) -> None:
        # 60% vs 50% — ten points, inside the threshold.
        measured = row(
            window_docs=600, window_total=1000, total_docs=500, grand_total=1000
        )
        assert not measured.drifted
        assert drift_notice([measured], hours=24) is None

    def test_a_drop_is_flagged_as_well_as_a_rise(self) -> None:
        """Coverage that fell is a regression, and just as much a finding."""
        measured = row(
            window_docs=100, window_total=1000, total_docs=900, grand_total=1000
        )
        notice = drift_notice([measured], hours=24)
        assert notice is not None
        assert "-80.0pp" in notice

    def test_an_empty_window_cannot_drift(self) -> None:
        assert drift_notice([row(window_total=0, total_docs=100)], hours=24) is None

    def test_many_drifting_fields_are_summarised_not_truncated(self) -> None:
        rows = [
            row(name=f"f{i}", window_docs=1000, window_total=1000, total_docs=0)
            for i in range(15)
        ]
        notice = drift_notice(rows, hours=24)
        assert notice is not None
        assert "15 field(s)" in notice
        assert "further field(s)" in notice


# --------------------------------------------------------------------------- #
# The zero row
# --------------------------------------------------------------------------- #


class TestNeverPopulated:
    def test_zero_coverage_is_its_own_category(self) -> None:
        assert row(window_docs=0, total_docs=0).category == CATEGORY_NEVER

    def test_it_survives_the_sort(self) -> None:
        rows = sort_rows(
            [
                row(name="agent.id", window_docs=0, total_docs=0),
                row(name="wazuh.agent.id", window_docs=WINDOW_DOCS, total_docs=1),
            ]
        )
        assert [r.name for r in rows] == ["wazuh.agent.id", "agent.id"]

    def test_it_is_not_filtered_by_default(self) -> None:
        rows = [row(name="agent.id", window_docs=0, total_docs=0)]
        kept, hidden = apply_min_docs(rows, 0)
        assert len(kept) == 1
        assert hidden == []

    def test_the_notice_names_the_trap(self) -> None:
        notice = coverage.never_populated_notice([row(window_docs=0, total_docs=0)])
        assert notice is not None
        assert "[MAPPED BUT NEVER POPULATED]" in notice
        assert "agent.id" in notice

    def test_min_docs_hides_it_but_reports_the_removal(self) -> None:
        rows = [
            row(name="agent.id", window_docs=0, total_docs=0),
            row(name="wazuh.agent.id", window_docs=5000, total_docs=9000),
        ]
        kept, hidden = apply_min_docs(rows, 1)
        assert [r.name for r in kept] == ["wazuh.agent.id"]
        assert [r.name for r in hidden] == ["agent.id"]

    def test_a_field_absent_from_the_probe_counts_as_zero(self) -> None:
        """The exists agg answers for every field asked about; a gap is a zero."""
        rows = build_rows(
            [FieldInfo(name="agent.id", types=["keyword"])],
            window_counts={},
            total_counts={},
            window_total=WINDOW_DOCS,
            grand_total=DATASTREAM_DOCS,
        )
        assert rows[0].window_docs == 0
        assert rows[0].category == CATEGORY_NEVER


class TestCategories:
    @pytest.mark.parametrize(
        ("docs", "expected"),
        [
            (1000, CATEGORY_COMPLETE),
            (995, CATEGORY_COMPLETE),
            (990, CATEGORY_COMPLETE),
            (989, CATEGORY_PARTIAL),
            (500, CATEGORY_PARTIAL),
            (499, CATEGORY_SPARSE),
            (1, CATEGORY_SPARSE),
            (0, CATEGORY_NEVER),
        ],
    )
    def test_bands(self, docs: int, expected: str) -> None:
        assert row(window_docs=docs, window_total=1000).category == expected

    def test_an_empty_window_falls_back_to_the_datastream(self) -> None:
        measured = row(window_total=0, total_docs=DATASTREAM_DOCS)
        assert measured.category == CATEGORY_COMPLETE


class TestQuery:
    def test_the_window_uses_the_v5_time_field(self) -> None:
        assert window_query(24) == {"range": {"@timestamp": {"gte": "now-24h"}}}


class TestCounting:
    def test_total_is_read_from_the_response(self) -> None:
        response = Response(
            200, json.dumps({"hits": {"total": {"value": 42, "relation": "eq"}}}), "u"
        )
        assert parse_total(response) == 42

    def test_an_unreadable_total_is_none_not_zero(self) -> None:
        assert parse_total(Response(200, "not json", "u")) is None
        assert parse_total(Response(200, json.dumps({"hits": {}}), "u")) is None


# --------------------------------------------------------------------------- #
# The tool
# --------------------------------------------------------------------------- #

MAPPED = {
    "event.action": {"keyword": {"type": "keyword"}},
    "source.ip": {"ip": {"type": "ip"}},
    "agent.id": {"keyword": {"type": "keyword"}},
}


def mapping_payload(
    declarations: dict[str, dict[str, Any]], indices: int = 1
) -> dict[str, Any]:
    """The real _mapping/field shape, including the last-segment key quirk."""
    return {
        f".ds-network-activity-{i:06d}": {
            "mappings": {
                name: {
                    "full_name": name,
                    "mapping": {name.split(".")[-1]: leaf},
                }
                for name, leaf in declarations.items()
            }
        }
        for i in range(1, indices + 1)
    }


class StubIndexer:
    """Answers _field_caps, _mapping/field, the counts, the probes and a sample."""

    def __init__(
        self,
        mapped: dict[str, Any] | None = None,
        window_total: int = WINDOW_DOCS,
        grand_total: int = DATASTREAM_DOCS,
        window_counts: dict[str, int] | None = None,
        total_counts: dict[str, int] | None = None,
        caps_status: int = 200,
        probe_status: int = 200,
        mapping: dict[str, Any] | None = None,
        mapping_status: int = 200,
        sample_docs: list[dict[str, Any]] | None = None,
        sample_status: int = 200,
    ) -> None:
        self.mapped = MAPPED if mapped is None else mapped
        self.window_total = window_total
        self.grand_total = grand_total
        self.window_counts = window_counts or {}
        self.total_counts = total_counts or {}
        self.caps_status = caps_status
        self.probe_status = probe_status
        # Default: every mapped field declared plainly, i.e. indexed.
        self.mapping = (
            mapping
            if mapping is not None
            else {name: {"type": "keyword"} for name in self.mapped}
        )
        self.mapping_status = mapping_status
        self.sample_docs = sample_docs or []
        self.sample_status = sample_status
        self.requests: list[tuple[str, Any]] = []

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Response:
        self.requests.append((path, params))
        if "_mapping/field" in path:
            return Response(
                self.mapping_status, json.dumps(mapping_payload(self.mapping)), path
            )
        return Response(
            self.caps_status, json.dumps({"fields": self.mapped}), path
        )

    async def post(self, path: str, body: Any = None) -> Response:
        self.requests.append((path, body))
        is_window = "range" in json.dumps(body.get("query", {}))
        total = self.window_total if is_window else self.grand_total
        aggs = body.get("aggs")

        if "_source" in body:
            return Response(
                self.sample_status,
                json.dumps({"hits": {"hits": [{"_source": d} for d in self.sample_docs]}}),
                path,
            )

        if not aggs:
            return Response(
                200,
                json.dumps({"hits": {"total": {"value": total, "relation": "eq"}}}),
                path,
            )

        if self.probe_status != 200:
            return Response(self.probe_status, json.dumps({"error": "probe"}), path)

        names = [
            spec["filter"]["exists"]["field"] for spec in aggs.values()
        ]
        source = self.window_counts if is_window else self.total_counts
        return Response(
            200,
            json.dumps(
                {
                    "hits": {"total": {"value": total, "relation": "eq"}},
                    "aggregations": {
                        f"f{i}": {"doc_count": source.get(name, 0)}
                        for i, name in enumerate(names)
                    },
                }
            ),
            path,
        )

    @property
    def probe_bodies(self) -> list[Any]:
        return [b for p, b in self.requests if isinstance(b, dict) and b.get("aggs")]


@pytest.fixture
def indexer() -> Iterator[Any]:
    previous = server._indexer

    def install(**kwargs: Any) -> StubIndexer:
        client = StubIndexer(**kwargs)
        server._indexer = client  # type: ignore[assignment]
        return client

    install()
    try:
        yield install
    finally:
        server._indexer = previous


@pytest.fixture(autouse=True)
def config() -> Iterator[None]:
    """A config with the documented defaults, so no environment is needed."""
    previous = server._config
    server._config = server.Config(
        indexer_url="https://indexer.example:9200",
        indexer_user="",
        indexer_password="",
        manager_url="",
        manager_user="",
        manager_password="",
        engine_url="",
        verify_ssl=False,
        timeout=60.0,
        schema_field_limit=200,
        schema_probe_batch=100,
        search_max_size=100,
        logtest_default_trace_level="ASSET_ONLY",
        logtest_default_space="custom",
    )
    try:
        yield
    finally:
        server._config = previous


class TestToolOutput:
    async def test_both_measurements_appear_per_field(self, indexer: Any) -> None:
        indexer(
            window_counts={"event.action": WINDOW_DOCS},
            total_counts={"event.action": 829_309},
        )
        out = await field_coverage(index=INDEX)
        assert "DOCS_WINDOW" in out
        assert "COVERAGE" in out
        assert "DATASTREAM" in out
        assert "100.0%" in out
        assert "8.1%" in out

    async def test_the_drift_notice_reaches_the_caller(self, indexer: Any) -> None:
        """T: full coverage in the window, low overall — the notice must appear."""
        indexer(
            window_counts={"event.action": WINDOW_DOCS},
            total_counts={"event.action": 829_309},
        )
        out = await field_coverage(index=INDEX)
        assert "[COVERAGE DRIFT]" in out
        assert out.startswith("=== DIAGNOSTICS")

    async def test_a_zero_field_is_in_the_output(self, indexer: Any) -> None:
        """T: 0% is printed, not filtered."""
        indexer(
            window_counts={"event.action": WINDOW_DOCS},
            total_counts={"event.action": 829_309},
        )
        out = await field_coverage(index=INDEX)
        assert "agent.id" in out
        assert CATEGORY_NEVER in out
        assert "[MAPPED BUT NEVER POPULATED]" in out

    async def test_identical_windows_produce_no_drift_notice(
        self, indexer: Any
    ) -> None:
        """T: hours older than the datastream — both numbers agree."""
        client = indexer(
            window_total=DATASTREAM_DOCS,
            window_counts={"event.action": 829_309, "source.ip": DATASTREAM_DOCS},
            total_counts={"event.action": 829_309, "source.ip": DATASTREAM_DOCS},
        )
        out = await field_coverage(index=INDEX, hours=99_999)
        assert "[COVERAGE DRIFT]" not in out
        assert "+0.0pp" in out
        assert client.probe_bodies  # the window pass really ran

    async def test_the_window_probe_is_scoped_to_the_window(self, indexer: Any) -> None:
        client = indexer()
        await field_coverage(index=INDEX, hours=6)
        queries = [b["query"] for b in client.probe_bodies]
        assert {"match_all": {}} in queries
        assert {"range": {"@timestamp": {"gte": "now-6h"}}} in queries

    async def test_both_probe_passes_ask_for_exact_counts(self, indexer: Any) -> None:
        client = indexer()
        await field_coverage(index=INDEX)
        assert all(b["track_total_hits"] is True for b in client.probe_bodies)

    async def test_the_prefix_narrows_field_caps(self, indexer: Any) -> None:
        client = indexer()
        await field_coverage(index=INDEX, prefix="source.")
        caps_params = [p for path, p in client.requests if "_field_caps" in path]
        assert caps_params == [{"fields": "source.*"}]

    async def test_the_status_legend_is_included(self, indexer: Any) -> None:
        indexer()
        out = await field_coverage(index=INDEX)
        assert "STATUS:" in out
        for name in (
            CATEGORY_COMPLETE,
            CATEGORY_PARTIAL,
            CATEGORY_SPARSE,
            CATEGORY_NEVER,
        ):
            assert name in out


class TestEmptyWindow:
    async def test_it_is_reported_and_nothing_is_divided_by_zero(
        self, indexer: Any
    ) -> None:
        """T: an empty window is named, and no percentage is invented for it."""
        indexer(window_total=0, total_counts={"event.action": 829_309})
        out = await field_coverage(index=INDEX, hours=2)
        assert "[EMPTY WINDOW]" in out
        assert "2h" in out
        # The datastream half is still measured and reported.
        assert "8.1%" in out

    async def test_the_window_probe_is_skipped(self, indexer: Any) -> None:
        client = indexer(window_total=0)
        await field_coverage(index=INDEX)
        queries = [b["query"] for b in client.probe_bodies]
        assert queries == [{"match_all": {}}]

    async def test_an_empty_index_is_not_a_table_of_zeros(self, indexer: Any) -> None:
        indexer(window_total=0, grand_total=0)
        out = await field_coverage(index=INDEX)
        assert "[NO DOCUMENTS]" in out
        assert CATEGORY_NEVER not in out


class TestTruncation:
    async def test_the_cap_is_reported(self, indexer: Any) -> None:
        """T: more fields than the limit — the cap must be stated, not silent."""
        indexer(mapped={f"f{i:04d}": {"keyword": {"type": "keyword"}} for i in range(250)})
        out = await field_coverage(index=INDEX)
        assert "[TRUNCATED]" in out
        assert "250" in out
        assert "KLAXON_SCHEMA_FIELD_LIMIT" in out

    async def test_only_the_capped_fields_are_probed(self, indexer: Any) -> None:
        client = indexer(
            mapped={f"f{i:04d}": {"keyword": {"type": "keyword"}} for i in range(250)}
        )
        await field_coverage(index=INDEX)
        probed = {
            spec["filter"]["exists"]["field"]
            for body in client.probe_bodies
            for spec in body["aggs"].values()
        }
        assert len(probed) == 200
        assert "f0199" in probed
        assert "f0200" not in probed

    async def test_a_field_count_under_the_limit_is_not_flagged(
        self, indexer: Any
    ) -> None:
        indexer()
        out = await field_coverage(index=INDEX)
        assert "[TRUNCATED]" not in out


class TestFilters:
    async def test_min_docs_reports_what_it_removed(self, indexer: Any) -> None:
        indexer(
            window_counts={"event.action": WINDOW_DOCS},
            total_counts={"event.action": 829_309},
        )
        out = await field_coverage(index=INDEX, min_docs=1)
        assert "[MIN_DOCS FILTER]" in out
        assert "agent.id" not in out.split("FIELD")[-1]

    async def test_min_docs_zero_hides_nothing(self, indexer: Any) -> None:
        indexer()
        out = await field_coverage(index=INDEX, min_docs=0)
        assert "[MIN_DOCS FILTER]" not in out


class TestInvalidArguments:
    @pytest.mark.parametrize("hours", [0, -1])
    async def test_non_positive_hours_is_refused(self, indexer: Any, hours: int) -> None:
        client = indexer()
        with pytest.raises(ToolError) as exc:
            await field_coverage(index=INDEX, hours=hours)
        assert "hours must be a positive integer" in str(exc.value)
        assert client.requests == []

    async def test_negative_min_docs_is_refused(self, indexer: Any) -> None:
        indexer()
        with pytest.raises(ToolError) as exc:
            await field_coverage(index=INDEX, min_docs=-5)
        assert "min_docs" in str(exc.value)

    async def test_an_invalid_index_is_refused(self, indexer: Any) -> None:
        indexer()
        with pytest.raises(ToolError):
            await field_coverage(index="../etc/passwd")


class TestFailures:
    async def test_a_missing_index_is_reported_as_such(self, indexer: Any) -> None:
        indexer(caps_status=404)
        out = await field_coverage(index=INDEX)
        assert "HTTP 404" in out
        assert "=== RAW RESPONSE ===" in out

    async def test_a_failed_probe_marks_the_rows_unknown(self, indexer: Any) -> None:
        indexer(probe_status=503)
        out = await field_coverage(index=INDEX)
        assert "[PROBE FAILED]" in out
        assert "not as empty" in out

    async def test_no_mapped_field_is_not_zero_coverage(self, indexer: Any) -> None:
        indexer(mapped={})
        out = await field_coverage(index=INDEX, prefix="agent.")
        assert "[NO MAPPED FIELDS]" in out
        assert "[HINT]" in out
        assert "wazuh.agent." in out


"""The third value: not measurable.

An exists aggregation answers 0 for a field the mapping declares index:false,
whatever the documents hold. Verified on a live instance: event.original in
wazuh-events-v5-network-activity* is {"index": false, "doc_values": false},
matches 0 of 10,243,389 documents, and carries the complete raw log line in
_source of every document sampled. Reported as 0% that is not a cautious
answer, it is a false one — and it would be the loudest line in the report.
"""

# The verified declaration, verbatim.
EVENT_ORIGINAL = {"type": "keyword", "index": False, "doc_values": False}
EVENT_MAPPED = {
    "event.original": {"keyword": {"type": "keyword"}},
    "event.action": {"keyword": {"type": "keyword"}},
}
EVENT_MAPPING = {
    "event.original": EVENT_ORIGINAL,
    "event.action": {"type": "keyword", "ignore_above": 1024},
}


class TestMappingFacts:
    def test_the_last_segment_key_quirk_is_handled(self) -> None:
        """The declaration arrives under the field's last segment, not its name."""
        parsed = parse_field_mappings(
            Response(200, json.dumps(mapping_payload(EVENT_MAPPING)), "u")
        )
        assert parsed["event.original"].unindexed
        assert parsed["event.original"].doc_values_disabled
        assert not parsed["event.action"].unindexed

    def test_unindexed_in_every_backing_index(self) -> None:
        parsed = parse_field_mappings(
            Response(200, json.dumps(mapping_payload(EVENT_MAPPING, indices=3)), "u")
        )
        assert parsed["event.original"].declared_in == 3
        assert parsed["event.original"].unindexed
        assert not parsed["event.original"].partially_indexed

    def test_unindexed_in_only_some_is_a_third_answer(self) -> None:
        """A rollover can change the declaration; that is itself the finding."""
        # Two backing indices, one declaring index:false and one not.
        merged = {
            ".ds-a": {
                "mappings": {
                    "event.original": {
                        "mapping": {"original": EVENT_ORIGINAL},
                    }
                }
            },
            ".ds-b": {
                "mappings": {
                    "event.original": {"mapping": {"original": {"type": "keyword"}}}
                }
            },
        }
        parsed = parse_field_mappings(Response(200, json.dumps(merged), "u"))
        assert parsed["event.original"].declared_in == 2
        assert parsed["event.original"].partially_indexed
        assert not parsed["event.original"].unindexed

    def test_enabled_false_counts_as_unindexed(self) -> None:
        parsed = parse_field_mappings(
            Response(
                200, json.dumps(mapping_payload({"a.b": {"enabled": False}})), "u"
            )
        )
        assert parsed["a.b"].unindexed

    def test_an_unreadable_body_yields_no_facts(self) -> None:
        assert parse_field_mappings(Response(200, "not json", "u")) == {}


class TestUnmeasurableRows:
    def test_an_unindexed_field_is_not_zero_percent(self) -> None:
        measured = row(name="event.original", window_docs=0, total_docs=0, unindexed=True)
        assert measured.category == coverage.CATEGORY_UNMEASURABLE
        assert measured.category != CATEGORY_NEVER
        assert measured.window_pct is None
        assert measured.window_label == coverage.MISSING
        assert measured.total_label == coverage.MISSING

    def test_doc_values_disabled_with_a_zero_is_undecidable(self) -> None:
        """Empty or invisible cannot be told apart, so neither is claimed."""
        measured = row(window_docs=0, total_docs=0, doc_values_disabled=True)
        assert not measured.measurable
        assert measured.unmeasurable_reason == coverage.REASON_NO_DOC_VALUES

    def test_doc_values_disabled_with_hits_is_plainly_measurable(self) -> None:
        """The probe found documents, so the field is evidently reachable."""
        measured = row(
            window_docs=100, window_total=1000, total_docs=100, doc_values_disabled=True
        )
        assert measured.measurable
        assert measured.category == CATEGORY_SPARSE

    def test_unmeasured_rows_sort_below_measured_ones(self) -> None:
        rows = sort_rows(
            [
                row(name="event.original", unindexed=True),
                row(name="agent.id", window_docs=0, total_docs=0),
                row(name="source.ip", window_docs=WINDOW_DOCS, total_docs=1),
            ]
        )
        assert [r.name for r in rows] == ["source.ip", "agent.id", "event.original"]

    def test_min_docs_never_hides_an_unmeasured_field(self) -> None:
        """Its count is not a low count; it is the absence of one."""
        kept, hidden = apply_min_docs([row(name="event.original", unindexed=True)], 1000)
        assert [r.name for r in kept] == ["event.original"]
        assert hidden == []

    def test_it_is_excluded_from_the_never_populated_count(self) -> None:
        rows = [row(name="event.original", unindexed=True)]
        assert coverage.never_populated_notice(rows) is None

    def test_the_notice_names_the_reason(self) -> None:
        notice = coverage.unmeasurable_notice(
            [row(name="event.original", unindexed=True)]
        )
        assert notice is not None
        assert "[NOT MEASURABLE]" in notice
        assert "event.original" in notice
        assert "index:false" in notice

    def test_the_notice_reports_source_evidence(self) -> None:
        notice = coverage.unmeasurable_notice(
            [row(name="event.original", unindexed=True, sample_hits=10, sample_size=10)]
        )
        assert notice is not None
        assert "10 of 10 sampled" in notice
        assert "no exists aggregation can see" in notice

    def test_partially_indexed_coverage_is_called_a_lower_bound(self) -> None:
        notice = coverage.partially_indexed_notice(
            [row(name="event.original", window_docs=5, partially_indexed=True)]
        )
        assert notice is not None
        assert "lower bound" in notice
        assert "rollover" in notice


class TestSourcePresence:
    def test_a_nested_value_is_found(self) -> None:
        assert source_has_path({"event": {"original": "Aug  1 ..."}}, "event.original")

    def test_a_literal_dotted_key_is_found(self) -> None:
        assert source_has_path({"event.original": "Aug  1 ..."}, "event.original")

    def test_an_absent_key_is_absent(self) -> None:
        assert not source_has_path({"event": {"action": "x"}}, "event.original")

    def test_null_and_empty_do_not_count_as_present(self) -> None:
        assert not source_has_path({"event": {"original": None}}, "event.original")
        assert not source_has_path({"event": {"original": []}}, "event.original")

    def test_a_list_of_objects_is_searched(self) -> None:
        assert source_has_path({"a": [{"b": 1}]}, "a.b")


class TestUnmeasurableTool:
    async def test_event_original_is_not_measurable_not_zero_percent(
        self, indexer: Any
    ) -> None:
        """The required case, with the verified mapping and the verified zero."""
        indexer(
            mapped=EVENT_MAPPED,
            mapping=EVENT_MAPPING,
            grand_total=10_243_389,
            window_counts={"event.action": 200_000},
            total_counts={"event.action": 829_609},
            sample_docs=[{"event": {"original": "Aug  1 10:55:10 filterlog[70190]"}}] * 10,
        )
        out = await field_coverage(index=INDEX, prefix="event.")

        assert "[NOT MEASURABLE]" in out
        assert coverage.CATEGORY_UNMEASURABLE in out
        # The row exists, and carries no coverage figure of any kind.
        line = next(l for l in out.splitlines() if l.startswith("event.original"))
        assert "0.0%" not in line
        assert CATEGORY_NEVER not in line
        assert coverage.MISSING in line
        # And it is not counted among the never-populated fields.
        assert "[MAPPED BUT NEVER POPULATED]" not in out

    async def test_the_source_sample_is_reported(self, indexer: Any) -> None:
        indexer(
            mapped=EVENT_MAPPED,
            mapping=EVENT_MAPPING,
            sample_docs=[{"event": {"original": "raw line"}}] * 10,
        )
        out = await field_coverage(index=INDEX, prefix="event.")
        assert "10 of 10 sampled" in out
        assert "NOT MEASURABLE" in out
        assert "_SOURCE" in out

    async def test_an_unindexed_field_is_never_probed(self, indexer: Any) -> None:
        """Probing it would only manufacture the zero we refuse to print."""
        client = indexer(mapped=EVENT_MAPPED, mapping=EVENT_MAPPING)
        await field_coverage(index=INDEX, prefix="event.")
        probed = {
            spec["filter"]["exists"]["field"]
            for body in client.probe_bodies
            for spec in body["aggs"].values()
        }
        assert probed == {"event.action"}

    async def test_the_mapping_is_read_before_the_probe(self, indexer: Any) -> None:
        client = indexer(mapped=EVENT_MAPPED, mapping=EVENT_MAPPING)
        await field_coverage(index=INDEX, prefix="event.")
        paths = [p for p, _ in client.requests]
        mapping_at = next(i for i, p in enumerate(paths) if "_mapping/field" in p)
        first_probe = next(
            i
            for i, (p, b) in enumerate(client.requests)
            if isinstance(b, dict) and b.get("aggs")
        )
        assert mapping_at < first_probe

    async def test_a_failed_mapping_check_warns_about_every_zero(
        self, indexer: Any
    ) -> None:
        indexer(mapping_status=403)
        out = await field_coverage(index=INDEX)
        assert "[MAPPING CHECK FAILED]" in out
        assert "index:false" in out

    async def test_a_failed_sample_still_reports_not_measurable(
        self, indexer: Any
    ) -> None:
        indexer(mapped=EVENT_MAPPED, mapping=EVENT_MAPPING, sample_status=503)
        out = await field_coverage(index=INDEX, prefix="event.")
        assert "[SOURCE SAMPLE FAILED]" in out
        assert "[NOT MEASURABLE]" in out

    async def test_min_docs_does_not_remove_it(self, indexer: Any) -> None:
        indexer(
            mapped=EVENT_MAPPED,
            mapping=EVENT_MAPPING,
            window_counts={"event.action": 200_000},
            total_counts={"event.action": 829_609},
        )
        out = await field_coverage(index=INDEX, prefix="event.", min_docs=1000)
        assert "event.original" in out
        assert coverage.CATEGORY_UNMEASURABLE in out

    async def test_a_plainly_mapped_field_is_unaffected(self, indexer: Any) -> None:
        """The check must not turn ordinary fields into unmeasurable ones."""
        indexer(
            window_counts={"event.action": WINDOW_DOCS},
            total_counts={"event.action": 829_309},
        )
        out = await field_coverage(index=INDEX)
        assert "[NOT MEASURABLE]" not in out
        assert "NOT MEASURABLE  (" not in out
        assert f"{coverage.CATEGORY_UNMEASURABLE}: 0" in out
        # Ordinary fields keep their measurements.
        assert "100.0%" in out


class TestCountDocuments:
    async def test_it_sends_track_total_hits(self, indexer: Any) -> None:
        client = indexer()
        total, response = await count_documents(client, INDEX)  # type: ignore[arg-type]
        assert total == DATASTREAM_DOCS
        assert client.requests[-1][1]["track_total_hits"] is True

    async def test_an_error_response_yields_no_count(self, indexer: Any) -> None:
        class Failing:
            async def post(self, path: str, body: Any = None) -> Response:
                return Response(500, "boom", path)

        total, response = await count_documents(Failing(), INDEX)  # type: ignore[arg-type]
        assert total is None
        assert response.status_code == 500
