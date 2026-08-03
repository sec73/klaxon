# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The severity scale: a zero that was measured, not a row that went missing.

A terms aggregation returns the values it found. `critical` absent from the
response and `critical` at zero are the same JSON, and a report that says "no
critical findings" on that basis has proved nothing. These tests pin the
difference: the full scale is always printed, an unexpected value is printed
too, and an unpopulated field is reported instead of rendered as a table of
zeros.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from klaxon_mcp import overview, server
from klaxon_mcp.clients import Response
from klaxon_mcp.constants import (
    FINDINGS_AGENT_NAME_FIELD,
    FINDINGS_CATEGORY_FIELD,
    FINDINGS_LEVEL_FIELD,
    FINDINGS_TITLE_FIELD,
    SEVERITY_SCALE,
)
from klaxon_mcp.overview import (
    AGG_AGENT_COUNT,
    AGG_AGENTS,
    AGG_CATEGORIES,
    AGG_SEVERITY,
    AGG_TITLE_COUNT,
    AGG_TITLES,
    build_query,
    parse,
    severity_rows,
    unknown_levels,
)
from klaxon_mcp.server import findings_overview

# The measured distribution on the live 5.0.0-beta4 instance: critical and high
# never occurred, which is exactly the case the tool has to make visible.
MEASURED = {"medium": 1252, "informational": 747, "low": 163}
MEASURED_TOTAL = sum(MEASURED.values())


def terms(counts: dict[str, int], other: int = 0) -> dict[str, Any]:
    return {
        "buckets": [{"key": k, "doc_count": v} for k, v in counts.items()],
        "sum_other_doc_count": other,
        "doc_count_error_upper_bound": 0,
    }


def findings_response(
    severity: dict[str, int] | None = None,
    agents: dict[str, dict[str, int]] | None = None,
    titles: dict[str, int] | None = None,
    categories: dict[str, int] | None = None,
    total: int | None = None,
    agent_cardinality: int | None = None,
    title_cardinality: int | None = None,
) -> dict[str, Any]:
    """A findings aggregation response shaped like the real one."""
    severity = MEASURED if severity is None else severity
    agents = {"opnsense": dict(severity)} if agents is None else agents
    titles = {"Suspicious login": 12} if titles is None else titles
    categories = {"security": 1415} if categories is None else categories
    resolved_total = sum(severity.values()) if total is None else total

    return {
        "hits": {"total": {"value": resolved_total, "relation": "eq"}, "hits": []},
        "aggregations": {
            AGG_SEVERITY: terms(severity),
            AGG_AGENTS: {
                "buckets": [
                    {
                        "key": name,
                        "doc_count": sum(levels.values()),
                        AGG_SEVERITY: terms(levels),
                    }
                    for name, levels in agents.items()
                ],
                "sum_other_doc_count": 0,
                "doc_count_error_upper_bound": 0,
            },
            AGG_AGENT_COUNT: {
                "value": len(agents) if agent_cardinality is None else agent_cardinality
            },
            AGG_TITLES: terms(titles),
            AGG_TITLE_COUNT: {
                "value": len(titles) if title_cardinality is None else title_cardinality
            },
            AGG_CATEGORIES: terms(categories),
        },
    }


# --------------------------------------------------------------------------- #
# The scale itself
# --------------------------------------------------------------------------- #


class TestSeverityScale:
    def test_absent_level_is_reported_as_zero(self) -> None:
        """The requirement: critical did not occur, so critical reads 0."""
        rows = {r.level: r.count for r in severity_rows(MEASURED)}
        assert rows["critical"] == 0
        assert rows["high"] == 0
        assert rows["medium"] == 1252
        assert rows["low"] == 163
        assert rows["informational"] == 747

    def test_scale_is_complete_and_in_canonical_order(self) -> None:
        levels = [r.level for r in severity_rows(MEASURED)]
        assert levels == list(SEVERITY_SCALE)

    def test_order_does_not_follow_the_counts(self) -> None:
        """low (163) stays above informational (747): severity, not frequency."""
        levels = [r.level for r in severity_rows(MEASURED)]
        assert levels.index("low") < levels.index("informational")

    def test_empty_aggregation_still_yields_the_full_scale(self) -> None:
        rows = severity_rows({})
        assert [r.level for r in rows] == list(SEVERITY_SCALE)
        assert all(r.count == 0 for r in rows)

    def test_known_levels_are_not_marked_unknown(self) -> None:
        assert all(r.known for r in severity_rows(MEASURED))


class TestUnknownSeverity:
    def test_unknown_value_is_kept_not_discarded(self) -> None:
        rows = severity_rows({**MEASURED, "catastrophic": 3})
        by_level = {r.level: r for r in rows}
        assert "catastrophic" in by_level
        assert by_level["catastrophic"].count == 3
        assert not by_level["catastrophic"].known

    def test_unknown_value_does_not_displace_the_scale(self) -> None:
        rows = severity_rows({"catastrophic": 3})
        assert [r.level for r in rows][: len(SEVERITY_SCALE)] == list(SEVERITY_SCALE)
        assert rows[-1].level == "catastrophic"

    def test_case_variant_is_not_folded_into_the_known_level(self) -> None:
        """Merging 'Medium' into 'medium' would hide a mapping change."""
        rows = {r.level: r for r in severity_rows({"Medium": 5, "medium": 1252})}
        assert rows["medium"].count == 1252
        assert rows["Medium"].count == 5
        assert not rows["Medium"].known

    def test_unknown_values_are_ordered_by_count(self) -> None:
        assert unknown_levels({"a": 1, "b": 9, "medium": 100}) == ["b", "a"]

    def test_the_scale_alone_has_no_unknowns(self) -> None:
        assert unknown_levels(MEASURED) == []

    def test_rendering_marks_the_unknown_row(self) -> None:
        result = parse(findings_response(severity={**MEASURED, "catastrophic": 3}))
        out = overview.render(result)
        assert "catastrophic" in out
        assert "UNKNOWN" in out

    def test_notice_names_the_unknown_value(self) -> None:
        result = parse(findings_response(severity={**MEASURED, "catastrophic": 3}))
        notices = " ".join(overview.overview_notices(result, hours=24))
        assert "UNKNOWN SEVERITY VALUE" in notices
        assert "catastrophic" in notices

    def test_notice_points_out_a_case_mismatch(self) -> None:
        result = parse(findings_response(severity={"Medium": 5}))
        notices = " ".join(overview.overview_notices(result, hours=24))
        assert "case" in notices.lower()
        assert "'Medium'" in notices


# --------------------------------------------------------------------------- #
# Query and parsing
# --------------------------------------------------------------------------- #


class TestQuery:
    def test_track_total_hits_is_set(self) -> None:
        """Without it the headline number silently becomes a lower bound."""
        assert build_query(24, 10, 10)["track_total_hits"] is True

    def test_no_documents_are_pulled(self) -> None:
        assert build_query(24, 10, 10)["size"] == 0

    def test_window_uses_the_v5_time_field(self) -> None:
        query = build_query(6, 10, 10)["query"]
        assert query == {"range": {"@timestamp": {"gte": "now-6h"}}}

    def test_aggregates_on_the_populated_wazuh_branch(self) -> None:
        aggs = build_query(24, 10, 10)["aggs"]
        assert aggs[AGG_SEVERITY]["terms"]["field"] == FINDINGS_LEVEL_FIELD
        assert aggs[AGG_AGENTS]["terms"]["field"] == FINDINGS_AGENT_NAME_FIELD
        assert aggs[AGG_TITLES]["terms"]["field"] == FINDINGS_TITLE_FIELD
        assert aggs[AGG_CATEGORIES]["terms"]["field"] == FINDINGS_CATEGORY_FIELD
        # The rule.* branch is mapped and empty; nothing may point at it.
        assert '"field": "rule.' not in json.dumps(build_query(24, 10, 10))

    def test_cross_tab_is_a_nested_aggregation(self) -> None:
        nested = build_query(24, 10, 10)["aggs"][AGG_AGENTS]["aggs"][AGG_SEVERITY]
        assert nested["terms"]["field"] == FINDINGS_LEVEL_FIELD

    def test_severity_terms_size_exceeds_the_scale(self) -> None:
        """An unexpected value must get a bucket, not vanish into 'other'."""
        size = build_query(24, 10, 10)["aggs"][AGG_SEVERITY]["terms"]["size"]
        assert size > len(SEVERITY_SCALE)

    def test_top_parameters_reach_the_aggregations(self) -> None:
        aggs = build_query(24, 3, 7)["aggs"]
        assert aggs[AGG_AGENTS]["terms"]["size"] == 3
        assert aggs[AGG_TITLES]["terms"]["size"] == 7

    def test_the_nested_agg_is_not_a_shared_object(self) -> None:
        """Aliasing the sub-agg would make one edit change both aggregations."""
        query = build_query(24, 10, 10)
        assert (
            query["aggs"][AGG_SEVERITY]
            is not query["aggs"][AGG_AGENTS]["aggs"][AGG_SEVERITY]
        )


class TestParse:
    def test_reads_the_measured_shape(self) -> None:
        result = parse(findings_response())
        assert result.total == MEASURED_TOTAL
        assert result.severity == MEASURED
        assert result.agents[0].key == "opnsense"
        assert result.agent_severity["opnsense"]["medium"] == 1252

    def test_missing_aggregations_do_not_invent_numbers(self) -> None:
        result = parse({"hits": {"total": {"value": 5, "relation": "eq"}}})
        assert result.total == 5
        assert result.severity == {}
        assert result.agents == []
        assert result.agent_cardinality is None

    def test_non_dict_payload_is_survivable(self) -> None:
        result = parse("not json")
        assert result.total == 0
        assert result.severity == {}

    def test_a_truncated_severity_agg_is_flagged(self) -> None:
        """More distinct levels than the agg size means the table is incomplete."""
        payload = findings_response()
        payload["aggregations"][AGG_SEVERITY]["sum_other_doc_count"] = 9
        result = parse(payload)
        assert result.severity_other == 9
        notices = " ".join(overview.overview_notices(result, hours=24))
        assert "[SEVERITY SCALE TRUNCATED]" in notices

    def test_cross_tab_columns_include_a_level_only_seen_per_agent(self) -> None:
        """A value the top-level agg missed must still get a column."""
        result = parse(
            findings_response(
                severity={"medium": 30}, agents={"dc01": {"medium": 30, "weird": 2}}
            )
        )
        assert "weird" in overview.cross_tab_levels(result)
        assert "weird" in overview.render(result)

    def test_lower_bound_total_is_flagged(self) -> None:
        result = parse({"hits": {"total": {"value": 10000, "relation": "gte"}}})
        assert result.total_is_lower_bound


# --------------------------------------------------------------------------- #
# The tool
# --------------------------------------------------------------------------- #


class StubIndexer:
    """Answers the exists-probe and the overview query with canned payloads."""

    def __init__(
        self,
        level_doc_count: int = 391_204,
        payload: dict[str, Any] | None = None,
        status: int = 200,
        probe_status: int = 200,
    ) -> None:
        self.level_doc_count = level_doc_count
        self.payload = findings_response() if payload is None else payload
        self.status = status
        self.probe_status = probe_status
        self.requests: list[tuple[str, Any]] = []

    async def post(self, path: str, body: Any = None) -> Response:
        self.requests.append((path, body))
        aggs = body.get("aggs") if isinstance(body, dict) else None
        is_probe = isinstance(aggs, dict) and "f0" in aggs
        if is_probe:
            return Response(
                self.probe_status,
                json.dumps({"aggregations": {"f0": {"doc_count": self.level_doc_count}}}),
                path,
            )
        return Response(self.status, json.dumps(self.payload), path)

    @property
    def overview_body(self) -> Any:
        """The body of the aggregation request, i.e. not the probe."""
        return self.requests[-1][1]


@pytest.fixture
def indexer() -> Iterator[Any]:
    """Install a stub indexer, configurable per test."""
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


class TestToolOutput:
    async def test_full_scale_reaches_the_caller(self, indexer: Any) -> None:
        indexer()
        out = await findings_overview()
        for level in SEVERITY_SCALE:
            assert level in out
        assert "[FULL SCALE SHOWN]" in out

    async def test_the_zero_rows_are_visible_as_numbers(self, indexer: Any) -> None:
        indexer()
        out = await findings_overview()
        rows = {
            line.split()[0]: line.split()[1]
            for line in out.splitlines()
            if line.split() and line.split()[0] in SEVERITY_SCALE
        }
        assert rows["critical"] == "0"
        assert rows["high"] == "0"
        assert rows["medium"] == "1252"

    async def test_diagnostics_block_comes_first(self, indexer: Any) -> None:
        indexer()
        out = await findings_overview()
        assert out.startswith("=== DIAGNOSTICS")

    async def test_output_is_tables_not_raw_json(self, indexer: Any) -> None:
        indexer()
        out = await findings_overview()
        assert "=== RAW RESPONSE ===" not in out
        assert "doc_count_error_upper_bound" not in out
        assert "CROSS-TAB" in out
        assert "TOP TITLES" in out
        assert "CATEGORIES" in out

    async def test_the_request_is_reproducible_from_the_footer(
        self, indexer: Any
    ) -> None:
        indexer()
        out = await findings_overview()
        assert "request: POST /wazuh-findings-v5-*/_search" in out

    async def test_track_total_hits_is_on_the_wire(self, indexer: Any) -> None:
        client = indexer()
        await findings_overview()
        assert client.overview_body["track_total_hits"] is True

    async def test_parameters_reach_the_query(self, indexer: Any) -> None:
        client = indexer()
        await findings_overview(hours=6, top_agents=3, top_titles=4)
        body = client.overview_body
        assert body["query"]["range"]["@timestamp"]["gte"] == "now-6h"
        assert body["aggs"][AGG_AGENTS]["terms"]["size"] == 3
        assert body["aggs"][AGG_TITLES]["terms"]["size"] == 4

    async def test_cross_tab_lists_every_agent(self, indexer: Any) -> None:
        indexer(
            payload=findings_response(
                severity={"medium": 30, "low": 10},
                agents={"opnsense": {"medium": 30}, "dc01": {"low": 10}},
            )
        )
        out = await findings_overview()
        assert "opnsense" in out
        assert "dc01" in out

    async def test_truncated_agent_list_says_so(self, indexer: Any) -> None:
        indexer(payload=findings_response(agent_cardinality=42))
        out = await findings_overview()
        assert "[AGENT LIST TRUNCATED]" in out
        assert "42" in out

    async def test_the_caption_counts_the_rows_not_the_request(
        self, indexer: Any
    ) -> None:
        """`top 10 of 5` over three rows is a caption that overstates its table."""
        indexer(payload=findings_response(agent_cardinality=42))
        out = await findings_overview(top_agents=10)
        assert f"{FINDINGS_AGENT_NAME_FIELD}, top 1 of 42" in out


class TestUnpopulatedSeverityField:
    async def test_no_table_of_zeros_is_produced(self, indexer: Any) -> None:
        """The failure this tool must not reproduce."""
        indexer(level_doc_count=0)
        out = await findings_overview()
        assert "[SEVERITY FIELD UNPOPULATED]" in out
        assert FINDINGS_LEVEL_FIELD in out
        # Not a single scale row: an all-zero table would assert the opposite
        # of what is known.
        assert "informational" not in out
        assert "CROSS-TAB" not in out

    async def test_the_aggregation_is_never_sent(self, indexer: Any) -> None:
        client = indexer(level_doc_count=0)
        await findings_overview()
        assert len(client.requests) == 1
        assert "f0" in client.requests[0][1]["aggs"]

    async def test_no_finding_count_is_invented(self, indexer: Any) -> None:
        """The aggregation was never sent, so there is no total to print."""
        indexer(level_doc_count=0)
        out = await findings_overview()
        assert "findings:       (not queried)" in out

    async def test_it_points_at_the_next_step(self, indexer: Any) -> None:
        indexer(level_doc_count=0)
        out = await findings_overview()
        assert "schema" in out
        assert "wazuh.rule." in out

    async def test_a_failed_probe_is_not_read_as_an_empty_field(
        self, indexer: Any
    ) -> None:
        """Unverified is a third state, distinct from populated and empty."""
        indexer(probe_status=503)
        out = await findings_overview()
        assert "[PROBE FAILED]" in out
        assert "[SEVERITY FIELD UNPOPULATED]" not in out
        # The overview still runs — a failed probe is not a reason to answer nothing.
        assert "CROSS-TAB" in out


class TestEmptyWindow:
    async def test_it_is_reported_as_an_empty_window(self, indexer: Any) -> None:
        indexer(payload=findings_response(severity={}, agents={}, titles={}, total=0))
        out = await findings_overview(hours=2)
        assert "[EMPTY WINDOW]" in out
        assert "2h" in out

    async def test_it_is_distinguished_from_an_empty_field(self, indexer: Any) -> None:
        """The probe count is what separates 'quiet window' from 'no data ever'."""
        indexer(
            level_doc_count=391_204,
            payload=findings_response(severity={}, agents={}, titles={}, total=0),
        )
        out = await findings_overview()
        assert "391204" in out
        assert "empty window rather than an empty field" in out

    async def test_no_severity_table_is_rendered(self, indexer: Any) -> None:
        indexer(payload=findings_response(severity={}, agents={}, titles={}, total=0))
        out = await findings_overview()
        assert "CROSS-TAB" not in out
        assert "informational" not in out


class TestInvalidArguments:
    @pytest.mark.parametrize("hours", [0, -1, -24])
    async def test_non_positive_hours_is_refused(self, indexer: Any, hours: int) -> None:
        client = indexer()
        with pytest.raises(ToolError) as exc:
            await findings_overview(hours=hours)
        assert "hours must be a positive integer" in str(exc.value)
        assert str(hours) in str(exc.value)
        # Nothing was queried on the strength of a nonsensical window.
        assert client.requests == []

    @pytest.mark.parametrize("name", ["top_agents", "top_titles"])
    async def test_non_positive_top_values_are_refused(
        self, indexer: Any, name: str
    ) -> None:
        indexer()
        with pytest.raises(ToolError) as exc:
            await findings_overview(**{name: 0})
        assert f"{name} must be a positive integer" in str(exc.value)

    async def test_oversized_top_value_is_refused(self, indexer: Any) -> None:
        indexer()
        with pytest.raises(ToolError) as exc:
            await findings_overview(top_agents=10_000)
        assert "must not exceed" in str(exc.value)


class TestErrorResponse:
    async def test_rejected_query_returns_the_unmodified_body(
        self, indexer: Any
    ) -> None:
        indexer(status=400, payload={"error": {"type": "search_phase_execution"}})
        out = await findings_overview()
        assert "[HTTP 400]" in out
        assert "=== RAW RESPONSE ===" in out
        assert "search_phase_execution" in out
