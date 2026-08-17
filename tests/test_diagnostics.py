# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The behaviour this project exists for: never let emptiness pass as an answer.

These encode the acceptance criteria that can be checked without a live cluster
(T1, T3, T6). T2, T4 and T5 need a real instance.
"""

from __future__ import annotations

import json
from typing import Any

from klaxon_mcp.clients import Response
from klaxon_mcp.diagnostics import (
    agg_size_capped_notice,
    render,
    search_notices,
    size_capped_notice,
    unmappable_agg_dropped_notice,
)


def resp(payload: Any, status: int = 200) -> Response:
    return Response(status, json.dumps(payload), "https://indexer:9200/x/_search")


def notice_tags(notices: list[str]) -> set[str]:
    return {n.split("]")[0].lstrip("[") for n in notices if n.startswith("[")}


class TestSizeCappedNotice:
    def test_document_size_cap_states_requested_and_effective(self) -> None:
        text = size_capped_notice(500, 100)
        assert "[SIZE CAPPED]" in text
        assert "500" in text
        assert "100" in text

    def test_agg_size_cap_states_requested_and_effective_per_aggregation(self) -> None:
        text = agg_size_capped_notice([("hosts.terms", 50_000)], 100)
        assert "[AGG SIZE CAPPED]" in text
        assert "hosts.terms" in text
        assert "50000" in text


    def test_agg_size_cap_names_every_lowered_aggregation(self) -> None:
        text = agg_size_capped_notice(
            [("hosts.terms", 50_000), ("agents.users.terms", 500)], 100
        )
        assert "hosts.terms requested 50000" in text
        assert "agents.users.terms requested 500" in text

    def test_agg_size_cap_empty_list_still_formats(self) -> None:
        text = agg_size_capped_notice([], 100)
        assert "[AGG SIZE CAPPED]" in text


class TestUnmappableAggDroppedNotice:
    def test_names_type_and_agg_and_states_absence(self) -> None:
        text = unmappable_agg_dropped_notice(
            [("scripted", "scripted_metric")]
        )
        assert "[UNMAPPABLE AGG DROPPED]" in text
        assert "scripted_metric (scripted)" in text
        # Never states a raw value — only the agg type and name.
        assert "absent from this response" in text

    def test_multiple_pairs(self) -> None:
        text = unmappable_agg_dropped_notice(
            [("a", "scripted_metric"), ("b", "weird_agg")]
        )
        assert "scripted_metric (a)" in text
        assert "weird_agg (b)" in text


class TestZeroHits:
    def test_zero_hits_names_the_index(self) -> None:
        """T6: the caller must be able to see a typo in the pattern."""
        notices = search_notices(
            "wazuh-events-v5-typo*",
            {"query": {"match_all": {}}},
            resp({"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}),
        )
        assert "ZERO HITS" in notice_tags(notices)
        joined = " ".join(notices)
        assert "wazuh-events-v5-typo*" in joined
        assert "pattern matches no index" in joined

    def test_nonzero_hits_produce_no_zero_notice(self) -> None:
        notices = search_notices(
            "wazuh-events-v5-network-activity*",
            {},
            resp({"hits": {"total": {"value": 390000, "relation": "eq"}, "hits": []}}),
        )
        assert "ZERO HITS" not in notice_tags(notices)


class TestLegacyPattern:
    def test_wazuh_alerts_is_called_out_explicitly(self) -> None:
        """T6: wazuh-alerts-* does not exist in Wazuh 5 at all."""
        notices = search_notices(
            "wazuh-alerts-*",
            {},
            resp({"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}}),
        )
        tags = notice_tags(notices)
        assert "WAZUH 4.x INDEX PATTERN" in tags
        assert "ZERO HITS" in tags
        joined = " ".join(notices)
        assert "wazuh-events-v5-*" in joined
        assert "does not exist in Wazuh 5" in joined

    def test_legacy_flagged_even_when_hits_exist(self) -> None:
        notices = search_notices(
            "wazuh-alerts-4.x-*",
            {},
            resp({"hits": {"total": {"value": 5, "relation": "eq"}, "hits": []}}),
        )
        assert "WAZUH 4.x INDEX PATTERN" in notice_tags(notices)

    def test_v5_pattern_is_not_flagged(self) -> None:
        notices = search_notices(
            "wazuh-events-v5-network-activity*",
            {},
            resp({"hits": {"total": {"value": 1, "relation": "eq"}, "hits": []}}),
        )
        assert "WAZUH 4.x INDEX PATTERN" not in notice_tags(notices)


class TestTotalHitsCap:
    def test_gte_relation_is_reported_as_truncation(self) -> None:
        """T1: the 10000 cap must never be presented as a real total."""
        notices = search_notices(
            "wazuh-events-v5-network-activity*",
            {"query": {"match_all": {}}},
            resp({"hits": {"total": {"value": 10000, "relation": "gte"}, "hits": []}}),
        )
        assert "TOTAL COUNT TRUNCATED" in notice_tags(notices)
        assert "track_total_hits" in " ".join(notices)

    def test_eq_relation_is_not_flagged(self) -> None:
        notices = search_notices(
            "wazuh-events-v5-network-activity*",
            {"track_total_hits": True},
            resp({"hits": {"total": {"value": 390000, "relation": "eq"}, "hits": []}}),
        )
        assert "TOTAL COUNT TRUNCATED" not in notice_tags(notices)

    def test_legacy_int_total_shape_is_handled(self) -> None:
        notices = search_notices(
            "wazuh-events-v5-*", {}, resp({"hits": {"total": 0, "hits": []}})
        )
        assert "ZERO HITS" in notice_tags(notices)


class TestAggregationCoverage:
    def test_partial_coverage_is_surfaced(self) -> None:
        """T3: one bucket covering ~13% of hits must expose the 87% gap.

        This is how a decoder gap becomes visible. Formatting it away is the
        exact failure mode this project was written to avoid.
        """
        total = 390_000
        notices = search_notices(
            "wazuh-events-v5-network-activity*",
            {"aggs": {"actions": {"terms": {"field": "event.action"}}}},
            resp(
                {
                    "hits": {"total": {"value": total, "relation": "eq"}, "hits": []},
                    "aggregations": {
                        "actions": {
                            "doc_count_error_upper_bound": 0,
                            "sum_other_doc_count": 0,
                            "buckets": [
                                {"key": "connection-denied", "doc_count": 50_700}
                            ],
                        }
                    },
                }
            ),
        )
        assert "PARTIAL AGGREGATION COVERAGE" in notice_tags(notices)
        joined = " ".join(notices)
        assert "50700 of 390000" in joined
        assert "13.0%" in joined
        assert "sum_other_doc_count=0" in joined
        assert "no value for the field" in joined

    def test_full_coverage_produces_no_notice(self) -> None:
        notices = search_notices(
            "wazuh-events-v5-network-activity*",
            {},
            resp(
                {
                    "hits": {"total": {"value": 100, "relation": "eq"}, "hits": []},
                    "aggregations": {
                        "a": {
                            "sum_other_doc_count": 0,
                            "buckets": [
                                {"key": "x", "doc_count": 60},
                                {"key": "y", "doc_count": 40},
                            ],
                        }
                    },
                }
            ),
        )
        assert "PARTIAL AGGREGATION COVERAGE" not in notice_tags(notices)

    def test_truncation_by_size_is_distinguished_from_missing_values(self) -> None:
        notices = search_notices(
            "wazuh-events-v5-*",
            {},
            resp(
                {
                    "hits": {"total": {"value": 100, "relation": "eq"}, "hits": []},
                    "aggregations": {
                        "a": {
                            "sum_other_doc_count": 30,
                            "buckets": [{"key": "x", "doc_count": 60}],
                        }
                    },
                }
            ),
        )
        joined = " ".join(notices)
        assert "PARTIAL AGGREGATION COVERAGE" in notice_tags(notices)
        assert "truncated by the agg 'size' parameter" in joined

    def test_empty_buckets_call_out_the_agent_id_trap(self) -> None:
        """The agent.id / wazuh.agent.id trap, seen from the search side."""
        notices = search_notices(
            "wazuh-events-v5-network-activity*",
            {"aggs": {"agents": {"terms": {"field": "agent.id"}}}},
            resp(
                {
                    "hits": {"total": {"value": 390_000, "relation": "eq"}, "hits": []},
                    "aggregations": {
                        "agents": {"sum_other_doc_count": 0, "buckets": []}
                    },
                }
            ),
        )
        assert "EMPTY AGGREGATION" in notice_tags(notices)
        joined = " ".join(notices)
        assert "wazuh.agent" in joined

    def test_nested_aggregations_are_inspected(self) -> None:
        notices = search_notices(
            "wazuh-events-v5-*",
            {},
            resp(
                {
                    "hits": {"total": {"value": 100, "relation": "eq"}, "hits": []},
                    "aggregations": {
                        "outer": {
                            "sum_other_doc_count": 0,
                            "buckets": [
                                {
                                    "key": "a",
                                    "doc_count": 100,
                                    "inner": {
                                        "sum_other_doc_count": 0,
                                        "buckets": [],
                                    },
                                }
                            ],
                        }
                    },
                }
            ),
        )
        assert any("outer>inner" in n for n in notices)


class TestErrorPassthrough:
    def test_index_not_found_is_explicit(self) -> None:
        notices = search_notices(
            "nonexistent-index",
            {},
            resp(
                {"error": {"type": "index_not_found_exception", "reason": "no such index"}},
                status=404,
            ),
        )
        tags = notice_tags(notices)
        assert "HTTP 404" in tags
        assert "INDEX NOT FOUND" in tags

    def test_error_status_short_circuits_hit_analysis(self) -> None:
        notices = search_notices(
            "wazuh-events-v5-*",
            {},
            resp({"error": {"type": "parsing_exception"}}, status=400),
        )
        assert "ZERO HITS" not in notice_tags(notices)
        assert "HTTP 400" in notice_tags(notices)


class TestRender:
    def test_raw_payload_is_preserved_verbatim(self) -> None:
        """The response body must survive unmodified; notices go in a preamble."""
        payload = {
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
            "took": 3,
        }
        response = resp(payload)
        out = render(search_notices("wazuh-alerts-*", {}, response), response)

        assert "DIAGNOSTICS" in out
        raw = out.split("=== RAW RESPONSE ===")[1]
        # Everything after the header parses back to the original payload.
        assert json.loads(raw.split("\n", 1)[1]) == payload

    def test_no_notices_still_returns_raw_body(self) -> None:
        payload = {"hits": {"total": {"value": 7, "relation": "eq"}, "hits": []}}
        response = resp(payload)
        out = render([], response)
        assert "DIAGNOSTICS" not in out
        assert json.loads(out.split("\n", 1)[1]) == payload

    def test_non_json_body_is_passed_through(self) -> None:
        response = Response(502, "<html>bad gateway</html>", "https://x/_search")
        out = render(["[HTTP 502] upstream"], response)
        assert "<html>bad gateway</html>" in out
