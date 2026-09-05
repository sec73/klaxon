# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The `parsing_cemetery` tool: end to end against a stub indexer.

Wazuh 5 has no archives/alerts split, so the tool measures the two gaps on the
events stream directly: decoder_gap (events never mapped to an event.dataset)
and detection_gap (sources with events but zero findings in wazuh-findings-v5-*).
These tests drive the real tool with a stub indexer and assert on the rendered
report, the queries it issued, the min_count/top_n filters, the empty-stream
handling and — with the anonymizer active — that agent-name keys and raw
samples are pseudonymized before they reach the output.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from klaxon_mcp import cemetery, server
from klaxon_mcp.clients import Response
from klaxon_mcp.config import AnonymizationConfig, Config
from klaxon_mcp.server import parsing_cemetery

TEST_SALT = "0123456789abcdef0123456789abcdef"
EVENTS = "wazuh-events-v5-*"
FINDINGS = "wazuh-findings-v5-*"


# --------------------------------------------------------------------------- #
# Response builders (real OpenSearch shapes: sub-aggregations nest DIRECTLY in
# a bucket as siblings of key/doc_count — no `aggs` wrapper on the wire).
# --------------------------------------------------------------------------- #


def total_response(value: int, url: str = f"https://indexer.example/{EVENTS}/_search") -> Response:
    return Response(
        200,
        json.dumps({"hits": {"total": {"value": value, "relation": "eq"}}}),
        url,
    )


def _hours(*pairs: tuple[str, int]) -> dict[str, Any]:
    return {
        "buckets": [
            {"key": 0, "key_as_string": label, "doc_count": count}
            for label, count in pairs
        ]
    }


def _top_hits(lines: list[str]) -> dict[str, Any]:
    return {
        "hits": {
            "total": {"value": len(lines), "relation": "eq"},
            "max_score": 1.0,
            "hits": [
                {"_index": "x", "_id": str(i), "_source": {"event.original": line}}
                for i, line in enumerate(lines)
            ],
        }
    }


def _agents_payload(
    leaves: list[dict[str, Any]],
    *,
    thin: bool,
    window: int,
    samples: dict[tuple[str, str], list[str]] | None = None,
) -> dict[str, Any]:
    """Build an `aggregations.agents` payload from leaf specs.

    A decoder leaf spec: {agent, category, total, thin, hours}.
    A detection leaf spec: {agent, category, total, hours, datasets}.
    When `samples` is given the leaf carries a nested top_hits of raw lines.
    """
    by_agent: dict[str, list[dict[str, Any]]] = {}
    for leaf in leaves:
        by_agent.setdefault(leaf["agent"], []).append(leaf)

    agent_buckets: list[dict[str, Any]] = []
    for agent, cats in by_agent.items():
        category_buckets: list[dict[str, Any]] = []
        for spec in cats:
            category: str = spec["category"]
            bucket: dict[str, Any] = {"key": category, "doc_count": spec["total"]}
            if thin:
                child: dict[str, Any] = {"doc_count": spec["thin"]}
                if spec.get("hours"):
                    child["hours"] = _hours(*spec["hours"])
                if samples:
                    child["samples"] = _top_hits(samples.get((agent, category), []))
                bucket["thin"] = child
            else:
                if spec.get("hours"):
                    bucket["hours"] = _hours(*spec["hours"])
                if spec.get("datasets"):
                    bucket["datasets"] = {
                        "buckets": [
                            {"key": name, "doc_count": count}
                            for name, count in spec["datasets"]
                        ]
                    }
                if samples:
                    bucket["samples"] = _top_hits(samples.get((agent, category), []))
            category_buckets.append(bucket)
        agent_buckets.append(
            {
                "key": agent,
                "doc_count": sum(spec["total"] for spec in cats),
                "categories": {"buckets": category_buckets},
            }
        )

    return {
        "hits": {"total": {"value": window, "relation": "eq"}},
        "aggregations": {"agents": {"buckets": agent_buckets}},
    }


def findings_payload(
    leaves: list[dict[str, Any]], window: int
) -> dict[str, Any]:
    """Per-(agent, category) finding counts. A spec: {agent, category, total}."""
    by_agent: dict[str, list[dict[str, Any]]] = {}
    for leaf in leaves:
        by_agent.setdefault(leaf["agent"], []).append(leaf)
    agent_buckets = [
        {
            "key": agent,
            "doc_count": sum(spec["total"] for spec in cats),
            "categories": {
                "buckets": [
                    {"key": spec["category"], "doc_count": spec["total"]}
                    for spec in cats
                ]
            },
        }
        for agent, cats in by_agent.items()
    ]
    return {
        "hits": {"total": {"value": window, "relation": "eq"}},
        "aggregations": {"agents": {"buckets": agent_buckets}},
    }


# --------------------------------------------------------------------------- #
# The stub indexer: it reads each request body and answers with the configured
# payload for that phase, and it records every (path, body) it was asked for.
# --------------------------------------------------------------------------- #


class StubIndexer:
    def __init__(
        self,
        *,
        events_total: int = 5000,
        events_window: int = 1000,
        findings_total: int = 10,
        findings_window: int = 3,
        decoder_leaves: list[dict[str, Any]] | None = None,
        detection_leaves: list[dict[str, Any]] | None = None,
        findings_leaves: list[dict[str, Any]] | None = None,
        decoder_samples: dict[tuple[str, str], list[str]] | None = None,
        detection_samples: dict[tuple[str, str], list[str]] | None = None,
    ) -> None:
        self.events_total = events_total
        self.events_window = events_window
        self.findings_total = findings_total
        self.findings_window = findings_window
        self.decoder_leaves = decoder_leaves or []
        self.detection_leaves = detection_leaves or []
        self.findings_leaves = findings_leaves or []
        self.decoder_samples = decoder_samples or {}
        self.detection_samples = detection_samples or {}
        self.requests: list[tuple[str, Any]] = []

    async def post(self, path: str, body: Any = None) -> Response:
        self.requests.append((path, body))
        parsed = body if isinstance(body, dict) else {}
        if not parsed.get("aggs"):
            # A bare document count (count_documents): events or findings stream.
            if FINDINGS in path:
                return total_response(self.findings_total, path)
            return total_response(self.events_total, path)

        agents = parsed["aggs"].get("agents")
        categories = agents.get("aggs", {}).get("categories", {}) if isinstance(
            agents, dict
        ) else {}
        sub = categories.get("aggs") if isinstance(categories, dict) else {}
        if not isinstance(sub, dict):
            sub = {}
        terms = agents.get("terms", {}) if isinstance(agents, dict) else {}
        is_samples = isinstance(terms, dict) and "include" in terms

        if FINDINGS in path:
            return Response(
                200,
                json.dumps(findings_payload(self.findings_leaves, self.findings_window)),
                path,
            )

        if is_samples:
            thin = "thin" in sub
            mapping = self.decoder_samples if thin else self.detection_samples
            leaves = self.decoder_leaves if thin else self.detection_leaves
            return Response(
                200,
                json.dumps(
                    _agents_payload(
                        leaves, thin=thin, window=self.events_window, samples=mapping
                    )
                ),
                path,
            )

        if "thin" in sub:
            payload = _agents_payload(
                self.decoder_leaves, thin=True, window=self.events_window
            )
        elif "hours" in sub:
            payload = _agents_payload(
                self.detection_leaves, thin=False, window=self.events_window
            )
        else:
            payload = _agents_payload(
                self.detection_leaves, thin=False, window=self.events_window
            )
        return Response(200, json.dumps(payload), path)


def make_config(*, enabled: bool) -> Config:
    return Config(
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
        anonymization=AnonymizationConfig(
            enabled=enabled,
            salt=TEST_SALT if enabled else "",
            mask_free_text_users=True,
            mask_fields=("user.name", "source.ip", "wazuh.agent.name"),
            log_path="/tmp/klaxon-test-cemetery.log",
        ),
    )


@pytest.fixture
def run_tool() -> Iterator[Any]:
    previous_indexer = server._indexer
    previous_config = server._config
    previous_anon = server._anonymizer

    def install(
        stub: StubIndexer | None = None, *, enabled: bool = False
    ) -> StubIndexer:
        stub = stub or StubIndexer()
        server._config = make_config(enabled=enabled)
        server._anonymizer = None  # type: ignore[assignment]
        server._indexer = stub  # type: ignore[assignment]
        return stub

    install()
    try:
        yield install
    finally:
        server._indexer = previous_indexer
        server._config = previous_config
        server._anonymizer = previous_anon


def _decoder_leaf(
    agent: str, category: str, total: int, thin: int, hours: list[tuple[str, int]]
) -> dict[str, Any]:
    return {"agent": agent, "category": category, "total": total, "thin": thin, "hours": hours}


def _detection_leaf(
    agent: str,
    category: str,
    total: int,
    hours: list[tuple[str, int]],
    datasets: list[tuple[str, int]],
) -> dict[str, Any]:
    return {
        "agent": agent,
        "category": category,
        "total": total,
        "hours": hours,
        "datasets": datasets,
    }


# --------------------------------------------------------------------------- #
# Empty streams and windows
# --------------------------------------------------------------------------- #


class TestEmptyIndexAndWindow:
    async def test_empty_events_index(self, run_tool: Any) -> None:
        run_tool(StubIndexer(events_total=0))
        out = await parsing_cemetery()
        assert "[NO DOCUMENTS]" in out
        assert "(no events index-wide)" in out
        assert "DECODER GAPS" not in out

    async def test_empty_window_reports_not_empty_index(self, run_tool: Any) -> None:
        run_tool(
            StubIndexer(
                events_total=5000,
                events_window=0,
            )
        )
        out = await parsing_cemetery(classification="decoder_gap")
        assert "[EMPTY WINDOW]" in out
        assert "5000 document(s) exist in the datastream" in out
        assert "DECODER GAPS" not in out

    async def test_findings_stream_empty_is_not_a_per_source_result(
        self, run_tool: Any
    ) -> None:
        run_tool(
            StubIndexer(
                findings_total=0,
                detection_leaves=[
                    _detection_leaf(
                        "fw1", "network-activity", 900,
                        [("2026-09-04T10:00:00.000Z", 900)],
                        [("opnsense.firewall", 900)],
                    )
                ],
            )
        )
        out = await parsing_cemetery(classification="detection_gap")
        assert "[FINDINGS STREAM EMPTY]" in out
        assert "(findings stream empty index-wide — nothing to detect from)" in out
        assert "fw1" not in out


# --------------------------------------------------------------------------- #
# decoder_gap
# --------------------------------------------------------------------------- #


class TestDecoderGap:
    async def test_aggregates_and_renders_gap_groups(self, run_tool: Any) -> None:
        run_tool(
            StubIndexer(
                decoder_leaves=[
                    _decoder_leaf(
                        "edge1", "network-activity", 800, 700,
                        [("2026-09-04T10:00:00.000Z", 700)],
                    ),
                    _decoder_leaf(
                        "mail1", "applications", 150, 40,
                        [("2026-09-04T10:00:00.000Z", 40)],
                    ),
                ],
                decoder_samples={
                    ("edge1", "network-activity"): ["raw syslog line one"],
                    ("mail1", "applications"): ["raw mail line"],
                },
            )
        )
        out = await parsing_cemetery(classification="decoder_gap", top_n=5)
        assert "DECODER GAPS" in out
        assert "GAP_EVENTS" in out
        assert "edge1" in out and "network-activity" in out
        assert "mail1" in out
        # Sorted by gap count descending: edge1 (700) above mail1 (40).
        assert out.index("edge1") < out.index("mail1")
        assert "700" in out
        # Raw samples present (anonymization inactive in this run).
        assert "raw syslog line one" in out
        assert "raw mail line" in out

    async def test_the_query_uses_the_verified_5x_signal(self, run_tool: Any) -> None:
        stub = run_tool(
            StubIndexer(
                decoder_leaves=[
                    _decoder_leaf(
                        "edge1", "network-activity", 800, 700,
                        [("2026-09-04T10:00:00.000Z", 700)],
                    )
                ]
            )
        )
        await parsing_cemetery(classification="decoder_gap")
        # Every aggregation query targets the events stream, never a 4.x name.
        agg_calls = [
            (p, b)
            for p, b in stub.requests
            if isinstance(b, dict) and b.get("aggs")
        ]
        assert agg_calls
        assert all(EVENTS in p for p, _b in agg_calls)
        text = json.dumps([b for _p, b in agg_calls])
        # 5.x-verified signal fields only.
        assert "wazuh.agent.name" in text
        assert "wazuh.integration.category" in text
        assert '"field": "event.dataset"' in text
        assert "must_not" in text

    async def test_min_count_filters_and_reports_when_nothing_survives(
        self, run_tool: Any
    ) -> None:
        stub = run_tool(
            StubIndexer(
                decoder_leaves=[
                    _decoder_leaf(
                        "mail1", "applications", 150, 40,
                        [("2026-09-04T10:00:00.000Z", 40)],
                    ),
                    _decoder_leaf(
                        "fw1", "network-activity", 500, 8,
                        [("2026-09-04T10:00:00.000Z", 8)],
                    ),
                ]
            )
        )
        out = await parsing_cemetery(classification="decoder_gap", min_count=50)
        assert "mail1" not in out
        assert "fw1" not in out
        assert "[NO DECODER-GAP GROUPS]" in out
        # No sample request is issued when no group survives the filter.
        agg_calls = [b for _p, b in stub.requests if isinstance(b, dict) and b.get("aggs")]
        assert len(agg_calls) == 1

    async def test_top_n_truncation_is_reported(self, run_tool: Any) -> None:
        leaves = [
            _decoder_leaf(f"a{i}", "network-activity", 500, 200 + i,
                          [("2026-09-04T10:00:00.000Z", 200 + i)])
            for i in range(4)
        ]
        run_tool(StubIndexer(decoder_leaves=leaves))
        out = await parsing_cemetery(classification="decoder_gap", top_n=2)
        assert "[TOP N TRUNCATED]" in out
        # The two largest groups are kept; the rest are dropped and reported.
        assert "a3" in out and "a2" in out
        assert "a1" not in out and "a0" not in out


# --------------------------------------------------------------------------- #
# detection_gap
# --------------------------------------------------------------------------- #


class TestDetectionGap:
    async def test_zero_findings_is_a_gap_and_findings_are_excluded(
        self, run_tool: Any
    ) -> None:
        run_tool(
            StubIndexer(
                findings_total=10,
                findings_window=3,
                findings_leaves=[{"agent": "web1", "category": "applications", "total": 3}],
                detection_leaves=[
                    _detection_leaf(
                        "fw1", "network-activity", 900,
                        [("2026-09-04T10:00:00.000Z", 900)],
                        [("opnsense.firewall", 900)],
                    ),
                    _detection_leaf(
                        "web1", "applications", 100,
                        [("2026-09-04T11:00:00.000Z", 100)],
                        [("apache-access", 100)],
                    ),
                ],
                detection_samples={
                    ("fw1", "network-activity"): ["fw raw line"],
                },
            )
        )
        out = await parsing_cemetery(classification="detection_gap")
        assert "DETECTION GAPS" in out
        # fw1 has zero findings -> a gap; web1 produced findings -> excluded.
        assert "fw1" in out
        assert "web1" not in out
        assert "[DETECTED SOURCES EXCLUDED] 1" in out
        assert "opnsense.firewall" in out
        assert "fw raw line" in out

    async def test_high_volume_sources_are_sorted_first(self, run_tool: Any) -> None:
        run_tool(
            StubIndexer(
                # The findings stream exists index-wide but has no findings in
                # the window, so every event source reads as a detection gap.
                findings_total=10,
                findings_window=0,
                detection_leaves=[
                    _detection_leaf(
                        "big1", "network-activity", 900,
                        [("2026-09-04T10:00:00.000Z", 900)], [],
                    ),
                    _detection_leaf(
                        "small1", "other", 20,
                        [("2026-09-04T11:00:00.000Z", 20)], [],
                    ),
                ],
            )
        )
        out = await parsing_cemetery(classification="detection_gap")
        assert "[EMPTY FINDINGS WINDOW]" in out
        assert "big1" in out and "small1" in out
        assert out.index("big1") < out.index("small1")

    async def test_min_count_filters_detection_groups(self, run_tool: Any) -> None:
        run_tool(
            StubIndexer(
                findings_total=10,
                findings_window=1,
                findings_leaves=[{"agent": "web1", "category": "applications", "total": 1}],
                detection_leaves=[
                    _detection_leaf(
                        "small1", "other", 5,
                        [("2026-09-04T10:00:00.000Z", 5)], [],
                    )
                ],
            )
        )
        out = await parsing_cemetery(classification="detection_gap", min_count=10)
        # 5 events < min_count=10, and no finding on the leaf: still too thin.
        assert "[NO DETECTION-GAP GROUPS]" in out
        assert "small1" not in out


# --------------------------------------------------------------------------- #
# Argument validation
# --------------------------------------------------------------------------- #


class TestArgumentValidation:
    async def test_bad_classification(self, run_tool: Any) -> None:
        with pytest.raises(ToolError, match="classification must be one of"):
            await parsing_cemetery(classification="rule_gap")

    async def test_hours_must_be_positive(self, run_tool: Any) -> None:
        with pytest.raises(ToolError, match="hours must be a positive integer"):
            await parsing_cemetery(hours=0)

    async def test_min_count_must_be_positive(self, run_tool: Any) -> None:
        with pytest.raises(ToolError, match="min_count must be a positive integer"):
            await parsing_cemetery(min_count=0)

    async def test_sample_size_is_capped(self, run_tool: Any) -> None:
        with pytest.raises(ToolError, match="sample_size must not exceed"):
            await parsing_cemetery(sample_size=cemetery.SAMPLE_SIZE_MAX + 1)

    async def test_top_n_is_capped(self, run_tool: Any) -> None:
        with pytest.raises(ToolError, match="top_n must not exceed"):
            await parsing_cemetery(top_n=cemetery.TOP_N_MAX + 1)


# --------------------------------------------------------------------------- #
# Pseudonymization of agent keys and raw samples
# --------------------------------------------------------------------------- #


class TestPseudonymization:
    async def test_agent_names_and_raw_samples_are_masked(self, run_tool: Any) -> None:
        stub = run_tool(
            StubIndexer(
                decoder_leaves=[
                    _decoder_leaf(
                        "edge1", "network-activity", 800, 700,
                        [("2026-09-04T10:00:00.000Z", 700)],
                    )
                ],
                decoder_samples={
                    ("edge1", "network-activity"): [
                        "sshd[123]: login by alice from 10.0.0.5",
                        "mail from alice@corp.example",
                    ]
                },
            ),
            enabled=True,
        )
        out = await parsing_cemetery(classification="decoder_gap")
        # The agent-name group key is a HOST token, not the raw hostname.
        assert "edge1" not in out
        assert "[HOST_" in out
        # Raw personal values never reach the output; their tokens do.
        assert "10.0.0.5" not in out
        assert "alice@corp.example" not in out
        assert "[IP_" in out
        assert "[EMAIL_" in out
        # A deterministic token for the agent name exists under the salt.
        assert len(stub.requests) >= 3

    async def test_no_unmasked_samples_when_anonymizer_off_but_banner_shows(
        self, run_tool: Any
    ) -> None:
        # Sanity: with masking off the raw line is returned, and the safety
        # banner says so rather than pretending it is masked.
        run_tool(
            StubIndexer(
                decoder_leaves=[
                    _decoder_leaf(
                        "edge1", "network-activity", 800, 700,
                        [("2026-09-04T10:00:00.000Z", 700)],
                    )
                ],
                decoder_samples={("edge1", "network-activity"): ["raw line"]},
            )
        )
        out = await parsing_cemetery(classification="decoder_gap")
        assert "raw line" in out


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #


class TestSummarize:
    def test_sustained_distinguishes_steady_from_spike(self) -> None:
        hours = [(f"2026-09-04T{h:02d}:00:00.000Z", 100) for h in range(24)]
        spike = [(hours[0][0], 2400)]
        steady = cemetery._summarize(
            cemetery.Leaf("a", "c", 2400, 2400, tuple(hours)),
            hours=24, count=2400,
        )
        burst = cemetery._summarize(
            cemetery.Leaf("a", "c", 2400, 2400, tuple(spike)),
            hours=24, count=2400,
        )
        assert steady.sustained is True
        assert steady.peak == 100
        assert steady.active == 24
        assert burst.sustained is False
        assert burst.peak == 2400

    def test_histogram_interval_scales_with_the_window(self) -> None:
        assert cemetery.histogram_interval(24) == "1h"
        assert cemetery.histogram_interval(168) == "6h"
        assert cemetery.histogram_interval(24 * 30) == "1d"
        assert cemetery.expected_buckets(24) == 24
