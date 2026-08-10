# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Aggregation-key masking through the `search` tool, end to end.

The anonymization layer must not let a `search` response leak the personal data
that lives in aggregation bucket keys, and only when the operator opts in via
KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS. These tests drive the real `search`
tool against a stub indexer and assert on the rendered output.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from typing import Any

import pytest

from klaxon_mcp import server
from klaxon_mcp.clients import Response
from klaxon_mcp.config import AnonymizationConfig, Config
from klaxon_mcp.server import search


def ph(kind: str, value: str) -> str:
    digest = hashlib.md5(value.encode("utf-8")).hexdigest()
    return f"[{kind}_{digest[:6]}]"


def config_with(*, enabled: bool, mask_agg_keys: bool) -> Config:
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
            mask_aggregation_keys=mask_agg_keys,
            mask_fields=(
                "source.ip",
                "related.hosts",
                "user.name",
                "wazuh.agent.name",
            ),
            log_path="/tmp/klaxon-test-agg-masking.log",
        ),
    )


# One host in `_source` and as a terms key, plus a username key: masking both
# places must leave no raw value anywhere in the rendered output.
PAYLOAD: dict[str, Any] = {
    "took": 3,
    "timed_out": False,
    "hits": {
        "total": {"value": 1, "relation": "eq"},
        "hits": [{"_source": {"related": {"hosts": ["nc02web"]}}}],
    },
    "aggregations": {
        "hosts": {"buckets": [{"key": "nc02web", "doc_count": 1}]},
        "users": {"buckets": [{"key": "root", "doc_count": 1}]},
    },
}


class RecordingIndexer:
    async def post(self, path: str, body: Any = None) -> Response:
        return Response(200, json.dumps(PAYLOAD), f"https://indexer.example{path}")


@pytest.fixture
def run_search() -> Iterator[Any]:
    """Install stub indexer, a fresh config and a freshly built anonymizer."""
    previous_indexer = server._indexer
    previous_config = server._config
    previous_anon = server._anonymizer

    def install(enabled: bool, mask_agg_keys: bool) -> None:
        server._config = config_with(enabled=enabled, mask_agg_keys=mask_agg_keys)
        # Rebuild the cached anonymizer from the config above.
        server._anonymizer = None  # type: ignore[assignment]
        server._indexer = RecordingIndexer()  # type: ignore[assignment]

    install(True, True)
    try:
        yield install
    finally:
        server._indexer = previous_indexer
        server._config = previous_config
        server._anonymizer = previous_anon


async def run(body: dict[str, Any]) -> str:
    return await search(index="wazuh-events-v5-*", body=json.dumps(body))


class TestSearchAggregationMasking:
    async def test_keys_are_tokenised_when_feature_on(self, run_search: Any) -> None:
        out = await run(
            {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        )
        assert ph("HOST", "nc02web") in out
        assert "nc02web" not in out

    async def test_source_and_agg_key_share_the_token(self, run_search: Any) -> None:
        out = await run(
            {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        )
        # The `_source` host and the aggregation key are the same entity, so the
        # same token appears in both places.
        assert out.count(ph("HOST", "nc02web")) >= 2

    async def test_doc_count_is_preserved(self, run_search: Any) -> None:
        out = await run(
            {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        )
        assert '"doc_count": 1' in out

    async def test_feature_off_leaves_keys_raw(self, run_search: Any) -> None:
        # Anonymization on, but aggregation-key masking off: byte-identical to
        # the pre-feature behaviour — `_source` is masked, agg keys are not.
        run_search(True, False)
        out = await run(
            {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        )
        assert '"key": "nc02web"' in out
        assert '"key": "[HOST_' not in out

    async def test_anonymization_disabled_passes_through(self, run_search: Any) -> None:
        run_search(False, True)
        out = await run(
            {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        )
        assert "nc02web" in out
        assert "[HOST_" not in out
