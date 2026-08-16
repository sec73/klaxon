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
import hmac
import json
from collections.abc import Iterator
from typing import Any

import pytest

from klaxon_mcp import server
from klaxon_mcp.clients import Response
from klaxon_mcp.config import AnonymizationConfig, Config
from klaxon_mcp.server import search

TEST_SALT = "klaxon-test-salt"


def ph(kind: str, value: str) -> str:
    digest = hmac.new(
        TEST_SALT.encode("utf-8"), f"{kind}:{value}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"[{kind}_{digest[:16]}]"


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
                "related.user",
                "user.name",
                "wazuh.agent.name",
            ),
            salt=TEST_SALT,
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
    def __init__(self, payload: dict[str, Any] | None = None) -> None:
        self.payload = payload if payload is not None else PAYLOAD

    async def post(self, path: str, body: Any = None) -> Response:
        return Response(200, json.dumps(self.payload), f"https://indexer.example{path}")


@pytest.fixture
def run_search() -> Iterator[Any]:
    """Install stub indexer, a fresh config and a freshly built anonymizer."""
    previous_indexer = server._indexer
    previous_config = server._config
    previous_anon = server._anonymizer

    def install(
        enabled: bool, mask_agg_keys: bool, payload: dict[str, Any] | None = None
    ) -> None:
        server._config = config_with(enabled=enabled, mask_agg_keys=mask_agg_keys)
        # Rebuild the cached anonymizer from the config above.
        server._anonymizer = None  # type: ignore[assignment]
        server._indexer = RecordingIndexer(payload)  # type: ignore[assignment]

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


# A response shaped EXACTLY like OpenSearch serves it: the nested sub-agg sits
# DIRECTLY in the bucket (siblings of `key`/`doc_count`), with no
# "aggregations" wrapper.
NESTED_PAYLOAD: dict[str, Any] = {
    "took": 3,
    "timed_out": False,
    "hits": {
        "total": {"value": 1, "relation": "eq"},
        "hits": [],
    },
    "aggregations": {
        "hosts": {
            "doc_count_error_upper_bound": 0,
            "sum_other_doc_count": 1,
            "buckets": [
                {
                    "key": "nc02web",
                    "doc_count": 3,
                    "users": {
                        "buckets": [
                            {"key": "root", "doc_count": 2},
                            {"key": "podomoro", "doc_count": 1},
                        ]
                    },
                }
            ],
        }
    },
}

# agents -> categories: the nested category field is NOT in mask_fields.
NESTED_CATEGORY_PAYLOAD: dict[str, Any] = {
    "took": 3,
    "timed_out": False,
    "hits": {"total": {"value": 1, "relation": "eq"}, "hits": []},
    "aggregations": {
        "agents": {
            "buckets": [
                {
                    "key": "web-server-01",
                    "doc_count": 3,
                    "categories": {
                        "buckets": [
                            {"key": "cloud-services", "doc_count": 2},
                            {"key": "security", "doc_count": 1},
                        ]
                    },
                }
            ]
        }
    },
}

# Masked stream: keys are ALREADY tokens (ingest-time masking).
TOKENISED_PAYLOAD: dict[str, Any] = {
    "took": 3,
    "timed_out": False,
    "hits": {"total": {"value": 1, "relation": "eq"}, "hits": []},
    "aggregations": {
        "hosts": {
            "buckets": [
                {
                    "key": "[HOST_aaaaaaaaaaaaaaaa]",
                    "doc_count": 3,
                    "users": {
                        "buckets": [
                            {"key": "[USER_bbbbbbbbbbbbbbbb]", "doc_count": 2}
                        ]
                    },
                }
            ]
        }
    },
}

# multi_terms [related.hosts, wazuh.integration.category] with OpenSearch's
# generated key_as_string (fields joined with "|") carrying a RAW hostname —
# the exact leak under test.
MULTI_TERMS_PAYLOAD: dict[str, Any] = {
    "took": 3,
    "timed_out": False,
    "hits": {"total": {"value": 1, "relation": "eq"}, "hits": []},
    "aggregations": {
        "pairs": {
            "buckets": [
                {
                    "key": ["brummfidel.sec73.io", "system-activity"],
                    "key_as_string": "brummfidel.sec73.io|system-activity",
                    "doc_count": 3,
                }
            ]
        }
    },
}


class TestSearchNestedAggregationMasking:
    async def test_nested_sub_agg_keys_are_tokenised_on_raw_stream(
        self, run_search: Any
    ) -> None:
        """The regression: `terms related.hosts -> terms related.user` on the
        RAW stream (wazuh-events-v5-*). The walker must tokenise the top-level
        AND the nested sub-agg keys — before the fix the nested `related.user`
        keys came back RAW. Run against a raw-stream-shaped index so the
        response walker itself is exercised."""
        run_search(True, True, NESTED_PAYLOAD)
        out = await run(
            {
                "size": 0,
                "aggs": {
                    "hosts": {
                        "terms": {"field": "related.hosts"},
                        "aggs": {"users": {"terms": {"field": "related.user"}}},
                    }
                },
            }
        )
        assert ph("HOST", "nc02web") in out
        assert ph("USER", "root") in out
        assert ph("USER", "podomoro") in out
        assert "nc02web" not in out
        assert '"key": "root"' not in out
        assert '"key": "podomoro"' not in out

    async def test_nested_unmasked_category_keys_stay_raw(
        self, run_search: Any
    ) -> None:
        """`terms wazuh.agent.name -> terms wazuh.integration.category`: the top
        key is masked, the nested category keys remain readable (regression)."""
        run_search(True, True, NESTED_CATEGORY_PAYLOAD)
        out = await run(
            {
                "size": 0,
                "aggs": {
                    "agents": {
                        "terms": {"field": "wazuh.agent.name"},
                        "aggs": {
                            "categories": {
                                "terms": {"field": "wazuh.integration.category"}
                            }
                        },
                    }
                },
            }
        )
        assert ph("HOST", "web-server-01") in out
        assert '"key": "cloud-services"' in out
        assert '"key": "security"' in out

    async def test_masked_stream_sub_agg_tokens_pass_through(
        self, run_search: Any
    ) -> None:
        """Masked stream: sub-agg keys are already tokens; they pass through
        unchanged (idempotent), never re-tokenised."""
        run_search(True, True, TOKENISED_PAYLOAD)
        out = await run(
            {
                "size": 0,
                "aggs": {
                    "hosts": {
                        "terms": {"field": "related.hosts"},
                        "aggs": {"users": {"terms": {"field": "related.user"}}},
                    }
                },
            }
        )
        assert "[HOST_aaaaaaaaaaaaaaaa]" in out
        assert "[USER_bbbbbbbbbbbbbbbb]" in out
        # No double-masking: the exact token (16 hex) appears, not a re-hash.
        assert "[HOST_aaaaaaaaaaaaaaaa]" in out
        assert "[USER_bbbbbbbbbbbbbbbb]" in out

    async def test_multi_terms_key_as_string_has_no_raw_value_on_raw_stream(
        self, run_search: Any
    ) -> None:
        """multi_terms [related.hosts, wazuh.integration.category] on the raw
        stream: the OpenSearch-generated key_as_string is rebuilt from the
        masked key list — no raw hostname survives (the leak), and key_as_string
        equals "|".join(key)."""
        run_search(True, True, MULTI_TERMS_PAYLOAD)
        out = await run(
            {
                "size": 0,
                "aggs": {
                    "pairs": {
                        "multi_terms": {
                            "terms": [
                                {"field": "related.hosts"},
                                {"field": "wazuh.integration.category"},
                            ]
                        }
                    }
                },
            }
        )
        assert ph("HOST", "brummfidel.sec73.io") in out
        assert '"key_as_string": "[HOST_' in out
        assert "brummfidel.sec73.io" not in out
