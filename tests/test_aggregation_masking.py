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
from mcp.server.mcpserver.exceptions import ToolError

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


def config_with(
    *,
    enabled: bool,
    mask_agg_keys: bool,
    block_unmappable: str = "block",
    block_unmappable_features: str = "block",
    mask_free_text_users: bool = True,
) -> Config:
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
            block_unmappable_aggs=block_unmappable,
            block_unmappable_features=block_unmappable_features,
            mask_free_text_users=mask_free_text_users,
            mask_fields=(
                "source.ip",
                "related.hosts",
                "related.user",
                "user.name",
                "wazuh.agent.name",
                "host.hostname",
                "user.id",
                "wazuh.agent.host.hostname",
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
    def __init__(
        self,
        payload: dict[str, Any] | None = None,
        status: int = 200,
    ) -> None:
        self.payload = payload if payload is not None else PAYLOAD
        self.status = status
        self.last_body: Any = None

    async def post(self, path: str, body: Any = None) -> Response:
        self.last_body = body
        return Response(
            self.status, json.dumps(self.payload), f"https://indexer.example{path}"
        )


@pytest.fixture
def run_search() -> Iterator[Any]:
    """Install stub indexer, a fresh config and a freshly built anonymizer."""
    previous_indexer = server._indexer
    previous_config = server._config
    previous_anon = server._anonymizer

    def install(
        enabled: bool,
        mask_agg_keys: bool,
        payload: dict[str, Any] | None = None,
        block_unmappable: str = "block",
        block_unmappable_features: str = "block",
        mask_free_text_users: bool = True,
        status: int = 200,
    ) -> None:
        server._config = config_with(
            enabled=enabled,
            mask_agg_keys=mask_agg_keys,
            block_unmappable=block_unmappable,
            block_unmappable_features=block_unmappable_features,
            mask_free_text_users=mask_free_text_users,
        )
        # Rebuild the cached anonymizer from the config above.
        server._anonymizer = None  # type: ignore[assignment]
        server._indexer = RecordingIndexer(payload, status)  # type: ignore[assignment]

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


# --------------------------------------------------------------------------- #
# Teil 12.3 — fail-closed block on unmappable aggregations + deep value pass
# --------------------------------------------------------------------------- #


SCRIPTED_BODY: dict[str, Any] = {
    "size": 0,
    "aggs": {
        "scripted": {
            "scripted_metric": {
                "init_script": "state.hosts = []",
                "map_script": "state.hosts.add(doc['wazuh.agent.host.hostname'].value)",
                "combine_script": "return state.hosts",
            }
        }
    },
}

UNKNOWN_BODY: dict[str, Any] = {"size": 0, "aggs": {"weird": {"weird_agg": {}}}}


class TestSearchFailClosedUnmappableAggs:
    """`block_unmappable_aggs` is an ACTIVE security control: a scripted_metric
    (or any unknown aggregation type) request is rejected BEFORE it reaches the
    indexer — never silently passed with HTTP 200."""

    async def test_scripted_metric_request_rejected_by_default(
        self, run_search: Any
    ) -> None:
        """The exact finding: scripted_metric reading wazuh.agent.host.hostname.
        Default (block) -> ToolError naming the agg type; indexer never called."""
        run_search(True, True)
        indexer = server._indexer
        assert indexer is not None and isinstance(indexer, RecordingIndexer)
        with pytest.raises(ToolError, match="scripted_metric"):
            await run(SCRIPTED_BODY)
        assert indexer.last_body is None  # request-side gate: never executed

    async def test_unknown_agg_type_rejected_by_default(self, run_search: Any) -> None:
        run_search(True, True)
        indexer = server._indexer
        assert indexer is not None and isinstance(indexer, RecordingIndexer)
        with pytest.raises(ToolError, match="weird_agg"):
            await run(UNKNOWN_BODY)
        assert indexer.last_body is None

    async def test_safe_agg_request_still_served(self, run_search: Any) -> None:
        """The gate must not reject mapped/safe aggregations."""
        run_search(True, True)
        out = await run(
            {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        )
        assert ph("HOST", "nc02web") in out

    async def test_block_does_not_fire_when_anonymization_inactive(
        self, run_search: Any
    ) -> None:
        """A local/disabled anonymizer has no masking guarantee to enforce —
        the operator chose not to mask, so no block (request reaches indexer)."""
        run_search(False, True)
        indexer = server._indexer
        assert indexer is not None and isinstance(indexer, RecordingIndexer)
        out = await run(SCRIPTED_BODY)
        assert "scripted_metric" in json.dumps(indexer.last_body)  # served through
        assert "nc02web" in out  # response returned unmasked

    async def test_drop_mode_strips_offending_agg(self, run_search: Any) -> None:
        """Config-selectable "drop": the offending aggregation is removed from
        the request before it is executed; a notice says so; safe aggs remain."""
        run_search(True, True, block_unmappable="drop")
        indexer = server._indexer
        assert indexer is not None and isinstance(indexer, RecordingIndexer)
        body = {
            "size": 0,
            "aggs": {
                "hosts": {"terms": {"field": "related.hosts"}},
                "scripted": {
                    "scripted_metric": {"map_script": "x"}
                },
            },
        }
        out = await run(body)
        assert "[UNMAPPABLE AGG DROPPED]" in out
        assert indexer.last_body is not None
        # The scripted agg never reached the indexer; the safe one did.
        assert "scripted_metric" not in json.dumps(indexer.last_body)
        assert "hosts" in indexer.last_body.get("aggs", {})


# scripted_metric output echoing RAW masked-field values; `_source` carries the
# identities so the deep value pass reuses their exact tokens.
DEEP_PASS_PAYLOAD: dict[str, Any] = {
    "took": 3,
    "timed_out": False,
    "hits": {
        "total": {"value": 1, "relation": "eq"},
        "hits": [
            {
                "_source": {
                    "wazuh": {
                        "agent": {
                            "host": {"hostname": "Supergrobi.intern.moenig.it"}
                        }
                    },
                    "related": {"user": ["root", "marco"]},
                    "user": {"id": "e883b765-27d5-44f5-89ba-209a31ae3b89"},
                }
            }
        ],
    },
    "aggregations": {
        "scripted": {
            "value": [
                "Supergrobi.intern.moenig.it",
                "root",
                "marco",
                "e883b765-27d5-44f5-89ba-209a31ae3b89",
                "192.168.1.10",
                "system-activity",
            ]
        }
    },
}


class TestSearchDeepValuePass:
    """Defense-in-depth: when an opaque aggregation IS served (explicit "off"),
    its raw values are masked by value pattern + known-value registry."""

    async def test_opaque_values_are_masked_via_search(self, run_search: Any) -> None:
        run_search(True, True, DEEP_PASS_PAYLOAD, block_unmappable="off")
        out = await run(SCRIPTED_BODY)
        # The raw leak values never appear anywhere in the rendered output.
        for raw in (
            "Supergrobi.intern.moenig.it",
            "root",
            "marco",
            "e883b765-27d5-44f5-89ba-209a31ae3b89",
            "192.168.1.10",
        ):
            assert raw not in out
        # The opaque echoes reuse the exact `_source` tokens.
        assert ph("HOST", "Supergrobi.intern.moenig.it") in out
        assert ph("USER", "root") in out
        assert ph("USER", "marco") in out
        assert ph("USER", "e883b765-27d5-44f5-89ba-209a31ae3b89") in out
        assert ph("IP", "192.168.1.10") in out
        # Unmasked free text (category) is untouched.
        assert "system-activity" in out


# --------------------------------------------------------------------------- #
# Teil 13 — fail-closed gate on opaque request features + error-body withholding
# --------------------------------------------------------------------------- #

RUNTIME_MAPPINGS_BODY: dict[str, Any] = {
    "size": 0,
    "runtime_mappings": {
        "rt_user": {"type": "keyword", "script": {"source": "emit(doc['user.name'].value)"}}
    },
    "aggs": {"by_rt_user": {"terms": {"field": "rt_user"}}},
}

SCRIPT_FIELDS_BODY: dict[str, Any] = {
    "size": 1,
    "script_fields": {"who": {"script": {"source": "params._source.user.name;"}}},
}

SUGGEST_BODY: dict[str, Any] = {
    "size": 0,
    "suggest": {"u": {"text": "root", "term": {"field": "user.name"}}},
}

HIGHLIGHT_BODY: dict[str, Any] = {
    "size": 1,
    "highlight": {"fields": {"message": {"fragment_size": 80}}},
}


class TestSearchFailClosedUnmappableFeatures:
    """Teil 13: `block_unmappable_features` is an ACTIVE security control — a
    request carrying runtime_mappings / script_fields / suggest / highlight is
    rejected BEFORE it reaches the indexer (fail-closed), "drop" strips the
    section, "off" serves it with only the response-side deep value pass."""

    async def test_script_fields_rejected_by_default(
        self, run_search: Any
    ) -> None:
        run_search(True, True)
        indexer = server._indexer
        assert indexer is not None and isinstance(indexer, RecordingIndexer)
        with pytest.raises(ToolError, match="script_fields"):
            await run(SCRIPT_FIELDS_BODY)
        assert indexer.last_body is None  # request-side gate: never executed

    async def test_runtime_mappings_rejected_by_default(
        self, run_search: Any
    ) -> None:
        run_search(True, True)
        with pytest.raises(ToolError, match="runtime_mappings"):
            await run(RUNTIME_MAPPINGS_BODY)

    async def test_suggest_rejected_by_default(self, run_search: Any) -> None:
        run_search(True, True)
        with pytest.raises(ToolError, match="suggest"):
            await run(SUGGEST_BODY)

    async def test_highlight_rejected_by_default(self, run_search: Any) -> None:
        run_search(True, True)
        with pytest.raises(ToolError, match="highlight"):
            await run(HIGHLIGHT_BODY)

    async def test_safe_request_still_served(self, run_search: Any) -> None:
        run_search(True, True)
        out = await run(
            {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        )
        assert ph("HOST", "nc02web") in out

    async def test_block_does_not_fire_when_anonymization_inactive(
        self, run_search: Any
    ) -> None:
        """A local/disabled anonymizer has no masking guarantee to enforce."""
        run_search(False, True)
        indexer = server._indexer
        assert indexer is not None and isinstance(indexer, RecordingIndexer)
        out = await run(SCRIPT_FIELDS_BODY)
        # Served through to the indexer (no 4xx from the Klaxon gate); the
        # stub returns its fixed payload unmasked.
        assert "script_fields" in json.dumps(indexer.last_body)
        assert "nc02web" in out

    async def test_drop_mode_strips_the_feature(self, run_search: Any) -> None:
        """"drop": the offending top-level section is removed from the request
        before it is executed; a notice says so; safe keys remain."""
        run_search(True, True, block_unmappable_features="drop")
        indexer = server._indexer
        assert indexer is not None and isinstance(indexer, RecordingIndexer)
        body = {
            "size": 0,
            "script_fields": {"who": {"script": {"source": "1"}}},
            "aggs": {"hosts": {"terms": {"field": "related.hosts"}}},
        }
        out = await run(body)
        assert "[UNMAPPABLE FEATURE DROPPED]" in out
        assert indexer.last_body is not None
        assert "script_fields" not in json.dumps(indexer.last_body)
        assert "hosts" in indexer.last_body.get("aggs", {})

    async def test_off_mode_serves_with_deep_value_pass(self, run_search: Any) -> None:
        """Explicit "off": the feature is served, and the response-side deep
        value pass masks the raw echoes (fields alias under a new name)."""
        payload = {
            "hits": {
                "total": {"value": 1, "relation": "eq"},
                "hits": [
                    {
                        "_source": {"user": {"name": "marco"}},
                        "fields": {"who": ["marco"]},
                    }
                ],
            }
        }
        run_search(True, True, payload, block_unmappable_features="off")
        out = await run(SCRIPT_FIELDS_BODY)
        assert "marco" not in out
        assert ph("USER", "marco") in out


class TestSearchErrorBodyWithheld:
    """Teil 13: an indexer error body can echo the raw query and is opaque to
    the walker — with anonymization active it is withheld from the served
    output (fail-closed), while the notice still names status/type."""

    async def test_error_body_withheld_when_active(self, run_search: Any) -> None:
        payload = {
            "error": {
                "type": "parsing_exception",
                "reason": "failed to parse field [marco] for type [keyword]",
            },
            "status": 400,
        }
        run_search(True, True, payload, status=400)
        out = await run({"size": 0})
        assert "HTTP 400" in out
        assert "[BODY WITHHELD]" in out
        assert "marco" not in out
        assert "parsing_exception" in out  # type is an enumeration, safe

    async def test_error_body_passed_through_when_inactive(
        self, run_search: Any
    ) -> None:
        payload = {
            "error": {"type": "parsing_exception", "reason": "bad [marco]"},
            "status": 400,
        }
        run_search(False, True, payload, status=400)
        out = await run({"size": 0})
        assert "marco" in out  # operator chose unmasked mode: body passes through

    async def test_ok_response_body_not_withheld(self, run_search: Any) -> None:
        run_search(True, True)
        out = await run(
            {"size": 0, "aggs": {"hosts": {"terms": {"field": "related.hosts"}}}}
        )
        assert "[BODY WITHHELD]" not in out
        assert ph("HOST", "nc02web") in out

    async def test_shard_failures_notice_and_stripped_body(
        self, run_search: Any
    ) -> None:
        """A 200 response with a failed shard: the notice names the count and
        the raw `failures` array (which echoes the query) is stripped."""
        payload = {
            "_shards": {
                "total": 8,
                "successful": 7,
                "failed": 1,
                "failures": [
                    {
                        "shard": 0,
                        "index": ".ds-x-000001",
                        "reason": {
                            "type": "script_exception",
                            "script": "params._source.user.name;",
                        },
                    }
                ],
            },
            "hits": {"total": {"value": 1, "relation": "eq"}, "hits": []},
        }
        run_search(True, True, payload)
        out = await run({"size": 0})
        assert "[SHARD FAILURES]" in out
        assert "params._source" not in out
        assert "failures" not in out
