# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Idempotent masking: values that are already Klaxon tokens pass through.

The Option B masked stream is tokenised by the ingest pipeline; the response
layer must never re-mask (or double-mask) those values. The passthrough guard
is value-shape based (`[FAMILY_<16 hex>]`), so it applies uniformly to
`_source` leaves, aggregation bucket keys and composite `after_key` values —
exactly the three places a masked-stream token can appear.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest

from klaxon_mcp.anonymization import IP, USER, Anonymizer, parse_agg_fields
from klaxon_mcp.clients import Response
from klaxon_mcp.config import AnonymizationConfig

TEST_SALT = "klaxon-test-salt"

MASK_FIELDS: tuple[str, ...] = (
    "destination.ip",
    "source.ip",
    "user.name",
    "user.effective.name",
    "related.ip",
    "related.user",
    "related.hosts",
    "host.hostname",
)


def anon(**overrides: Any) -> Anonymizer:
    overrides.setdefault("salt", TEST_SALT)
    overrides.setdefault("mask_aggregation_keys", True)
    overrides.setdefault("mask_fields", MASK_FIELDS)
    return Anonymizer(
        AnonymizationConfig(enabled=overrides.pop("enabled", True), **overrides)
    )


def token(kind: str, value: str) -> str:
    digest = hmac.new(
        TEST_SALT.encode("utf-8"), f"{kind}:{value}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"[{kind}_{digest[:16]}]"


class TestSourcePassthrough:
    def test_token_source_value_passes_through(self) -> None:
        t = token(USER, "jdoe")
        out = anon().mask_json({"_source": {"user.name": t}})
        assert out["_source"]["user.name"] == t

    def test_token_array_values_pass_through(self) -> None:
        t1 = token(IP, "10.0.0.1")
        t2 = token(IP, "10.0.0.2")
        out = anon().mask_json({"_source": {"related.ip": [t1, t2]}})
        assert out["_source"]["related.ip"] == [t1, t2]

    def test_non_token_value_is_still_masked(self) -> None:
        out = anon().mask_json({"_source": {"user.name": "jdoe"}})
        assert out["_source"]["user.name"] == token(USER, "jdoe")

    def test_free_text_with_embedded_token_is_not_remasked(self) -> None:
        t = token(USER, "jdoe")
        out = anon().mask_json(
            {"_source": {"message": f"login ok for {t} from 10.0.0.9"}}
        )
        msg = out["_source"]["message"]
        assert t in msg  # the existing token stays byte-identical
        assert token(IP, "10.0.0.9") in msg
        assert "10.0.0.9" not in msg


class TestAggregationKeyPassthrough:
    def _mask(self, response_body: Any, request_body: Any) -> dict[str, Any]:
        a = anon()
        response = Response(
            200, json.dumps(response_body), "https://indexer.example/_search"
        )
        masked = a.mask_response(response, agg_map=parse_agg_fields(request_body))
        return masked.json()

    def test_tokenized_terms_key_passes_through(self) -> None:
        t = token(USER, "jdoe")
        body = {"size": 0, "aggs": {"users": {"terms": {"field": "user.name"}}}}
        response = {"aggregations": {"users": {"buckets": [{"key": t, "doc_count": 3}]}}}
        masked = self._mask(response, body)
        assert masked["aggregations"]["users"]["buckets"][0]["key"] == t

    def test_tokenized_multi_terms_keys_pass_through(self) -> None:
        t1 = token(USER, "jdoe")
        t2 = token(IP, "10.0.0.1")
        body = {
            "aggs": {
                "combo": {"multi_terms": {"terms": [{"field": "user.name"}, {"field": "destination.ip"}]}}
            }
        }
        response = {
            "aggregations": {
                "combo": {
                    "buckets": [{"key": [t1, t2], "key_as_string": f"{t1}|{t2}", "doc_count": 1}]
                }
            }
        }
        masked = self._mask(response, body)
        bucket = masked["aggregations"]["combo"]["buckets"][0]
        assert bucket["key"] == [t1, t2]
        assert bucket["key_as_string"] == f"{t1}|{t2}"

    def test_tokenized_composite_after_key_passes_through(self) -> None:
        t1 = token(USER, "jdoe")
        t2 = token(IP, "10.0.0.1")
        body = {
            "aggs": {
                "pages": {
                    "composite": {
                        "sources": [
                            {"u": {"terms": {"field": "user.name"}}},
                            {"ip": {"terms": {"field": "destination.ip"}}},
                        ]
                    }
                }
            }
        }
        response = {
            "aggregations": {
                "pages": {
                    "buckets": [{"key": {"u": t1, "ip": t2}, "doc_count": 4}],
                    "after_key": {"u": t1, "ip": t2},
                }
            }
        }
        masked = self._mask(response, body)
        agg = masked["aggregations"]["pages"]
        assert agg["buckets"][0]["key"] == {"u": t1, "ip": t2}
        assert agg["after_key"] == {"u": t1, "ip": t2}

    def test_non_token_aggregation_key_is_still_masked(self) -> None:
        body = {"size": 0, "aggs": {"users": {"terms": {"field": "user.name"}}}}
        response = {"aggregations": {"users": {"buckets": [{"key": "jdoe", "doc_count": 3}]}}}
        masked = self._mask(response, body)
        assert masked["aggregations"]["users"]["buckets"][0]["key"] == token(USER, "jdoe")


class TestNoDoubleMasking:
    def test_remasking_a_masked_response_is_a_noop(self) -> None:
        a = anon()
        doc = {
            "_source": {
                "user.name": "jdoe",
                "related.ip": ["10.0.0.1"],
                "message": "user jdoe hit 10.0.0.1",
            }
        }
        once = a.mask_json(doc)
        twice = a.mask_json(once)
        assert twice == once

    def test_masked_stream_token_shape_is_never_modified(self) -> None:
        # The pipeline scheme ([FAMILY_<16 hex>]) is exactly what the response
        # layer's passthrough recognises, so stream tokens stay stable.
        pipeline_token = token(IP, "10.0.0.1")
        a = anon(masked_streams=("klaxon-masked-customer-a-v5*",))
        out = a.mask_json({"_source": {"source.ip": pipeline_token}})
        assert out["_source"]["source.ip"] == pipeline_token
