# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""LIVE integration test for NESTED aggregation-key masking (skippable).

Proves on a real OpenSearch/Wazuh 5 indexer that the response walker tokenises
sub-aggregation bucket keys at EVERY depth — the regression where a nested
`terms related.user` under `terms related.hosts` came back RAW. It queries the
RAW stream (`wazuh-events-v5-*`) so the walker itself is exercised, runs the
real `Anonymizer` over the live response, and asserts:

  * the nested `related.user` sub-bucket keys are tokens (the exact leak);
  * a nested UNMASKED field (`wazuh.integration.category` under
    `wazuh.agent.name`) stays readable;
  * `doc_count` / `sum_other_doc_count` are byte-identical raw vs masked.

Non-destructive: read-only `_search`. Skips cleanly when the credentials are
missing, the raw stream is unreachable, or the 24h window has no data for the
queried fields.

Credentials come ONLY from `KLAXON_INDEXER_URL` / `KLAXON_INDEXER_USER` /
`KLAXON_INDEXER_PASSWORD` (optionally a gitignored local `.env`), exactly like
`klaxon masking deploy` / `klaxon masking test`. The password, the salt and any
raw personal value from the live response are never logged.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from klaxon_mcp import live_test
from klaxon_mcp.anonymization import (
    _TOKEN_RE,
    Anonymizer,
    parse_agg_fields,
)
from klaxon_mcp.clients import Response
from klaxon_mcp.config import AnonymizationConfig
from klaxon_mcp.live_config import live_salt
from klaxon_mcp.masked_stream import load_tenant_config

pytestmark = [pytest.mark.integration, pytest.mark.live, pytest.mark.asyncio]

# The tenant whose effective mask list drives the anonymizer. Its fields.yaml
# lists both `related.hosts` (HOST) and `related.user` (USER) as mask fields,
# and does NOT list `wazuh.integration.category`.
LIVE_TENANT = "customer-a"

# The 24h window so the live search never scans the whole cluster.
_WINDOW = {"range": {"@timestamp": {"gte": "now-24h"}}}

# terms related.hosts -> terms related.user: the exact leak from the finding.
NESTED_BODY: dict[str, Any] = {
    "size": 0,
    "query": {"bool": {"filter": [_WINDOW]}},
    "aggs": {
        "hosts": {
            "terms": {"field": "related.hosts", "size": 20},
            "aggs": {"users": {"terms": {"field": "related.user", "size": 20}}},
        }
    },
}

# terms wazuh.agent.name -> terms wazuh.integration.category: nested UNMASKED.
CATEGORY_BODY: dict[str, Any] = {
    "size": 0,
    "query": {"bool": {"filter": [_WINDOW]}},
    "aggs": {
        "agents": {
            "terms": {"field": "wazuh.agent.name", "size": 20},
            "aggs": {
                "categories": {
                    "terms": {"field": "wazuh.integration.category", "size": 20}
                }
            },
        }
    },
}


@pytest.fixture
def live_config() -> tuple[live_test.LiveIndexerConfig, Any]:
    """(live credentials, tenant config) — skips cleanly when credentials are
    missing, so the live tests never fail a CI run without an indexer."""
    live, missing = live_test.resolve_live_config()
    if live is None:
        pytest.skip(
            f"live agg-masking test skipped: KLAXON_INDEXER_URL/USER/PASSWORD "
            f"are not all set (missing: {', '.join(missing)}). Export them or "
            "add a gitignored tests/live/.env / .env.live file — see "
            "tests/live/.env.example. The password is never logged."
        )
    return live, load_tenant_config(LIVE_TENANT)


def _client(live: live_test.LiveIndexerConfig) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=live.url,
        auth=(live.user, live.password),
        verify=live.verify_ssl,
        timeout=60.0,
        headers={"Content-Type": "application/json"},
    )


def _anonymizer(cfg: Any) -> Anonymizer:
    """An anonymizer over the tenant's effective mask list + live salt. The
    response layer and the walker share the token function, so a raw live value
    maps to the same token the `_source` pass would produce."""
    return Anonymizer(
        AnonymizationConfig(
            enabled=True,
            salt=live_salt(cfg),
            mask_fields=cfg.all_masked_fields,
            mask_aggregation_keys=True,
            log_path="/tmp/klaxon-live-agg-masking.log",
        )
    )


async def _live_search(
    client: httpx.AsyncClient, body: dict[str, Any]
) -> dict[str, Any]:
    resp = await client.post("/wazuh-events-v5-*/_search", json=body)
    if not resp.is_success:
        pytest.skip(
            f"live agg-masking test skipped: raw stream query returned HTTP "
            f"{resp.status_code} — is the cluster up and is wazuh-events-v5-* "
            "available?"
        )
    return resp.json()


def _sub_agg_buckets(
    masked: dict[str, Any], parent: str, child: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(parent buckets, child sub-agg buckets) from a masked response."""
    if "aggregations" not in masked or parent not in masked["aggregations"]:
        pytest.skip(
            f"live agg-masking test skipped: no {parent!r} aggregation in the "
            "response (no data in the 24h window?)"
        )
    parent_buckets = masked["aggregations"][parent].get("buckets", [])
    child_buckets: list[dict[str, Any]] = []
    for bucket in parent_buckets:
        if not isinstance(bucket, dict):
            continue
        sub = bucket.get(child)
        if isinstance(sub, dict) and isinstance(sub.get("buckets"), list):
            child_buckets.extend(sub["buckets"])
    if not child_buckets:
        pytest.skip(
            f"live agg-masking test skipped: no {child!r} sub-buckets under "
            f"{parent!r} in the 24h window"
        )
    return parent_buckets, child_buckets


async def test_live_nested_sub_agg_keys_tokenised_on_raw_stream(
    live_config: tuple[live_test.LiveIndexerConfig, Any],
) -> None:
    """`terms related.hosts -> terms related.user` on the RAW stream: the
    nested `related.user` sub-agg keys are tokens (the exact leak), and counts
    are byte-identical raw vs masked."""
    live, cfg = live_config
    anon = _anonymizer(cfg)
    agg_map = parse_agg_fields(NESTED_BODY)

    async with _client(live) as client:
        raw = await _live_search(client, NESTED_BODY)

    masked = anon.mask_response(
        Response(200, json.dumps(raw), "https://indexer/_search"), agg_map=agg_map
    ).json()

    parent_buckets, child_buckets = _sub_agg_buckets(masked, "hosts", "users")
    # The top-level keys are tokenised too — sanity that the walker ran.
    for bucket in parent_buckets:
        assert _TOKEN_RE.match(str(bucket["key"])), (
            "top-level related.hosts bucket key was not tokenised"
        )
    # The regression: the NESTED related.user keys must be tokens, not RAW.
    for bucket in child_buckets:
        assert _TOKEN_RE.match(str(bucket["key"])), (
            "nested related.user sub-agg bucket key leaked RAW"
        )

    # Counts are never modified by the walker.
    raw_hosts = raw["aggregations"]["hosts"]["buckets"]
    for r_bucket, m_bucket in zip(raw_hosts, parent_buckets):
        assert r_bucket["doc_count"] == m_bucket["doc_count"]
        assert (
            raw["aggregations"]["hosts"].get("sum_other_doc_count", 0)
            == masked["aggregations"]["hosts"].get("sum_other_doc_count", 0)
        )


async def test_live_nested_unmasked_category_keys_stay_raw(
    live_config: tuple[live_test.LiveIndexerConfig, Any],
) -> None:
    """`terms wazuh.agent.name -> terms wazuh.integration.category`: the nested
    category keys are NOT in mask_fields, so they stay readable (regression for
    the "unmasked below" case)."""
    live, cfg = live_config
    anon = _anonymizer(cfg)
    agg_map = parse_agg_fields(CATEGORY_BODY)

    async with _client(live) as client:
        raw = await _live_search(client, CATEGORY_BODY)

    masked = anon.mask_response(
        Response(200, json.dumps(raw), "https://indexer/_search"), agg_map=agg_map
    ).json()

    parent_buckets, child_buckets = _sub_agg_buckets(
        masked, "agents", "categories"
    )
    for bucket in parent_buckets:
        assert _TOKEN_RE.match(str(bucket["key"])), (
            "top-level wazuh.agent.name bucket key was not tokenised"
        )
    for bucket in child_buckets:
        assert not _TOKEN_RE.match(str(bucket["key"])), (
            "nested wazuh.integration.category key was tokenised — an unmasked "
            "field must stay readable"
        )
