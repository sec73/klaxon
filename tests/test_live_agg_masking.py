# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""LIVE integration test for NESTED aggregation-key masking (skippable).

Proves on a real OpenSearch/Wazuh 5 indexer that the response walker tokenises
sub-aggregation bucket keys at EVERY depth — the regression where a nested
`terms related.user` under `terms related.hosts` came back RAW — and that
`multi_terms` `key_as_string` is rebuilt from the masked key list (the
`related.hosts` raw-value leak inside key_as_string). It queries the RAW stream
(`wazuh-events-v5-*`) so the walker itself is exercised, runs the real
`Anonymizer` over the live response, and asserts:

  * the nested `related.user` sub-bucket keys are tokens (the exact leak);
  * a nested UNMASKED field (`wazuh.integration.category` under
    `wazuh.agent.name`) stays readable;
  * `multi_terms` key_as_string == "|".join(masked key list), so no raw
    hostname survives inside it and the token family is consistent;
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

# multi_terms [related.hosts, wazuh.integration.category]: related.hosts is
# masked (HOST), category is unmasked — the key_as_string leak scenario.
MULTI_TERMS_BODY: dict[str, Any] = {
    "size": 0,
    "query": {"bool": {"filter": [_WINDOW]}},
    "aggs": {
        "pairs": {
            "multi_terms": {
                "size": 20,
                "terms": [
                    {"field": "related.hosts"},
                    {"field": "wazuh.integration.category"},
                ],
            }
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


async def test_live_multi_terms_key_as_string_has_no_raw_value(
    live_config: tuple[live_test.LiveIndexerConfig, Any],
) -> None:
    """multi_terms [related.hosts, wazuh.integration.category] on the RAW
    stream: the masked hostname appears in key AND in the REBUILT key_as_string
    (== "|".join(key)), so the joined key_as_string can never carry a raw
    remnant of the masked field and the token family is consistent. Counts are
    byte-identical raw vs masked."""
    live, cfg = live_config
    anon = _anonymizer(cfg)
    agg_map = parse_agg_fields(MULTI_TERMS_BODY)

    async with _client(live) as client:
        raw = await _live_search(client, MULTI_TERMS_BODY)

    masked = anon.mask_response(
        Response(200, json.dumps(raw), "https://indexer/_search"), agg_map=agg_map
    ).json()

    if "aggregations" not in masked or "pairs" not in masked["aggregations"]:
        pytest.skip(
            "live multi_terms test skipped: no data in the 24h window"
        )
    buckets = masked["aggregations"]["pairs"].get("buckets", [])
    if not buckets:
        pytest.skip("live multi_terms test skipped: no buckets in the 24h window")

    raw_buckets = raw["aggregations"]["pairs"]["buckets"]
    for bucket, r_bucket in zip(buckets, raw_buckets):
        key = bucket["key"]
        assert isinstance(key, list) and key, "multi_terms bucket has no key list"
        # related.hosts (the first field) is masked -> its key element is a token.
        assert _TOKEN_RE.fullmatch(str(key[0])), (
            "multi_terms related.hosts key element leaked RAW"
        )
        # key_as_string is REBUILT from the masked key list -> joined exactly.
        if "key_as_string" in bucket:
            assert bucket["key_as_string"] == "|".join(str(k) for k in key), (
                "key_as_string not rebuilt from the masked key list"
            )
        # Counts are never modified by the walker.
        assert bucket["doc_count"] == r_bucket["doc_count"]


# --------------------------------------------------------------------------- #
# Teil 12.3 — live probe: the scripted_metric query is REJECTED (fail-closed)
# --------------------------------------------------------------------------- #

# The exact finding: scripted_metric reading wazuh.agent.host.hostname over the
# network-activity stream, last 30 min. The response walker cannot map its
# opaque output, so `block_unmappable_aggs` (default) must REJECT the request
# before it reaches the indexer — never silently pass it with HTTP 200.
SCRIPTED_METRIC_BODY: dict[str, Any] = {
    "size": 0,
    "query": {"bool": {"filter": [_WINDOW]}},
    "aggs": {
        "scripted": {
            "scripted_metric": {
                "init_script": "state.hosts = []",
                "map_script": (
                    "state.hosts.add(doc['wazuh.agent.host.hostname'].value)"
                ),
                "combine_script": "return state.hosts",
            }
        }
    },
}


def _server_config_for(
    live: live_test.LiveIndexerConfig, cfg: Any
) -> Any:
    """A server Config over the live credentials + tenant mask list + live salt,
    with the default fail-closed `block_unmappable_aggs`."""
    from klaxon_mcp.config import AnonymizationConfig, Config

    return Config(
        indexer_url=live.url,
        indexer_user=live.user,
        indexer_password=live.password,
        manager_url="",
        manager_user="",
        manager_password="",
        engine_url="",
        verify_ssl=live.verify_ssl,
        timeout=60.0,
        schema_field_limit=200,
        schema_probe_batch=100,
        search_max_size=100,
        logtest_default_trace_level="ASSET_ONLY",
        logtest_default_space="custom",
        anonymization=AnonymizationConfig(
            enabled=True,
            salt=live_salt(cfg),
            mask_fields=cfg.all_masked_fields,
            mask_aggregation_keys=True,
            log_path="/tmp/klaxon-live-agg-masking.log",
        ),
    )


async def test_live_scripted_metric_query_is_rejected(
    live_config: tuple[live_test.LiveIndexerConfig, Any],
) -> None:
    """The Teil 12.3 PRIMARY acceptance: the scripted_metric finding query is
    REJECTED by the request-side fail-closed gate (not silently passed with
    HTTP 200). Exercises the real `server.search` gate against the raw stream
    pattern."""
    from mcp.server.mcpserver.exceptions import ToolError

    from klaxon_mcp import server as server_mod

    live, cfg = live_config
    previous_indexer = server_mod._indexer
    previous_config = server_mod._config
    previous_anon = server_mod._anonymizer
    try:
        server_mod._config = _server_config_for(live, cfg)
        server_mod._anonymizer = None
        server_mod._indexer = None
        with pytest.raises(ToolError, match="scripted_metric"):
            await server_mod.search(
                index="wazuh-events-v5-*", body=json.dumps(SCRIPTED_METRIC_BODY)
            )
        # The gate fires BEFORE any indexer request — nothing was sent.
        assert server_mod._indexer is None
    finally:
        server_mod._indexer = previous_indexer
        server_mod._config = previous_config
        server_mod._anonymizer = previous_anon


# --------------------------------------------------------------------------- #
# Teil 13 — live probe: opaque request features are REJECTED (fail-closed)
# --------------------------------------------------------------------------- #

# The exact Teil-13 finding: script_fields is arbitrary code (like
# scripted_metric) and a raw username leaks under an unmapped `fields.<name>`
# key while `_source.user.name` is tokenised. `block_unmappable_features`
# (default) must REJECT the request before it reaches the indexer.
SCRIPT_FIELDS_LIVE_BODY: dict[str, Any] = {
    "size": 1,
    "query": {"bool": {"filter": [_WINDOW]}},
    "script_fields": {
        "who": {"script": {"source": "params._source.user.name;"}}
    },
}


async def test_live_script_fields_query_is_rejected(
    live_config: tuple[live_test.LiveIndexerConfig, Any],
) -> None:
    """Teil 13 PRIMARY acceptance: the script_fields finding query is REJECTED
    by the request-side fail-closed `block_unmappable_features` gate (a raw
    username would otherwise leak under the `fields.who` alias)."""
    from mcp.server.mcpserver.exceptions import ToolError

    from klaxon_mcp import server as server_mod

    live, cfg = live_config
    previous_indexer = server_mod._indexer
    previous_config = server_mod._config
    previous_anon = server_mod._anonymizer
    try:
        server_mod._config = _server_config_for(live, cfg)
        server_mod._anonymizer = None
        server_mod._indexer = None
        with pytest.raises(ToolError, match="script_fields"):
            await server_mod.search(
                index="wazuh-events-v5-*", body=json.dumps(SCRIPT_FIELDS_LIVE_BODY)
            )
        # The gate fires BEFORE any indexer request — nothing was sent.
        assert server_mod._indexer is None
    finally:
        server_mod._indexer = previous_indexer
        server_mod._config = previous_config
        server_mod._anonymizer = previous_anon


async def test_live_suggest_query_is_rejected(
    live_config: tuple[live_test.LiveIndexerConfig, Any],
) -> None:
    """Teil 13: a term/phrase/completion suggester returns raw field text; the
    fail-closed `block_unmappable_features` gate rejects it."""
    from mcp.server.mcpserver.exceptions import ToolError

    from klaxon_mcp import server as server_mod

    live, cfg = live_config
    previous_indexer = server_mod._indexer
    previous_config = server_mod._config
    previous_anon = server_mod._anonymizer
    try:
        server_mod._config = _server_config_for(live, cfg)
        server_mod._anonymizer = None
        server_mod._indexer = None
        body: dict[str, Any] = {
            "size": 0,
            "query": {"bool": {"filter": [_WINDOW]}},
            "suggest": {"u": {"text": "root", "term": {"field": "user.name"}}},
        }
        with pytest.raises(ToolError, match="suggest"):
            await server_mod.search(index="wazuh-events-v5-*", body=json.dumps(body))
        assert server_mod._indexer is None
    finally:
        server_mod._indexer = previous_indexer
        server_mod._config = previous_config
        server_mod._anonymizer = previous_anon
