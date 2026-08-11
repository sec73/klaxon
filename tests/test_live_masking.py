# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""LIVE integration test for the generated masking pipeline (skippable).

Proves on a real OpenSearch/Wazuh 5 indexer that the pipeline `klaxon masking
generate` emits (a) compiles (Stage A — `POST /_scripts/painless/_execute`) and
(b) masks documents correctly (Stage B — `POST /_ingest/pipeline/_simulate`,
inline so nothing is deployed or persisted).

Credentials come ONLY from `KLAXON_INDEXER_URL` / `KLAXON_INDEXER_USER` /
`KLAXON_INDEXER_PASSWORD` (optionally loaded from a gitignored local `.env`
file such as `tests/live/.env` or `.env.live`). When any of the three is unset
the test SKIPS cleanly with a clear message — it never fails the suite. The
password is never logged.

Same code, CLI equivalent: `klaxon masking test --tenant customer-a`.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from klaxon_mcp import live_test
from klaxon_mcp.masked_stream import build_pipeline, load_tenant_config
from klaxon_mcp.masking import verify_script_structure

pytestmark = [pytest.mark.integration, pytest.mark.live, pytest.mark.asyncio]

# The tenant whose generated pipeline is tested against the live indexer.
LIVE_TENANT = "customer-a"


@pytest.fixture
def live_config() -> tuple[live_test.LiveIndexerConfig, Any]:
    """(live credentials, tenant config) — skips cleanly when credentials are
    missing, so the live tests never fail a CI run without an indexer."""
    live, missing = live_test.resolve_live_config()
    if live is None:
        pytest.skip(
            f"live masking test skipped: KLAXON_INDEXER_URL/USER/PASSWORD are "
            f"not all set (missing: {', '.join(missing)}). Export them or add a "
            "gitignored tests/live/.env / .env.live file — see "
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


async def test_live_stage_a_ingest_allowlist(
    live_config: tuple[live_test.LiveIndexerConfig, Any],
) -> None:
    """The cluster's ingest Painless allowlist has every API the generated
    script needs (String.sha256, Pattern/Matcher, StringBuilder, collections).

    Also asserts the offline structural invariants (functions before statements,
    no `ctx['_source']`) so a regression is caught even before the HTTP round trip.
    """
    live, cfg = live_config
    salt = live_test.live_salt(cfg)
    script = build_pipeline(cfg, salt)["processors"][0]["script"]["source"]

    assert verify_script_structure(script) == []
    assert "ctx['_source']" not in script  # Bug 2 gate

    async with _client(live) as client:
        ok, detail = await live_test.stage_a_ingest_allowlist(client)
    assert ok, detail


async def test_live_stage_b_simulate_masks_correctly(
    live_config: tuple[live_test.LiveIndexerConfig, Any],
) -> None:
    """The pipeline masks the representative documents correctly (no NPE, no
    `klaxon.masking_error`, tokens consistent, arrays element-wise, hashes and
    already-tokenised values untouched, idempotent)."""
    live, cfg = live_config
    salt = live_test.live_salt(cfg)

    async with _client(live) as client:
        sources, errors = await live_test.stage_b_simulate(
            client, build_pipeline(cfg, salt), live_test.live_test_docs()
        )
    assert errors == [], f"simulate reported failures: {errors}"
    problems = live_test.check_simulated(sources, cfg, salt)
    assert problems == [], "masking behaviour problems:\n" + "\n".join(problems)
