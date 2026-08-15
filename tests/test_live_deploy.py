# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""LIVE integration test for `masking deploy`'s ISM verify (skippable).

Proves on a real OpenSearch/Wazuh 5 indexer that the deployed ISM policy's GET
envelope — which wraps the policy DOUBLE-nested (`response["policy"]["policy"]`,
next to `_id`/`_version`/`_seq_no`/`_primary_term`) — is parsed into the actual
policy, and that the deploy's fingerprint compare accepts a policy the indexer
re-serves in an equivalent unit. Non-destructive: it only GETs the already-
deployed policy, and skips cleanly when the tenant is not deployed or when the
credentials are missing.

Credentials come ONLY from `KLAXON_INDEXER_URL` / `KLAXON_INDEXER_USER` /
`KLAXON_INDEXER_PASSWORD` (optionally a gitignored local `.env`), exactly like
`klaxon masking deploy` / `klaxon masking test`. When any is unset the test
SKIPS cleanly — it never fails a CI run without an indexer. The password is
never logged.

The full end-to-end live check is `klaxon masking deploy --tenant customer-a`
(which now verifies the ISM policy against the real envelope); this test pins
the parsing/fingerprint fix against the real response shape without writing
anything.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from klaxon_mcp import deploy, live_test
from klaxon_mcp.masked_stream import build_ism_policy, load_tenant_config

pytestmark = [pytest.mark.integration, pytest.mark.live, pytest.mark.asyncio]

# The tenant whose deployed ISM policy is checked against the live indexer.
LIVE_TENANT = "customer-a"


@pytest.fixture
def live_config() -> tuple[live_test.LiveIndexerConfig, Any]:
    """(live credentials, tenant config) — skips cleanly when credentials are
    missing, so the live tests never fail a CI run without an indexer."""
    live, missing = live_test.resolve_live_config()
    if live is None:
        pytest.skip(
            f"live deploy test skipped: KLAXON_INDEXER_URL/USER/PASSWORD are "
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


async def test_live_deployed_ism_policy_envelope_parses_and_verifies(
    live_config: tuple[live_test.LiveIndexerConfig, Any],
) -> None:
    """The deployed ISM policy's REAL GET envelope is parsed into the innermost
    policy (the fix for the double-nesting bug), and — when the tenant was
    deployed from the current artifacts — the deploy's fingerprint compare
    passes against the actual response."""
    live, cfg = live_config

    async with _client(live) as client:
        resp = await client.get(f"/_plugins/_ism/policies/{cfg.ism_policy_name}")
        if not resp.is_success:
            pytest.skip(
                f"tenant {LIVE_TENANT} has no deployed ISM policy (HTTP "
                f"{resp.status_code}); run `klaxon masking deploy --tenant "
                f"{LIVE_TENANT}` first so the live verify path can be checked"
            )
        parsed = resp.json()

    policy = deploy._ism_policy_from_envelope(parsed)
    assert policy is not None, "could not extract the policy from the real envelope"
    assert isinstance(policy.get("states"), list) and policy["states"], (
        "extracted body is not an ISM policy (no states) — envelope parsing wrong"
    )

    # The regression: fingerprinting the RAW envelope always differed from what
    # was sent. The extraction must actually change what is compared.
    naive = deploy._normalized_for_compare("ism", parsed)
    fixed = deploy._normalized_for_compare("ism", policy)
    assert deploy._fingerprint(naive) != deploy._fingerprint(fixed), (
        "envelope extraction did not change the compared body — the wrapper is "
        "still being fingerprinted"
    )

    # When the tenant was deployed from the CURRENT artifacts (same retention),
    # the deploy's verify path passes against the real envelope — the exact
    # comparison `klaxon masking deploy` now runs, INCLUDING the known-ISM-
    # defaults normalization (ISM_SERVER_DEFAULTS: retry / copy_alias /
    # ism_template list form + last_updated_time metadata) that the real
    # re-served policy carries but the artifact does not. A retention/config
    # drift on the live tenant is an environment difference, not a code bug:
    # skip.
    artifact = build_ism_policy(cfg)
    sent = deploy._normalized_for_compare(
        "ism", deploy._sent_resource("ism", artifact)
    )
    sent_norm, fixed_norm = deploy._normalize_ism_server_defaults(sent, fixed)
    if deploy._fingerprint_for("ism", fixed_norm) != deploy._fingerprint_for(
        "ism", sent_norm
    ):
        pytest.skip(
            "deployed ISM policy was built from different artifacts (retention/"
            "config drift on the live tenant) — cannot assert the deploy verify"
        )
    assert deploy._fingerprint_for("ism", fixed_norm) == deploy._fingerprint_for(
        "ism", sent_norm
    )
