# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""`klaxon masking teardown` — remove the Option B masked-stream infrastructure.

Removes, in dependency order, every indexer resource `klaxon masking deploy`
created for one tenant (the raw Wazuh streams are never touched):

  1. data stream    klaxon-masked-<tenant>-v5
                    (DELETE /_data_stream/...; then any orphaned
                     .ds-klaxon-masked-<tenant>-v5-* backing indices)
  2. sync marker    klaxon-sync-state/_doc/klaxon-sync-<tenant>
                    ONLY with --purge-sync-state (default: KEEP, so a future
                    re-setup can resume from the last checkpoint)
  3. index template klaxon-masked-<tenant>
                    (DELETE /_index_template/...)
  4. ISM policy     klaxon-masked-retention-<tenant>
                    (DELETE /_plugins/_ism/policies/...)
  5. ingest pipeline klaxon-mask-<tenant>
                    (DELETE /_ingest/pipeline/...)

then VERIFIES (mandatory, after removal):

  * GET /_cat/indices/klaxon-*          -> no klaxon-* indices left
  * GET /_index_template/klaxon-masked-<tenant>                   -> 404
  * GET /_plugins/_ism/policies/klaxon-masked-retention-<tenant>  -> 404
  * GET /_ingest/pipeline/klaxon-mask-<tenant>                    -> 404
  * GET /_cat/indices/wazuh-events-v5-* and wazuh-findings-v5-*
    -> both raw streams still exist with UNCHANGED doc counts (before/after)

SAFETY CONTRACT (hard, enforced in code):

  * Only `klaxon-*`-namespaced resources are ever deleted. A guard raises
    before any DELETE whose resource name does not start with `klaxon-` (or the
    `.ds-klaxon-` backing-index prefix), so a tenant-config bug can never
    target `wazuh-events-v5-*` / `wazuh-findings-v5-*` or any Wazuh template,
    policy or pipeline.
  * A missing resource (404) is "already removed" — logged, and the teardown
    continues (idempotent). Other failures are logged and left for the
    verification phase, which reports every leftover and exits non-zero, so a
    partial teardown is never reported as success.
  * Credentials come ONLY from KLAXON_INDEXER_URL/USER/PASSWORD (optionally a
    gitignored local .env via --env), exactly like `klaxon masking deploy`.
    The password, the salt, token values and raw data are NEVER logged — only
    resource names and HTTP statuses.
  * The Klaxon response-layer masking config (mask_fields,
    mask_aggregation_keys, gdpr_checker custom_patterns) is NOT touched, and
    neither is tenants/<tenant>/fields.yaml — this tool removes indexer
    resources only.

`--dry-run` prints the plan without contacting the indexer or changing
anything. Without `--yes` the command is safe-by-default: it prompts with the
full list (non-interactive runs abort with no changes); `--yes` confirms and
executes.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

import httpx

from .live_config import LiveIndexerConfig, resolve_live_config
from .masked_stream import TenantConfig, load_tenant_config

_TIMEOUT = 60.0

# Resource-name prefixes the teardown may DELETE. Everything else (in
# particular anything starting with `wazuh-`) is refused by `_require_klaxon`.
_SAFE_PREFIXES: tuple[str, ...] = ("klaxon-", ".ds-klaxon-")

# The two raw Wazuh streams whose doc counts must remain unchanged.
_RAW_PATTERNS: tuple[str, ...] = ("wazuh-events-v5-*", "wazuh-findings-v5-*")


class TeardownError(RuntimeError):
    """A hard teardown failure (never carries secrets)."""


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="klaxon masking teardown",
        description=(
            "Remove the Option B masked-stream infrastructure for one tenant "
            "(data stream, sync checkpoint marker [with --purge-sync-state], "
            "index template, ISM policy, ingest pipeline) in dependency order, "
            "then verify nothing klaxon-* is left and the raw Wazuh streams are "
            "untouched. Destructive and irreversible — preview with --dry-run. "
            "Needs admin indexer credentials (KLAXON_INDEXER_URL/USER/PASSWORD)."
        ),
    )
    parser.add_argument(
        "--tenant",
        metavar="TENANT",
        required=True,
        help="Tenant (directory under tenants/) whose Option B resources are "
        "removed, e.g. customer-a. Validated like the generator (never "
        "interpolated into a resource name unguarded).",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repo root (default: nearest ancestor with tenants/).",
    )
    parser.add_argument(
        "--env",
        metavar="FILE",
        default=None,
        help="Local dotenv file with KLAXON_INDEXER_* vars (default: first "
        "existing of .env.live, tests/live/.env).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the plan without contacting the indexer or changing "
        "anything. Safe default: without --yes the command never changes "
        "anything without confirmation.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm and execute the teardown without prompting.",
    )
    parser.add_argument(
        "--purge-sync-state",
        action="store_true",
        help="Also delete the sync checkpoint marker "
        "(klaxon-sync-state/_doc/klaxon-sync-<tenant> and the marker index once "
        "empty). Default: keep the marker so a future re-setup can resume from "
        "the last checkpoint.",
    )
    return parser.parse_args(argv)


def _plan(cfg: TenantConfig, purge_sync_state: bool) -> list[str]:
    """Every resource the teardown would remove, in dependency order."""
    items = [
        f"data stream     {cfg.masked_stream}",
        f"backing indices .ds-{cfg.masked_stream}-* (if any)",
        f"sync marker     {cfg.sync_state_index}/_doc/{cfg.sync_state_doc_id}",
        f"index template  {cfg.index_template_name}",
        f"ISM policy      {cfg.ism_policy_name}",
        f"ingest pipeline {cfg.pipeline_name}",
    ]
    if purge_sync_state:
        items[2] += "   (PURGED — a future re-setup starts fresh)"
    else:
        items[2] += "   (KEPT — add --purge-sync-state to delete)"
    return items


def _verify_plan(cfg: TenantConfig, purge_sync_state: bool) -> list[str]:
    """The verification checks a real teardown runs (shown by --dry-run)."""
    checks = [
        (
            "GET /_cat/indices/klaxon-* + .ds-klaxon-*  -> empty (no klaxon-* "
            "indices left)"
        ),
        f"GET /_index_template/{cfg.index_template_name}  -> 404",
        f"GET /_plugins/_ism/policies/{cfg.ism_policy_name}  -> 404",
        f"GET /_ingest/pipeline/{cfg.pipeline_name}  -> 404",
        (
            "GET /_cat/indices/wazuh-events-v5-* + wazuh-findings-v5-* "
            "-> doc counts unchanged (raw streams untouched)"
        ),
    ]
    if not purge_sync_state:
        checks.insert(
            0,
            (
                f"note: {cfg.sync_state_index} may remain (sync marker KEPT by "
                "design — not a leftover)"
            ),
        )
    return checks


def _confirm(prompt: str) -> bool:
    """Destructive-action confirmation. Explicit y/yes only; non-TTY defaults
    to no (change nothing)."""
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(prompt).strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _explain_sync_state(purge: bool) -> None:
    if purge:
        print(
            "  sync checkpoint marker: WILL BE DELETED (fresh start; a future\n"
            "    re-setup begins a new initial-lookback window)."
        )
    else:
        print(
            "  sync checkpoint marker: KEPT — a future re-setup resumes from\n"
            "    the last checkpoint. Add --purge-sync-state to delete it too."
        )


# --------------------------------------------------------------------------- #
# Guards + small helpers
# --------------------------------------------------------------------------- #


def _require_klaxon(resource: str) -> None:
    """Hard safety guard: never DELETE anything outside the klaxon-* namespace.

    Every resource name is derived from a validated tenant name and a hardcoded
    `klaxon-` prefix, so this can never fire in practice — it is the belt-and-
    suspenders guarantee that no command path (and no future caller) can ever
    delete a `wazuh-*` resource.
    """
    if not resource.startswith(_SAFE_PREFIXES):
        raise TeardownError(
            f"refusing to delete non-klaxon resource {resource!r} — only "
            "klaxon-* namespaced resources may be removed"
        )


def _error_detail(resp: httpx.Response) -> str:
    """A safe one-line indexer error reason (never the raw body/password/salt)."""
    try:
        payload = resp.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, dict):
            reason = err.get("reason")
            if isinstance(reason, str) and reason:
                return reason[:300]
    return f"HTTP {resp.status_code}"


def _sum_docs(rows: list[dict[str, Any]]) -> int:
    total = 0
    for row in rows:
        raw = row.get("docs.count")
        try:
            total += int(raw or 0)
        except (TypeError, ValueError):
            pass
    return total


async def _cat_indices(
    client: httpx.AsyncClient, pattern: str
) -> list[dict[str, str]]:
    """Rows from `GET /_cat/indices/<pattern>?format=json` (index + docs.count).

    Includes hidden indices (`.ds-*` backing indices of data streams) via
    `expand_wildcards=open,hidden`. Empty pattern -> [] (missing cluster-wide
    match and HTTP 404 both mean "nothing here").
    """
    resp = await client.get(
        "/_cat/indices",
        params={
            "index": pattern,
            "format": "json",
            "h": "index,docs.count",
            "expand_wildcards": "open,hidden",
        },
    )
    if not resp.is_success:
        return []
    parsed = resp.json()
    if not isinstance(parsed, list):
        return []
    return [
        r for r in parsed if isinstance(r, dict) and r.get("index")
    ]


async def _capture_raw(client: httpx.AsyncClient) -> dict[str, tuple[bool, int]]:
    """Before/after snapshot of the raw streams: {pattern: (exists, docs)}."""
    state: dict[str, tuple[bool, int]] = {}
    for pattern in _RAW_PATTERNS:
        rows = await _cat_indices(client, pattern)
        state[pattern] = (len(rows) > 0, _sum_docs(rows))
    return state


async def _count_docs(client: httpx.AsyncClient, index: str) -> int | None:
    """Document count of an index, or None when it cannot be read (404 etc.)."""
    resp = await client.get(f"/{index}/_count")
    if not resp.is_success:
        return None
    parsed = resp.json()
    if not isinstance(parsed, dict):
        return None
    count = parsed.get("count")
    if isinstance(count, bool) or not isinstance(count, (int, float)):
        return None
    return int(count)


# --------------------------------------------------------------------------- #
# Destructive steps (each idempotent; 404 == already removed)
# --------------------------------------------------------------------------- #


async def _delete(
    client: httpx.AsyncClient,
    label: str,
    path: str,
    lines: list[str],
) -> bool:
    """DELETE one resource; 404 is "already removed" (idempotent). Returns
    success (a non-404 failure is recorded and left for verification)."""
    _require_klaxon(path.rsplit("/", 1)[-1])
    resp = await client.delete(path)
    if resp.status_code == 404:
        lines.append(f"[skip] {label}: already removed (404)")
        return True
    if resp.is_success:
        lines.append(f"[ok] {label}: deleted")
        return True
    lines.append(
        f"[fail] {label}: DELETE returned HTTP {resp.status_code} — "
        f"{_error_detail(resp)}"
    )
    return False


async def _delete_data_stream(
    client: httpx.AsyncClient, cfg: TenantConfig, lines: list[str]
) -> bool:
    """Step 1: DELETE the masked data stream, then sweep any orphaned backing
    indices (`.ds-klaxon-masked-<tenant>-v5-*`) the stream delete left behind."""
    _require_klaxon(cfg.masked_stream)
    ok = await _delete(
        client,
        f"data stream {cfg.masked_stream}",
        f"/_data_stream/{cfg.masked_stream}",
        lines,
    )
    rows = await _cat_indices(client, f".ds-{cfg.masked_stream}-*")
    for row in rows:
        index = row["index"]
        _require_klaxon(index)
        await _delete(client, f"backing index {index}", f"/{index}", lines)
    return ok


async def _purge_sync_state(
    client: httpx.AsyncClient, cfg: TenantConfig, lines: list[str]
) -> bool:
    """Step 2 (only with --purge-sync-state): DELETE the checkpoint marker doc,
    then the marker index once it holds no other tenants' markers. The index is
    shared across tenants, so it is only removed when empty."""
    _require_klaxon(cfg.sync_state_index)
    doc_path = f"/{cfg.sync_state_index}/_doc/{cfg.sync_state_doc_id}"
    ok = await _delete(client, f"sync marker {doc_path[1:]}", doc_path, lines)

    count = await _count_docs(client, cfg.sync_state_index)
    if count is None:
        lines.append(
            f"[ok] sync-state index {cfg.sync_state_index}: gone (404)"
        )
        return ok
    if count == 0:
        await _delete(
            client,
            f"sync-state index {cfg.sync_state_index}",
            f"/{cfg.sync_state_index}",
            lines,
        )
    else:
        lines.append(
            f"[info] sync-state index {cfg.sync_state_index}: kept — still "
            f"holds {count} other tenant marker(s)"
        )
    return ok


# --------------------------------------------------------------------------- #
# Verification (mandatory, runs after removal)
# --------------------------------------------------------------------------- #


async def _verify(
    client: httpx.AsyncClient,
    cfg: TenantConfig,
    *,
    purge_sync_state: bool,
    before: dict[str, tuple[bool, int]],
    lines: list[str],
) -> list[str]:
    """Prove nothing klaxon-* is left and the raw streams are untouched.

    Returns a list of problems (empty == clean teardown). `klaxon-sync-state`
    is the ONE allowed exception: it is the documented shared marker index,
    kept by default so a future re-setup can resume; when --purge-sync-state
    was requested it must be gone unless it still holds other tenants' markers.
    """
    problems: list[str] = []

    # 1. No klaxon-* indices left. `.ds-*` backing indices are hidden and are
    #    NOT matched by a plain `klaxon-*` _cat pattern, so sweep them too —
    #    an orphaned `.ds-klaxon-masked-<tenant>-v5-*` backing index is exactly
    #    the kind of leftover a teardown must report.
    rows = await _cat_indices(client, "klaxon-*")
    rows += await _cat_indices(client, ".ds-klaxon-*")
    remaining = [r["index"] for r in rows]
    for index in sorted(remaining):
        if index == cfg.sync_state_index:
            if purge_sync_state:
                count = await _count_docs(client, cfg.sync_state_index)
                if count is None:
                    lines.append(
                        f"[info] {cfg.sync_state_index}: present, count "
                        "unknown — kept for manual review"
                    )
                elif count > 0:
                    lines.append(
                        f"[info] {cfg.sync_state_index}: kept ({count} other "
                        "tenant marker(s))"
                    )
                else:
                    problems.append(
                        f"{cfg.sync_state_index} still exists and is empty — "
                        "sync-state purge incomplete"
                    )
            else:
                lines.append(
                    f"[info] {cfg.sync_state_index}: kept (sync marker "
                    "preserved by design)"
                )
            continue
        problems.append(f"leftover klaxon-* index: {index}")

    # 2. The masked data stream is gone (404 or no streams listed).
    resp = await client.get(f"/_data_stream/{cfg.masked_stream}")
    gone = False
    if resp.status_code == 404:
        gone = True
    elif resp.is_success:
        parsed = resp.json()
        streams = parsed.get("data_streams") if isinstance(parsed, dict) else None
        gone = not isinstance(streams, list) or not streams
    if gone:
        lines.append(f"[ok] verify data stream {cfg.masked_stream}: gone")
    else:
        problems.append(
            f"data stream {cfg.masked_stream} still present (HTTP "
            f"{resp.status_code})"
        )

    # 3. Template / ISM policy / pipeline -> 404.
    for label, path in (
        (
            f"index template {cfg.index_template_name}",
            f"/_index_template/{cfg.index_template_name}",
        ),
        (
            f"ISM policy {cfg.ism_policy_name}",
            f"/_plugins/_ism/policies/{cfg.ism_policy_name}",
        ),
        (
            f"ingest pipeline {cfg.pipeline_name}",
            f"/_ingest/pipeline/{cfg.pipeline_name}",
        ),
    ):
        resp = await client.get(path)
        if resp.status_code == 404:
            lines.append(f"[ok] verify {label}: gone (404)")
        else:
            problems.append(f"{label} still present (HTTP {resp.status_code})")

    # 4. Raw streams: still exist, doc counts unchanged (before/after).
    after = await _capture_raw(client)
    for pattern in _RAW_PATTERNS:
        was, now = before[pattern], after[pattern]
        if was != now:
            problems.append(
                f"raw stream {pattern} CHANGED during teardown: before={was} "
                f"after={now} — WAZUH DATA TOUCHED, investigate immediately"
            )
        elif now[0]:
            lines.append(
                f"[ok] raw stream {pattern}: {now[1]} doc(s), unchanged"
            )
        else:
            lines.append(
                f"[info] raw stream {pattern}: empty before and after — "
                "unchanged (no data on this cluster)"
            )

    return problems


# --------------------------------------------------------------------------- #
# Execution
# --------------------------------------------------------------------------- #


async def _run(
    live: LiveIndexerConfig,
    cfg: TenantConfig,
    *,
    purge_sync_state: bool,
    yes: bool,
) -> int:
    plan = _plan(cfg, purge_sync_state)
    if not yes:
        print(f"teardown[{cfg.tenant}] the following resources would be DELETED:")
        for item in plan:
            print(f"  {item}")
        _explain_sync_state(purge_sync_state)
        if not _confirm("Proceed with teardown? [y/N] "):
            print(
                f"teardown[{cfg.tenant}] aborted — no changes made.",
                file=sys.stderr,
            )
            return 1

    if not live.verify_ssl:
        print(
            f"teardown[{cfg.tenant}] WARNING: KLAXON_INDEXER_VERIFY_SSL=false — "
            "TLS verification is DISABLED. Use it only against a self-signed "
            "lab cluster.",
            file=sys.stderr,
        )

    async with httpx.AsyncClient(
        base_url=live.url,
        auth=(live.user, live.password),
        verify=live.verify_ssl,
        timeout=_TIMEOUT,
        headers={"Content-Type": "application/json"},
    ) as client:
        # Snapshot the raw stream state BEFORE any removal.
        before = await _capture_raw(client)

        removal: list[str] = []
        print(f"teardown[{cfg.tenant}] removing in dependency order:")
        await _delete_data_stream(client, cfg, removal)
        if purge_sync_state:
            await _purge_sync_state(client, cfg, removal)
        # Spec order: template, ISM policy, pipeline.
        await _delete(
            client,
            f"index template {cfg.index_template_name}",
            f"/_index_template/{cfg.index_template_name}",
            removal,
        )
        await _delete(
            client,
            f"ISM policy {cfg.ism_policy_name}",
            f"/_plugins/_ism/policies/{cfg.ism_policy_name}",
            removal,
        )
        await _delete(
            client,
            f"ingest pipeline {cfg.pipeline_name}",
            f"/_ingest/pipeline/{cfg.pipeline_name}",
            removal,
        )
        for line in removal:
            print(f"  {line}")

        verify_lines: list[str] = []
        problems = await _verify(
            client,
            cfg,
            purge_sync_state=purge_sync_state,
            before=before,
            lines=verify_lines,
        )
        print(f"teardown[{cfg.tenant}] verification:")
        for line in verify_lines:
            print(f"  {line}")

    if problems:
        print(
            f"teardown[{cfg.tenant}] VERIFICATION FAILED — leftovers found:",
            file=sys.stderr,
        )
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print(
        f"teardown[{cfg.tenant}] ok: Option B resources removed; raw streams "
        "untouched."
    )
    return 0


def teardown_main(argv: list[str] | None = None) -> int:
    """Console entry for `klaxon masking teardown`. 0 = ok, 1 = failure, 2 = usage."""
    args = _parse_args(argv)

    try:
        cfg = load_tenant_config(args.tenant, args.root)
    except (FileNotFoundError, ValueError) as exc:
        print(f"teardown[{args.tenant}] error: {exc}", file=sys.stderr)
        return 2

    purge_sync_state = args.purge_sync_state

    # --dry-run is fully offline (no credentials needed): print the plan and
    # the verification checks, change nothing. --dry-run wins over --yes (the
    # safe reading of a contradictory invocation).
    if args.dry_run:
        print(f"teardown[{cfg.tenant}] dry run — would remove (no changes):")
        for item in _plan(cfg, purge_sync_state):
            print(f"  {item}")
        print(f"teardown[{cfg.tenant}] then verify:")
        for check in _verify_plan(cfg, purge_sync_state):
            print(f"  {check}")
        print(f"teardown[{cfg.tenant}] no changes made (dry run).")
        return 0

    live, missing = resolve_live_config(args.env)
    if live is None:
        print(
            f"teardown[{cfg.tenant}] ERROR: indexer credentials not set. "
            f"Missing: {', '.join(missing)}. Set KLAXON_INDEXER_URL, "
            "KLAXON_INDEXER_USER and KLAXON_INDEXER_PASSWORD (or a local .env "
            "file via --env). The password is never logged.",
            file=sys.stderr,
        )
        return 1

    try:
        return asyncio.run(
            _run(live, cfg, purge_sync_state=purge_sync_state, yes=args.yes)
        )
    except httpx.TransportError as exc:
        print(
            f"teardown[{cfg.tenant}] error: indexer unreachable: {exc}",
            file=sys.stderr,
        )
        return 1
