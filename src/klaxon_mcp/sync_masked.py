# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Option B operational commands: sync the masked stream, verify drift, apply infra.

All commands talk to the indexer DIRECTLY (never through the response masker) —
the sync job must see raw values to mask them, and that is intentional. The raw
Wazuh streams are only ever read; nothing is written to them.

Commands (wired into `klaxon-mcp`):
  * --sync-masked  --tenant X    periodic reindex of a time window through the
                                 masking pipeline, with a checkpoint + preflight
                                 and a FAIL-CLOSED backstop: any quarantine doc
                                 (masking failure) in the window fails the run
                                 and the checkpoint is NOT advanced
  * --verify-config --tenant X   drift audit: fields.yaml vs config vs pipeline
                                 (incl. the quarantine on_failure presence)
  * --apply-masked-infra --tenant X  PUT pipeline (real salt), ISM, template,
                                 data stream + quarantine ISM/template
  * masking migrate --tenant X   ONE-TIME, operator-run migration of legacy
                                 masking_error docs from the masked stream into
                                 the quarantine stream (destructive, idempotent)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from .clients import IndexerClient, Response, TransportError
from .config import Config, ConfigError
from .masked_stream import (
    DEFAULT_INITIAL_LOOKBACK_HOURS,
    DEFAULT_OVERLAP_HOURS,
    DEFAULT_RETENTION_DAYS,
    QUARANTINE_RETENTION_DAYS,
    TenantConfig,
    build_index_template,
    build_ism_policy,
    build_quarantine_index_template,
    build_quarantine_ism_policy,
    deploy_pipeline,
    effective_mask_fields_from_config,
    fields_yaml_sha256,
    fingerprint_matches,
    load_tenant_config,
    pipeline_field_names,
    pipeline_has_quarantine_on_failure,
)


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="seconds")


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Preflight (drift control point before every sync run)
# --------------------------------------------------------------------------- #


async def _fetch_pipeline(
    client: IndexerClient, cfg: TenantConfig
) -> dict[str, Any] | None:
    """The deployed pipeline body, or None when it does not exist."""
    try:
        resp = await client.get(f"/_ingest/pipeline/{cfg.pipeline_name}")
    except TransportError:
        return None
    if not resp.ok:
        return None
    parsed = resp.json()
    if not isinstance(parsed, dict):
        return None
    return parsed.get(cfg.pipeline_name)


def _effective_klaxon_fields(config: Config) -> tuple[str, ...]:
    anon = config.anonymization
    return tuple((*anon.mask_fields, *anon.mask_free_text_fields))


def preflight_report(
    cfg: TenantConfig, deployed: dict[str, Any] | None, config: Config
) -> list[str]:
    """Compare fields.yaml -> effective config vs deployed pipeline; return problems."""
    problems: list[str] = []
    expected = set(effective_mask_fields_from_config(cfg))
    klaxon = set(_effective_klaxon_fields(config))
    if deployed is None:
        problems.append(
            f"pipeline {cfg.pipeline_name} is not deployed. Run "
            "`klaxon-mcp --apply-masked-infra --tenant <tenant>` first."
        )
        return problems

    if not fingerprint_matches(deployed, cfg):
        problems.append(
            f"deployed pipeline {cfg.pipeline_name} was generated from a "
            "different fields.yaml (fingerprint/sha256 or field list mismatch). "
            "Regenerate and redeploy before syncing."
        )
    deployed_fields = set(pipeline_field_names(deployed))
    if deployed_fields != expected:
        problems.append(
            f"deployed pipeline masks {sorted(deployed_fields)} but fields.yaml "
            f"requires {sorted(expected)}."
        )
    if not pipeline_has_quarantine_on_failure(deployed):
        problems.append(
            f"deployed pipeline {cfg.pipeline_name} lacks the quarantine "
            "on_failure routing — masking-failure documents would stay in the "
            "masked stream (fail-open) instead of being rerouted to "
            f"{cfg.quarantine_stream_pattern}. Redeploy a pipeline generated "
            "with the quarantine routing before syncing."
        )
    if klaxon != expected:
        problems.append(
            f"effective Klaxon config masks {sorted(klaxon)} but fields.yaml "
            f"requires {sorted(expected)}. The response layer and the pipeline "
            "are out of sync — fix the Klaxon config or regenerate."
        )
    return problems


# --------------------------------------------------------------------------- #
# Checkpoint
# --------------------------------------------------------------------------- #


async def _read_checkpoint(
    client: IndexerClient, cfg: TenantConfig
) -> datetime | None:
    resp = await client.get(f"/{cfg.sync_state_index}/_doc/{cfg.sync_state_doc_id}")
    if not resp.ok:
        return None
    parsed = resp.json()
    if not isinstance(parsed, dict):
        return None
    source = parsed.get("_source")
    if not isinstance(source, dict):
        return None
    raw = source.get("checkpoint")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _write_checkpoint(
    client: IndexerClient, cfg: TenantConfig, checkpoint: datetime
) -> Response:
    body = {
        "tenant": cfg.tenant,
        "checkpoint": _iso(checkpoint),
        "updated": _iso(_now()),
    }
    return await client.put(
        f"/{cfg.sync_state_index}/_doc/{cfg.sync_state_doc_id}", body=body
    )


# --------------------------------------------------------------------------- #
# Reindex execution: async task submission + polling + transport retry
#
# The reindex is submitted with wait_for_completion=false, so the POST returns
# a task id immediately and the task is then polled via GET /_tasks/<id>. A
# long synchronous _reindex connection is exactly what proxies/LBs close on
# long requests — the transport-level failure this code fixes. Transport-level
# errors (connect/read timeout, connection reset, protocol errors — the
# httpx.TransportError family) are TRANSIENT and retried with backoff for the
# SAME window; HTTP 4xx/5xx are reported with status + body and never retried
# blindly (they will not heal by retrying, and would only amplify load).
# --------------------------------------------------------------------------- #

SYNC_REINDEX_ATTEMPTS = 3
SYNC_RETRY_BACKOFF_SECONDS = (5.0, 15.0, 45.0)
SYNC_TASK_POLL_SECONDS = 5.0


async def _submit_reindex_task(
    client: IndexerClient,
    cfg: TenantConfig,
    config: Config,
    body: dict[str, Any],
) -> str | None:
    """POST /_reindex?wait_for_completion=false; return the task id, or None.

    Transport-level errors are retried with backoff (SYNC_REINDEX_ATTEMPTS).
    On failure the window is NOT reindexed and the checkpoint is NOT advanced —
    the window is retried on the next run (fail-closed). HTTP errors return
    None without retrying, with the status + body already reported.
    """
    for attempt in range(1, SYNC_REINDEX_ATTEMPTS + 1):
        try:
            resp = await client.post(
                "/_reindex",
                body=body,
                params={"wait_for_completion": "false"},
                timeout=config.sync_reindex_timeout,
            )
        except TransportError as exc:
            if attempt < SYNC_REINDEX_ATTEMPTS:
                delay = SYNC_RETRY_BACKOFF_SECONDS[attempt - 1]
                print(
                    f"sync-masked[{cfg.tenant}] reindex transport error "
                    f"(attempt {attempt}/{SYNC_REINDEX_ATTEMPTS}): {exc}; "
                    f"retrying in {delay:.0f}s.",
                    file=sys.stderr,
                )
                await asyncio.sleep(delay)
                continue
            print(
                f"sync-masked[{cfg.tenant}] reindex failed at transport level "
                f"after {SYNC_REINDEX_ATTEMPTS} attempts: {exc}. The window was "
                "NOT reindexed and the checkpoint was NOT advanced; it will be "
                "retried on the next run.",
                file=sys.stderr,
            )
            return None

        if not resp.ok:
            # HTTP error: report status + body; do NOT retry blindly.
            print(
                f"sync-masked[{cfg.tenant}] reindex FAILED (HTTP "
                f"{resp.status_code}); checkpoint NOT advanced. Failed window "
                "will be retried.",
                file=sys.stderr,
            )
            print(resp.text[:2000], file=sys.stderr)
            return None

        parsed = resp.json()
        task_id = parsed.get("task") if isinstance(parsed, dict) else None
        if not isinstance(task_id, str) or not task_id:
            print(
                f"sync-masked[{cfg.tenant}] reindex did not return a task id "
                f"(response: {resp.text[:500]}); checkpoint NOT advanced.",
                file=sys.stderr,
            )
            return None
        return task_id
    return None  # unreachable


async def _poll_reindex_task(
    client: IndexerClient,
    cfg: TenantConfig,
    config: Config,
    task_id: str,
) -> dict[str, Any] | None:
    """Poll GET /_tasks/<id> until the reindex task completes.

    Returns the completed task body (the reindex result sits in task.status),
    or None on failure/timeout with the message already printed. A transport
    error on a poll is transient and retried; the overall deadline is
    config.sync_task_timeout (KLAXON_SYNC_TASK_TIMEOUT, default 60 min).
    """
    deadline = time.monotonic() + config.sync_task_timeout
    poll = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(
                f"sync-masked[{cfg.tenant}] reindex task {task_id} did not "
                f"complete within {config.sync_task_timeout:.0f}s; checkpoint "
                "NOT advanced. The window will be retried on the next run.",
                file=sys.stderr,
            )
            return None
        try:
            resp = await client.get(
                f"/_tasks/{task_id}", timeout=config.sync_reindex_timeout
            )
        except TransportError as exc:
            poll += 1
            print(
                f"sync-masked[{cfg.tenant}] reindex task poll transport error "
                f"(poll #{poll}): {exc}; retrying.",
                file=sys.stderr,
            )
            await asyncio.sleep(min(SYNC_TASK_POLL_SECONDS, remaining))
            continue
        if not resp.ok:
            print(
                f"sync-masked[{cfg.tenant}] reindex task poll FAILED (HTTP "
                f"{resp.status_code}) for {task_id}; checkpoint NOT advanced.",
                file=sys.stderr,
            )
            print(resp.text[:1000], file=sys.stderr)
            return None
        parsed = resp.json()
        if isinstance(parsed, dict) and parsed.get("completed"):
            return parsed
        await asyncio.sleep(min(SYNC_TASK_POLL_SECONDS, remaining))


def _reindex_task_result(completed: dict[str, Any]) -> dict[str, Any] | None:
    """The reindex result of a completed task body, normalised to the top level.

    GET /_tasks/<id> nests the reindex result (failures/created/total/...) under
    task.status, whereas a synchronous _reindex response carries it at the top
    level. Returns None when the result cannot be read — the caller treats that
    as FAIL-CLOSED (success not confirmed, checkpoint not advanced).
    """
    task = completed.get("task")
    status = task.get("status") if isinstance(task, dict) else None
    return status if isinstance(status, dict) else None


# --------------------------------------------------------------------------- #
# Sync
# --------------------------------------------------------------------------- #


async def _sync(
    client: IndexerClient,
    cfg: TenantConfig,
    config: Config,
    *,
    overlap_hours: int,
    initial_lookback_hours: int,
    dry_run: bool,
) -> int:
    deployed = await _fetch_pipeline(client, cfg)
    problems = preflight_report(cfg, deployed, config)
    if problems:
        print(f"sync-masked[{cfg.tenant}] PREFLIGHT FAILED — not syncing:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    checkpoint = await _read_checkpoint(client, cfg)
    now = _now()
    if checkpoint is None:
        window_start = now - timedelta(hours=initial_lookback_hours)
        print(
            f"sync-masked[{cfg.tenant}] no checkpoint; initial lookback "
            f"{initial_lookback_hours}h"
        )
    else:
        window_start = checkpoint - timedelta(hours=overlap_hours)
    window_end = now

    body: dict[str, Any] = {
        "source": {
            "index": cfg.raw_stream,
            "query": {
                "range": {
                    "@timestamp": {"gte": _iso(window_start), "lte": _iso(window_end)}
                }
            },
        },
        "dest": {
            "index": cfg.masked_stream,
            "op_type": "create",
            "pipeline": cfg.pipeline_name,
        },
        "conflicts": "proceed",
    }
    print(
        f"sync-masked[{cfg.tenant}] window {_iso(window_start)} -> {_iso(window_end)} "
        f"(raw {cfg.raw_stream} -> {cfg.masked_stream} via {cfg.pipeline_name})"
    )
    if dry_run:
        print("dry run: reindex not sent, checkpoint not advanced.")
        return 0

    # Submit the reindex as an async task and poll it. wait_for_completion=false
    # returns a task id immediately, so a proxy/LB closing a long synchronous
    # connection cannot abort a large window. Transport-level failures are
    # retried with backoff; the checkpoint advances ONLY after the task completes
    # without failures (fail-closed).
    task_id = await _submit_reindex_task(client, cfg, config, body)
    if task_id is None:
        # Message already printed; checkpoint NOT advanced.
        return 1

    completed = await _poll_reindex_task(client, cfg, config, task_id)
    if completed is None:
        # Message already printed; checkpoint NOT advanced.
        return 1

    result = _reindex_task_result(completed)
    if result is None:
        print(
            f"sync-masked[{cfg.tenant}] reindex task completed but its result "
            "could not be read — success is not confirmed. checkpoint NOT "
            "advanced.",
            file=sys.stderr,
        )
        return 1
    failed = result.get("failures")
    if failed:
        # conflicts:proceed means create-conflicts are NOT failures; anything
        # listed here is a real error -> do not advance.
        print(
            f"sync-masked[{cfg.tenant}] reindex reported {len(failed)} failure(s); "
            "checkpoint NOT advanced.",
            file=sys.stderr,
        )
        print(json.dumps(failed[:5], indent=2)[:2000], file=sys.stderr)
        return 1

    # ---- Fail-closed backstop. Masking failures are rerouted to the quarantine
    # stream by the pipeline's on_failure; ANY quarantine doc in this window
    # means masking failed. Do NOT advance the checkpoint and alert, so the
    # window is retried after the pipeline is fixed. ----
    quarantine_count, masked_count = await _fail_closed_backstop(
        client, cfg, window_start, window_end
    )
    if quarantine_count is None or masked_count is None:
        print(
            f"sync-masked[{cfg.tenant}] FAIL: could not count the "
            f"{cfg.quarantine_stream_pattern} / {cfg.masked_stream_pattern} "
            "streams for the window — masking success could not be verified. "
            "checkpoint NOT advanced.",
            file=sys.stderr,
        )
        return 1
    if quarantine_count > 0:
        print(
            f"sync-masked[{cfg.tenant}] FAIL-CLOSED BACKSTOP: "
            f"{quarantine_count} masking-failure document(s) routed to "
            f"{cfg.quarantine_stream_pattern} in window "
            f"{_iso(window_start)} -> {_iso(window_end)}. checkpoint NOT "
            "advanced; the window will be re-scanned on the next run.",
            file=sys.stderr,
        )
        print(
            f"  Investigate the masking failures (klaxon.masking_error / "
            "klaxon.quarantine.reason in the quarantine stream) and fix the "
            "pipeline or the documents before re-running.",
            file=sys.stderr,
        )
        return 1

    # ---- Optional reconcile: source(window) == masked(window) + quarantine
    # (window), to catch silent drops (docs neither masked nor quarantined).
    # Off by default; KLAXON_SYNC_RECONCILE=true enables it, and
    # KLAXON_SYNC_RECONCILE_FAIL=true turns a mismatch into a failed run. ----
    if _env_flag("KLAXON_SYNC_RECONCILE"):
        source_count = await _count_window_docs(
            client, cfg.raw_stream, window_start, window_end
        )
        if source_count is None:
            print(
                f"sync-masked[{cfg.tenant}] reconcile SKIPPED: could not count "
                f"{cfg.raw_stream} for the window.",
                file=sys.stderr,
            )
        else:
            expected = masked_count + quarantine_count
            if source_count != expected:
                mismatch = (
                    f"sync-masked[{cfg.tenant}] RECONCILE MISMATCH: source "
                    f"({source_count}) != masked ({masked_count}) + quarantine "
                    f"({quarantine_count}) in window "
                    f"{_iso(window_start)} -> {_iso(window_end)} — silent drop "
                    "suspected."
                )
                if _env_flag("KLAXON_SYNC_RECONCILE_FAIL"):
                    print(mismatch + " checkpoint NOT advanced.", file=sys.stderr)
                    return 1
                print(mismatch, file=sys.stderr)
            else:
                print(
                    f"sync-masked[{cfg.tenant}] reconcile ok: source == masked + "
                    f"quarantine ({source_count})."
                )

    # Advance the checkpoint only after success.
    written = await _write_checkpoint(client, cfg, window_end)
    if not written.ok:
        print(
            f"sync-masked[{cfg.tenant}] reindex succeeded but checkpoint write "
            f"failed (HTTP {written.status_code}); window may be re-scanned next "
            "run (safe: op_type create + conflicts proceed).",
            file=sys.stderr,
        )
        return 1

    print(f"sync-masked[{cfg.tenant}] ok — checkpoint advanced to {_iso(window_end)}")
    await _report_masking_errors(client, cfg)
    return 0


async def _report_masking_errors(client: IndexerClient, cfg: TenantConfig) -> None:
    """Surface documents that were ingested but failed masking (flagged raw).

    Defense-in-depth only: with the fail-closed quarantine routing in place,
    masking failures never stay in the masked stream, so this should report 0.
    It catches a pipeline that predates the quarantine routing (the sync
    preflight refuses those, but a manual/legacy reindex could still write one).
    """
    query = {
        "size": 0,
        "query": {"exists": {"field": "klaxon.masking_error"}},
        "track_total_hits": True,
    }
    try:
        resp = await client.post(f"/{cfg.masked_stream_pattern}/_search", body=query)
    except TransportError:
        return
    if not resp.ok:
        return
    parsed = resp.json()
    total = (parsed.get("hits") or {}).get("total") if isinstance(parsed, dict) else None
    if isinstance(total, dict):
        count = total.get("value", 0)
    elif isinstance(total, int):
        count = total
    else:
        count = 0
    if count:
        print(
            f"sync-masked[{cfg.tenant}] WARNING: {count} document(s) in the masked "
            "stream carry klaxon.masking_error (masking failed, raw data "
            "flagged). Exclude them from queries (`NOT exists "
            "klaxon.masking_error`) and fix the pipeline.",
            file=sys.stderr,
        )


# --------------------------------------------------------------------------- #
# Fail-closed backstop: quarantine count + optional reconcile
# --------------------------------------------------------------------------- #


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


async def _count_window_docs(
    client: IndexerClient,
    pattern: str,
    window_start: datetime,
    window_end: datetime,
) -> int | None:
    """Exact document count of a stream pattern within the sync window.

    Returns None when the count could not be obtained (indexer unreachable /
    non-2xx). The caller treats None as FAIL-CLOSED (do not advance the
    checkpoint — the window's masking success could not be verified).
    """
    query = {
        "size": 0,
        "query": {
            "range": {"@timestamp": {"gte": _iso(window_start), "lte": _iso(window_end)}}
        },
        "track_total_hits": True,
    }
    try:
        resp = await client.post(f"/{pattern}/_search", body=query)
    except TransportError:
        return None
    if not resp.ok:
        return None
    parsed = resp.json()
    total = (parsed.get("hits") or {}).get("total") if isinstance(parsed, dict) else None
    if isinstance(total, dict):
        return int(total.get("value", 0))
    if isinstance(total, int):
        return total
    return 0


async def _fail_closed_backstop(
    client: IndexerClient,
    cfg: TenantConfig,
    window_start: datetime,
    window_end: datetime,
) -> tuple[int | None, int | None]:
    """Count quarantine docs for the window; return (quarantine_count, masked_count).

    quarantine_count > 0 means masking failed for that many documents in this
    window — the caller MUST fail the run and not advance the checkpoint. Either
    count is None when the corresponding stream could not be counted (fail-closed).
    """
    quarantine_count = await _count_window_docs(
        client, cfg.quarantine_stream_pattern, window_start, window_end
    )
    masked_count = await _count_window_docs(
        client, cfg.masked_stream_pattern, window_start, window_end
    )
    return quarantine_count, masked_count


def sync_command(
    tenant: str,
    *,
    overlap_hours: int = DEFAULT_OVERLAP_HOURS,
    initial_lookback_hours: int = DEFAULT_INITIAL_LOOKBACK_HOURS,
    dry_run: bool = False,
) -> int:
    """Reindex the recent window from the raw stream through the masking pipeline."""
    from . import server

    try:
        cfg = load_tenant_config(tenant)
        config = Config.from_env()
    except (ConfigError, FileNotFoundError, ValueError) as exc:
        print(f"sync-masked[{tenant}] error: {exc}", file=sys.stderr)
        return 2

    client = server.get_indexer()
    return asyncio.run(
        _sync(
            client,
            cfg,
            config,
            overlap_hours=overlap_hours,
            initial_lookback_hours=initial_lookback_hours,
            dry_run=dry_run,
        )
    )


# --------------------------------------------------------------------------- #
# verify-config (scheduled drift audit)
# --------------------------------------------------------------------------- #


def verify_command(tenant: str) -> int:
    """Compare fields.yaml vs committed config fragment vs config vs deployed pipeline."""
    from . import server
    from .masking import check_artifacts

    problems: list[str] = []
    try:
        cfg = load_tenant_config(tenant)
        config = Config.from_env()
    except (ConfigError, FileNotFoundError, ValueError) as exc:
        print(f"verify-config[{tenant}] error: {exc}", file=sys.stderr)
        return 2

    generated_drift = check_artifacts(cfg)
    if generated_drift:
        problems.append("generated artifacts drifted from fields.yaml:")
        problems.extend(f"  {line}" for line in generated_drift)

    try:
        client = server.get_indexer()
        deployed = asyncio.run(_fetch_pipeline(client, cfg))
    except TransportError as exc:
        print(f"verify-config[{tenant}] indexer unreachable: {exc}", file=sys.stderr)
        deployed = None

    problems.extend(preflight_report(cfg, deployed, config))

    print(f"verify-config[{tenant}] fields.yaml sha256: {fields_yaml_sha256(cfg)}")
    if problems:
        print("DRIFT DETECTED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print("ok: fields.yaml, config and deployed pipeline are in sync.")
    return 0


# --------------------------------------------------------------------------- #
# salt-check (deploy-time salt comparison)
# --------------------------------------------------------------------------- #


def salt_check_command(tenant: str) -> int:
    """Compare the salt baked into the DEPLOYED pipeline with the current env salt.

    The deployed pipeline carries its salt in `params.salt` (ingest pipelines
    cannot read process env). If the current `KLAXON_ANONYMIZATION_SALT` (or
    `salt_env` from fields.yaml) differs from what was deployed, tokens from the
    deployed pipeline will not match a fresh generate/apply — determinism is
    lost — so a mismatch is an error.
    """
    from . import server
    from .masking import check_deployed_salt

    try:
        cfg = load_tenant_config(tenant)
    except (FileNotFoundError, ValueError) as exc:
        print(f"salt-check[{tenant}] error: {exc}", file=sys.stderr)
        return 2

    current = os.environ.get(cfg.salt_env, "").strip() or None
    if current is None:
        print(
            f"salt-check[{tenant}] {cfg.salt_env} is not set — cannot compare "
            "against the deployed pipeline. Set it to the salt the pipeline was "
            "deployed with.",
            file=sys.stderr,
        )
        return 2

    try:
        client = server.get_indexer()
    except Exception as exc:  # noqa: BLE001 - a broken indexer is a reportable error
        print(f"salt-check[{tenant}] indexer unreachable: {exc}", file=sys.stderr)
        return 1

    deployed = asyncio.run(_fetch_pipeline(client, cfg))
    if deployed is None:
        print(
            f"salt-check[{tenant}] pipeline {cfg.pipeline_name} is not deployed. "
            f"Deploy it first (`klaxon-mcp --apply-masked-infra --tenant {tenant}`).",
            file=sys.stderr,
        )
        return 1

    ok, message = check_deployed_salt(deployed, current)
    print(f"salt-check[{tenant}] {message}")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# --apply-masked-infra (deploy pipeline + ISM + template + data stream)
# --------------------------------------------------------------------------- #


async def _fetch_wazuh_mappings(client: IndexerClient) -> dict[str, Any]:
    """Copy the mappings of the Wazuh events stream so queries behave identically."""
    resp = await client.get("/wazuh-events-v5-*/_mapping")
    if not resp.ok:
        raise RuntimeError(
            f"could not fetch wazuh-events-v5-* mappings (HTTP {resp.status_code})"
        )
    parsed = resp.json()
    if not isinstance(parsed, dict):
        raise RuntimeError("unexpected response from _mapping")
    # Merge mappings of all matching indices: first one's mappings object.
    for value in parsed.values():
        if isinstance(value, dict) and isinstance(value.get("mappings"), dict):
            return cast(dict[str, Any], value["mappings"])
    return {}


async def _apply_infra(
    client: IndexerClient,
    cfg: TenantConfig,
    *,
    retention_days: int,
    dry_run: bool,
) -> int:
    try:
        mappings = await _fetch_wazuh_mappings(client)
    except RuntimeError as exc:
        print(f"apply-masked-infra[{cfg.tenant}] error: {exc}", file=sys.stderr)
        return 1

    pipeline = deploy_pipeline(cfg)
    ism = build_ism_policy(cfg, retention_days)
    template = build_index_template(cfg, mappings)
    # Quarantine infra: the template's pattern covers the on_failure routing
    # target (klaxon-quarantine-<tenant>-v5-raw), which auto-creates on first
    # masking failure. No index.default_pipeline — quarantine docs must never
    # re-enter the masking pipeline.
    quarantine_ism = build_quarantine_ism_policy(cfg, QUARANTINE_RETENTION_DAYS)
    quarantine_template = build_quarantine_index_template(cfg, mappings)

    if dry_run:
        print(f"apply-masked-infra[{cfg.tenant}] dry run — would PUT:")
        print(f"  pipeline  {cfg.pipeline_name}")
        print(f"  ISM       {cfg.ism_policy_name} (retention {retention_days}d)")
        print(f"  template  {cfg.index_template_name}")
        print(f"  data stream {cfg.masked_stream}")
        print(f"  ISM       {cfg.quarantine_ism_policy_name} (retention "
              f"{QUARANTINE_RETENTION_DAYS}d, forensics)")
        print(f"  template  {cfg.quarantine_index_template_name}")
        return 0

    try:
        results = [
            ("pipeline", await client.put(f"/_ingest/pipeline/{cfg.pipeline_name}", body=pipeline)),
            ("ISM policy", await client.put(f"/_plugins/_ism/policies/{cfg.ism_policy_name}", body=ism)),
            ("index template", await client.put(f"/_index_template/{cfg.index_template_name}", body=template)),
            ("data stream", await client.put(f"/_data_stream/{cfg.masked_stream}", body={})),
            ("quarantine ISM policy", await client.put(
                f"/_plugins/_ism/policies/{cfg.quarantine_ism_policy_name}",
                body=quarantine_ism,
            )),
            ("quarantine index template", await client.put(
                f"/_index_template/{cfg.quarantine_index_template_name}",
                body=quarantine_template,
            )),
        ]
    except TransportError as exc:
        print(f"apply-masked-infra[{cfg.tenant}] transport error: {exc}", file=sys.stderr)
        return 1

    for name, resp in results:
        if not resp.ok:
            print(
                f"apply-masked-infra[{cfg.tenant}] PUT {name} failed (HTTP "
                f"{resp.status_code}): {resp.text[:500]}",
                file=sys.stderr,
            )
            return 1

    print(
        f"apply-masked-infra[{cfg.tenant}] ok: pipeline, ISM ({retention_days}d "
        f"retention), template and data stream {cfg.masked_stream} in place, plus "
        f"quarantine ISM ({QUARANTINE_RETENTION_DAYS}d) and quarantine template "
        f"{cfg.quarantine_index_template_name} (fail-closed on_failure routing)."
    )
    return 0


def apply_infra_command(
    tenant: str, *, retention_days: int = DEFAULT_RETENTION_DAYS, dry_run: bool = False
) -> int:
    """Create the masking pipeline, ISM policy, index template and data stream."""
    from . import server

    try:
        cfg = load_tenant_config(tenant)
        Config.from_env()
    except (ConfigError, FileNotFoundError, ValueError) as exc:
        print(f"apply-masked-infra[{tenant}] error: {exc}", file=sys.stderr)
        return 2

    client = server.get_indexer()
    return asyncio.run(
        _apply_infra(client, cfg, retention_days=retention_days, dry_run=dry_run)
    )


# --------------------------------------------------------------------------- #
# migrate-quarantine (ONE-TIME migration of pre-quarantine masking_error docs)
#
# Before the fail-closed on_failure existed, masking-failure documents were
# flagged `klaxon.masking_error` and LEFT in the masked stream. This command
# migrates them into the quarantine stream and removes them from the masked
# stream. Operator-run ONLY (never automated): it DELETES documents. Idempotent:
# after a successful run there are no masking_error docs left, so re-running is
# a no-op. The reindex does NOT go through the masking pipeline — quarantine
# documents must never re-enter masking.
# --------------------------------------------------------------------------- #


async def _migrate_quarantine(
    client: IndexerClient, cfg: TenantConfig, *, dry_run: bool
) -> int:
    exists_query = {"query": {"exists": {"field": "klaxon.masking_error"}}}

    count_resp = await client.post(
        f"/{cfg.masked_stream_pattern}/_search",
        body={**exists_query, "size": 0, "track_total_hits": True},
    )
    if not count_resp.ok:
        print(
            f"migrate-quarantine[{cfg.tenant}] could not count masking_error "
            f"docs in {cfg.masked_stream_pattern} (HTTP "
            f"{count_resp.status_code})",
            file=sys.stderr,
        )
        return 1
    parsed = count_resp.json()
    total = (parsed.get("hits") or {}).get("total") if isinstance(parsed, dict) else None
    count = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    if count == 0:
        print(
            f"migrate-quarantine[{cfg.tenant}] no klaxon.masking_error docs in "
            f"{cfg.masked_stream_pattern} — nothing to migrate."
        )
        return 0
    print(
        f"migrate-quarantine[{cfg.tenant}] {count} masking_error doc(s) found "
        f"in {cfg.masked_stream_pattern}."
    )
    if dry_run:
        print(
            f"  dry run: would reindex them into {cfg.quarantine_routing_index} "
            "(no masking pipeline) and delete them from the masked stream."
        )
        return 0

    # 1. Reindex the flagged docs into the quarantine stream (op_type create +
    #    conflicts proceed: idempotent, no duplicates). NO dest pipeline — the
    #    quarantine template carries no index.default_pipeline, and passing the
    #    masking pipeline here would re-mask (and could re-trigger) the failure.
    reindex_body = {
        "source": {"index": cfg.masked_stream_pattern, **exists_query},
        "dest": {"index": cfg.quarantine_routing_index, "op_type": "create"},
        "conflicts": "proceed",
    }
    try:
        resp = await client.post("/_reindex", body=reindex_body)
    except TransportError as exc:
        print(f"migrate-quarantine[{cfg.tenant}] reindex failed: {exc}", file=sys.stderr)
        return 1
    if not resp.ok:
        print(
            f"migrate-quarantine[{cfg.tenant}] reindex FAILED (HTTP "
            f"{resp.status_code}); nothing was deleted.",
            file=sys.stderr,
        )
        print(resp.text[:1000], file=sys.stderr)
        return 1
    reindexed = resp.json()
    if reindexed.get("failures"):
        print(
            f"migrate-quarantine[{cfg.tenant}] reindex reported failure(s); "
            "NOTHING was deleted from the masked stream. Investigate before "
            "re-running.",
            file=sys.stderr,
        )
        print(json.dumps(reindexed["failures"][:5], indent=2)[:1500], file=sys.stderr)
        return 1
    migrated = int(reindexed.get("created", 0))

    # 2. Delete the migrated docs from the masked stream (same query).
    try:
        del_resp = await client.post(
            f"/{cfg.masked_stream_pattern}/_delete_by_query", body=exists_query
        )
    except TransportError as exc:
        print(f"migrate-quarantine[{cfg.tenant}] delete failed: {exc}", file=sys.stderr)
        return 1
    if not del_resp.ok:
        print(
            f"migrate-quarantine[{cfg.tenant}] delete-by-query FAILED (HTTP "
            f"{del_resp.status_code}); the docs were COPIED to quarantine but "
            "still remain in the masked stream — re-run the migration.",
            file=sys.stderr,
        )
        print(del_resp.text[:1000], file=sys.stderr)
        return 1
    del_parsed = del_resp.json()
    deleted = int(del_parsed.get("deleted", 0)) if isinstance(del_parsed, dict) else 0

    print(
        f"migrate-quarantine[{cfg.tenant}] migrated {migrated} masking_error "
        f"doc(s) to {cfg.quarantine_routing_index} (no masking pipeline) and "
        f"deleted {deleted} from {cfg.masked_stream_pattern}."
    )
    if migrated != deleted:
        print(
            f"  WARNING: migrated ({migrated}) != deleted ({deleted}); re-run "
            "the migration to converge.",
            file=sys.stderr,
        )
        return 1
    return 0


def migrate_quarantine_command(
    tenant: str, *, dry_run: bool = False
) -> int:
    """ONE-TIME, operator-run migration of legacy masking_error docs to quarantine.

    NEVER automated. Finds `klaxon.masking_error` docs in the masked stream,
    reindexes them into the quarantine stream (op_type create, conflicts
    proceed, no masking pipeline), then deletes them from the masked stream and
    logs the count. Idempotent: re-running after success is a no-op.
    """
    from . import server

    try:
        cfg = load_tenant_config(tenant)
        Config.from_env()
    except (ConfigError, FileNotFoundError, ValueError) as exc:
        print(f"migrate-quarantine[{tenant}] error: {exc}", file=sys.stderr)
        return 2

    client = server.get_indexer()
    return asyncio.run(_migrate_quarantine(client, cfg, dry_run=dry_run))
