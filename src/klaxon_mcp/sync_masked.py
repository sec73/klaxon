# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Option B operational commands: sync the masked stream, verify drift, apply infra.

All commands talk to the indexer DIRECTLY (never through the response masker) —
the sync job must see raw values to mask them, and that is intentional. The raw
Wazuh streams are only ever read; nothing is written to them.

Commands (wired into `klaxon-mcp`):
  * sync-masked  --tenant X      periodic reindex of a time window through the
                                 masking pipeline, with a checkpoint + preflight
  * verify-config --tenant X     drift audit: fields.yaml vs config vs pipeline
  * apply-masked-infra --tenant X  PUT pipeline (real salt), ISM, template,
                                 data stream
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from .clients import IndexerClient, Response, TransportError
from .config import Config, ConfigError
from .masked_stream import (
    DEFAULT_INITIAL_LOOKBACK_HOURS,
    DEFAULT_OVERLAP_HOURS,
    DEFAULT_RETENTION_DAYS,
    TenantConfig,
    build_index_template,
    build_ism_policy,
    deploy_pipeline,
    effective_mask_fields_from_config,
    fields_yaml_sha256,
    fingerprint_matches,
    load_tenant_config,
    pipeline_field_names,
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
            "`klaxon-mcp apply-masked-infra --tenant <tenant>` first."
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

    try:
        resp = await client.post("/_reindex", body=body)
    except TransportError as exc:
        print(
            f"sync-masked[{cfg.tenant}] reindex failed at transport level: {exc}",
            file=sys.stderr,
        )
        return 1

    if not resp.ok:
        # Do NOT advance the checkpoint: the window is retried on the next run.
        print(
            f"sync-masked[{cfg.tenant}] reindex FAILED (HTTP {resp.status_code}); "
            "checkpoint NOT advanced. Failed window will be retried.",
            file=sys.stderr,
        )
        print(resp.text[:2000], file=sys.stderr)
        return 1

    parsed = resp.json()
    failed = parsed.get("failures") if isinstance(parsed, dict) else None
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
    """Surface documents that were ingested but failed masking (flagged raw)."""
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
            f"Deploy it first (`klaxon-mcp apply-masked-infra --tenant {tenant}`).",
            file=sys.stderr,
        )
        return 1

    ok, message = check_deployed_salt(deployed, current)
    print(f"salt-check[{tenant}] {message}")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# apply-masked-infra (deploy pipeline + ISM + template + data stream)
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

    if dry_run:
        print(f"apply-masked-infra[{cfg.tenant}] dry run — would PUT:")
        print(f"  pipeline  {cfg.pipeline_name}")
        print(f"  ISM       {cfg.ism_policy_name} (retention {retention_days}d)")
        print(f"  template  {cfg.index_template_name}")
        print(f"  data stream {cfg.masked_stream}")
        return 0

    try:
        results = [
            ("pipeline", await client.put(f"/_ingest/pipeline/{cfg.pipeline_name}", body=pipeline)),
            ("ISM policy", await client.put(f"/_plugins/_ism/policies/{cfg.ism_policy_name}", body=ism)),
            ("index template", await client.put(f"/_index_template/{cfg.index_template_name}", body=template)),
            ("data stream", await client.put(f"/_data_stream/{cfg.masked_stream}", body={})),
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
        f"retention), template and data stream {cfg.masked_stream} in place."
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
