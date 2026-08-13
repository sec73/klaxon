# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""`klaxon masking deploy` — one idempotent, ordered, self-verifying Option B deploy.

Manual deployment was failing in practice: missing `yq`, YAML->JSON conversion,
"already exists" on the data stream, ordering mistakes, TLS/auth friction, and a
deploy racing a running sync job. This subcommand deploys the generated masking
artifacts to the indexer in ONE step:

  preflight (fail-fast, before any write)
    1. drift check against fields.yaml (reuses verify-config / check_artifacts)
    2. indexer credentials set (KLAXON_INDEXER_URL/USER/PASSWORD)
    3. salt env set (deploy would otherwise bake a random salt that diverges
       from the response layer)
    4. the DEPLOYED pipeline's salt matches the env salt (tokens stay
       deterministic across deploys)
    5. no sync job is running/very recent (a documented heuristic — there is no
       lock; abort unless --force)
    6. the mandatory generator self-test passes (the script to be deployed is
       byte-identical to derive_token)

  ordered deployment (each step idempotent, verified after every PUT):
    1. pipeline            PUT /_ingest/pipeline/klaxon-mask-<tenant>
    2. ISM policies (both) PUT /_plugins/_ism/policies/...
    3. index templates (both)  PUT /_index_template/...
    4. masked data stream  create only if absent (already exists == success)
    5. roles               roles-<tenant>.yaml converted to JSON IN CODE (no yq)
    6. role mappings       only if the fragment carries mapping info; otherwise
                           a reminder to map users/backends
  final smoke test: POST /_ingest/pipeline/<name>/_simulate with
  {"user":{"name":"marcomoenig"},"message":"uid=marcomoenig"} -> user.name and
  the free-text uid= use the SAME token and no klaxon.masking_error is set.

  --dry-run  prints the full plan without writing anything
  --rollback restores the last snapshot (tenants/<tenant>/generated/backup/<ts>/)
             via the same ordered path

The running server stays write-incapable: this is a separate CLI path that must
be invoked explicitly with admin credentials. Credentials come ONLY from
KLAXON_INDEXER_URL/USER/PASSWORD (optionally a gitignored local .env via
--env), exactly like `klaxon masking test`. The password, the salt, token values
and raw data are NEVER logged — only names, statuses and counts.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml

from .artifact_io import check_artifacts, generated_dir
from .live_config import resolve_live_config
from .masked_stream import (
    QUARANTINE_RETENTION_DAYS,
    TenantConfig,
    build_deployable_pipeline,
    build_index_template,
    build_ism_policy,
    build_quarantine_index_template,
    build_quarantine_ism_policy,
    load_tenant_config,
    resolve_salt,
)
from .masking import check_deployed_salt, run_generator_selftest
from .tokens import token

# The sync-job heuristic window: a checkpoint `updated` within this many seconds
# means a sync completed recently and a new window may start any moment. There
# is no lock in the sync job, so this is a documented best-effort guard, not a
# lock — override with `--force` when you know no sync is running.
SYNC_RUNNING_WINDOW_SECONDS = 300

_TIMEOUT = 60.0

# Keys OpenSearch adds around/when re-serving a deployed resource. Dropped before
# the "does what was sent match what came back" fingerprint comparison.
_IGNORED_WRAPPER_KEYS = frozenset(
    {"_id", "_index", "_version", "_seq_no", "_primary_term", "_source", "_meta"}
)


def _ts() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _fingerprint(obj: Any) -> str:
    """A stable summary fingerprint of a resource body (sorted keys)."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _drop_wrapper_keys(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: v for k, v in obj.items() if k not in _IGNORED_WRAPPER_KEYS}
    return obj


def _sent_resource(kind: str, body: Any) -> Any:
    """The resource body as the GET will return it, for the fingerprint compare.

    ISM PUT bodies are wrapped in `{"policy": ...}` while the GET returns the
    unwrapped policy; everything else is returned as sent.
    """
    if kind == "ism" and isinstance(body, dict):
        return _drop_wrapper_keys(body.get("policy", body))
    return _drop_wrapper_keys(body)


def _extract_resource(kind: str, path: str, parsed: Any) -> dict[str, Any] | None:
    """The resource body from a GET response, per resource kind."""
    if not isinstance(parsed, dict):
        return None
    if kind == "pipeline":
        name = path.rsplit("/", 1)[1]
        body = parsed.get(name)
        return body if isinstance(body, dict) else None
    if kind == "ism":
        body = parsed.get("policy")
        return body if isinstance(body, dict) else None
    if kind == "template":
        entries = parsed.get("index_templates")
        if isinstance(entries, list) and entries and isinstance(entries[0], dict):
            body = entries[0].get("index_template")
            return body if isinstance(body, dict) else None
        return None
    if kind == "role":
        name = path.rsplit("/", 1)[1]
        body = parsed.get(name)
        return body if isinstance(body, dict) else None
    return None


async def _get_resource(
    client: httpx.AsyncClient, kind: str, path: str
) -> dict[str, Any] | None:
    """GET a deployed resource and extract its body; None when absent/unreadable."""
    resp = await client.get(path)
    if not resp.is_success:
        return None
    return _extract_resource(kind, path, resp.json())


async def _put_verified(
    client: httpx.AsyncClient,
    label: str,
    path: str,
    body: Any,
    *,
    kind: str,
    lines: list[str],
) -> bool:
    """PUT a resource, then GET it back and assert the fingerprint matches.

    Appends an `[ok]`/`[skip]`/`[fail]` line. Returns success.
    """
    resp = await client.put(path, content=json.dumps(body))
    if not resp.is_success:
        lines.append(
            f"[fail] {label}: PUT returned HTTP {resp.status_code} — {_error_detail(resp)}"
        )
        return False
    sent = _sent_resource(kind, body)
    received = await _get_resource(client, kind, path)
    if received is None:
        lines.append(f"[fail] {label}: PUT ok but GET back failed/empty — verify")
        return False
    received_norm = _drop_wrapper_keys(received)
    if _fingerprint(received_norm) != _fingerprint(sent):
        lines.append(
            f"[fail] {label}: deployed resource does not match what was sent "
            "(verify) — fingerprint differs"
        )
        return False
    lines.append(f"[ok] {label} (verified)")
    return True


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
                return str(reason)[:300]
    return f"HTTP {resp.status_code}"


async def _fetch_wazuh_mappings(client: httpx.AsyncClient) -> dict[str, Any]:
    """The mappings of the Wazuh events stream (mirror of sync_masked's).

    Read-only; needed so the masked data stream carries the same mappings as the
    raw stream and queries behave identically.
    """
    resp = await client.get("/wazuh-events-v5-*/_mapping")
    if not resp.is_success:
        raise RuntimeError(
            f"could not fetch wazuh-events-v5-* mappings (HTTP {resp.status_code})"
        )
    try:
        parsed = resp.json()
    except ValueError as exc:
        raise RuntimeError("unexpected response from _mapping") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("unexpected response from _mapping")  # noqa: TRY004
    for value in parsed.values():
        if isinstance(value, dict) and isinstance(value.get("mappings"), dict):
            return dict(value["mappings"])
    return {}


# --------------------------------------------------------------------------- #
# Preflight
# --------------------------------------------------------------------------- #


async def _get_deployed_pipeline(
    client: httpx.AsyncClient, cfg: TenantConfig
) -> dict[str, Any] | None:
    """The currently deployed pipeline body, or None."""
    resp = await client.get(f"/_ingest/pipeline/{cfg.pipeline_name}")
    if not resp.is_success:
        return None
    parsed = resp.json()
    if not isinstance(parsed, dict):
        return None
    body = parsed.get(cfg.pipeline_name)
    return body if isinstance(body, dict) else None


async def _sync_recently_active(
    client: httpx.AsyncClient, cfg: TenantConfig, window_seconds: int = SYNC_RUNNING_WINDOW_SECONDS
) -> bool:
    """Heuristic: was the sync checkpoint written within `window_seconds`?

    The sync job advances its checkpoint only AFTER a successful run; there is
    no lock, so a recent checkpoint is the only signal a new window may start
    imminently. Documented as best-effort — use `--force` when you know no sync
    is running.
    """
    resp = await client.get(f"/{cfg.sync_state_index}/_doc/{cfg.sync_state_doc_id}")
    if not resp.is_success:
        return False
    parsed = resp.json()
    source = parsed.get("_source") if isinstance(parsed, dict) else None
    if not isinstance(source, dict):
        return False
    raw = source.get("updated")
    if not isinstance(raw, str):
        return False
    try:
        updated = datetime.fromisoformat(raw)
    except ValueError:
        return False
    age = (datetime.now(UTC) - updated.astimezone(UTC)).total_seconds()
    return 0 <= age < window_seconds


def _parse_roles_fragment(cfg: TenantConfig) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse the roles fragment into (roles, rolemappings).

    The fragment is a YAML mapping of role name -> spec. A top-level
    `rolemapping` key (if present) holds mapping specs; everything else is a
    role. Done in code (pyyaml) — no external `yq` dependency.
    """
    from .masked_stream import build_roles_fragment

    text = build_roles_fragment(cfg)
    parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict):
        raise ValueError("roles fragment is not a mapping")  # noqa: TRY004
    raw: dict[str, Any] = dict(parsed)
    mappings: dict[str, Any] = {}
    rolemap = raw.pop("rolemapping", None)
    if isinstance(rolemap, dict):
        mappings = dict(rolemap)
    elif isinstance(rolemap, list):
        for item in rolemap:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                mappings[str(item["name"])] = item
    return raw, mappings


# --------------------------------------------------------------------------- #
# Deployment
# --------------------------------------------------------------------------- #


def _deploy_plan(cfg: TenantConfig, roles: dict[str, Any]) -> list[str]:
    plan = [
        f"pipeline      {cfg.pipeline_name}",
        f"ISM           {cfg.ism_policy_name} (retention masked)",
        f"ISM           {cfg.quarantine_ism_policy_name} (quarantine)",
        f"index template {cfg.index_template_name}",
        f"index template {cfg.quarantine_index_template_name}",
        f"data stream   {cfg.masked_stream} (create only if absent)",
    ]
    plan.extend(f"role          {name}" for name in roles)
    return plan


async def _deploy_roles(
    client: httpx.AsyncClient, cfg: TenantConfig, roles: dict[str, Any], lines: list[str]
) -> bool:
    ok = True
    for name, spec in roles.items():
        if not await _put_verified(
            client, f"role {name}", f"/_plugins/_security/api/roles/{name}", spec, kind="role", lines=lines
        ):
            ok = False
    return ok


async def _deploy_core(
    client: httpx.AsyncClient,
    cfg: TenantConfig,
    salt: str,
    *,
    retention_days: int,
    lines: list[str],
) -> bool:
    """Run the ordered deployment steps; return overall success."""
    try:
        mappings = await _fetch_wazuh_mappings(client)
    except RuntimeError as exc:
        lines.append(f"[fail] could not fetch wazuh-events-v5-* mappings: {exc}")
        return False

    pipeline = build_deployable_pipeline(cfg, salt)
    ism = build_ism_policy(cfg, retention_days)
    template = build_index_template(cfg, mappings)
    quarantine_ism = build_quarantine_ism_policy(cfg, QUARANTINE_RETENTION_DAYS)
    quarantine_template = build_quarantine_index_template(cfg, mappings)
    roles, mappings_cfg = _parse_roles_fragment(cfg)

    # 1. Pipeline
    if not await _put_verified(
        client,
        f"pipeline {cfg.pipeline_name}",
        f"/_ingest/pipeline/{cfg.pipeline_name}",
        pipeline,
        kind="pipeline",
        lines=lines,
    ):
        return False
    # 2. ISM policies (both)
    if not await _put_verified(
        client,
        f"ISM {cfg.ism_policy_name}",
        f"/_plugins/_ism/policies/{cfg.ism_policy_name}",
        ism,
        kind="ism",
        lines=lines,
    ):
        return False
    if not await _put_verified(
        client,
        f"ISM {cfg.quarantine_ism_policy_name}",
        f"/_plugins/_ism/policies/{cfg.quarantine_ism_policy_name}",
        quarantine_ism,
        kind="ism",
        lines=lines,
    ):
        return False
    # 3. Index templates (both)
    if not await _put_verified(
        client,
        f"index template {cfg.index_template_name}",
        f"/_index_template/{cfg.index_template_name}",
        template,
        kind="template",
        lines=lines,
    ):
        return False
    if not await _put_verified(
        client,
        f"index template {cfg.quarantine_index_template_name}",
        f"/_index_template/{cfg.quarantine_index_template_name}",
        quarantine_template,
        kind="template",
        lines=lines,
    ):
        return False
    # 4. Masked data stream — create only if absent ("already exists" = success).
    resp = await client.get(f"/_data_stream/{cfg.masked_stream}*")
    if resp.is_success:
        parsed = resp.json()
        streams = parsed.get("data_streams") if isinstance(parsed, dict) else None
        if isinstance(streams, list) and streams:
            lines.append(
                f"[skip] data stream {cfg.masked_stream} already exists"
            )
        else:
            create = await client.put(f"/_data_stream/{cfg.masked_stream}", content="{}")
            if not create.is_success:
                lines.append(
                    f"[fail] data stream {cfg.masked_stream}: PUT returned HTTP "
                    f"{create.status_code} — {_error_detail(create)}"
                )
                return False
            lines.append(f"[ok] data stream {cfg.masked_stream} created")
    else:
        lines.append(
            f"[fail] data stream existence check failed (HTTP {resp.status_code})"
        )
        return False
    # 5. Roles (YAML -> JSON in code).
    if not await _deploy_roles(client, cfg, roles, lines):
        return False
    # 6. Role mappings — only if the fragment carries mapping info.
    if mappings_cfg:
        for name, spec in mappings_cfg.items():
            if not await _put_verified(
                client,
                f"role mapping {name}",
                f"/_plugins/_security/api/rolesmapping/{name}",
                spec,
                kind="role",
                lines=lines,
            ):
                return False
    else:
        lines.append(
            "[info] roles fragment carries no rolemapping section — map "
            "users/backends to the roles manually "
            "(PUT /_plugins/_security/api/rolesmapping/<role>)"
        )
    return True


async def _smoke_test(
    client: httpx.AsyncClient, cfg: TenantConfig, salt: str, lines: list[str]
) -> bool:
    """Final smoke test against the DEPLOYED pipeline by name."""
    doc = {"user": {"name": "marcomoenig"}, "message": "uid=marcomoenig"}
    resp = await client.post(
        f"/_ingest/pipeline/{cfg.pipeline_name}/_simulate",
        content=json.dumps({"docs": [{"_source": doc}]}),
    )
    if not resp.is_success:
        lines.append(
            f"[fail] smoke _simulate returned HTTP {resp.status_code} — {_error_detail(resp)}"
        )
        return False
    parsed = resp.json()
    docs = parsed.get("docs") if isinstance(parsed, dict) else None
    if not isinstance(docs, list) or not docs:
        lines.append("[fail] smoke _simulate returned no docs")
        return False
    first = docs[0]
    doc_obj = first.get("doc") if isinstance(first, dict) else None
    source = doc_obj.get("_source") if isinstance(doc_obj, dict) else None
    if not isinstance(source, dict):
        lines.append("[fail] smoke _simulate produced no _source")
        return False

    expected = token("USER", "marcomoenig", salt)
    user_obj = source.get("user")
    username = user_obj.get("name") if isinstance(user_obj, dict) else None
    message = source.get("message")
    masking_error = None
    klaxon = source.get("klaxon")
    if isinstance(klaxon, dict):
        masking_error = klaxon.get("masking_error")

    problems: list[str] = []
    if username != expected:
        problems.append(
            f"user.name -> {username!r}, expected a token (not a raw username)"
        )
    if not isinstance(message, str) or expected not in message:
        problems.append("the free-text uid= value is not masked with the SAME token")
    if masking_error:
        problems.append("klaxon.masking_error is set")
    if problems:
        for p in problems:
            lines.append(f"[fail] smoke test: {p}")
        return False
    lines.append("[ok] smoke test: user.name and free-text uid= share one token, no masking_error")
    return True


# --------------------------------------------------------------------------- #
# Snapshot / rollback
# --------------------------------------------------------------------------- #


def _backup_dir(cfg: TenantConfig) -> Path:
    return Path(generated_dir(cfg)) / "backup"


def _new_snapshot_dir(cfg: TenantConfig) -> Path:
    d = _backup_dir(cfg) / _ts()
    d.mkdir(parents=True, exist_ok=True)
    return d


async def _snapshot_current(
    client: httpx.AsyncClient, cfg: TenantConfig, ts_dir: Path, lines: list[str]
) -> None:
    """Save the CURRENT deployed resources (only those that exist) to `ts_dir`."""
    entries: list[tuple[str, str, str]] = [
        ("01", "pipeline", f"/_ingest/pipeline/{cfg.pipeline_name}"),
        ("02", "ism-masked", f"/_plugins/_ism/policies/{cfg.ism_policy_name}"),
        ("03", "ism-quarantine", f"/_plugins/_ism/policies/{cfg.quarantine_ism_policy_name}"),
        ("04", "template-masked", f"/_index_template/{cfg.index_template_name}"),
        ("05", "template-quarantine", f"/_index_template/{cfg.quarantine_index_template_name}"),
    ]
    for seq, name, path in entries:
        body = await _get_resource(client, "pipeline" if name == "pipeline" else ("ism" if name.startswith("ism") else "template"), path)
        if body is None:
            continue
        (ts_dir / f"{seq}-{name}.json").write_text(
            json.dumps(body, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
    lines.append(f"[info] snapshot of previous state saved to {ts_dir}")


def _latest_snapshot_dir(cfg: TenantConfig) -> Path | None:
    base = _backup_dir(cfg)
    if not base.is_dir():
        return None
    snapshots = sorted(
        (p for p in base.iterdir() if p.is_dir()), reverse=True
    )
    return snapshots[0] if snapshots else None


async def _rollback(
    client: httpx.AsyncClient, cfg: TenantConfig, ts_dir: Path, lines: list[str]
) -> bool:
    """Re-deploy the last snapshot via the same ordered path."""
    for path in sorted(ts_dir.iterdir()):
        if not path.is_file() or not path.name.endswith(".json"):
            continue
        body = json.loads(path.read_text(encoding="utf-8"))
        kind = "pipeline" if path.name.startswith("01") else (
            "ism" if path.name.startswith(("02", "03")) else "template"
        )
        if kind == "ism":
            # The snapshot stored the unwrapped policy; ISM PUT expects the
            # {"policy": ...} wrapper.
            body = {"policy": body}
        resource = path.name.split("-", 1)[1].rsplit(".", 1)[0]
        name = {
            "pipeline": cfg.pipeline_name,
            "ism-masked": cfg.ism_policy_name,
            "ism-quarantine": cfg.quarantine_ism_policy_name,
            "template-masked": cfg.index_template_name,
            "template-quarantine": cfg.quarantine_index_template_name,
        }[resource]
        target = {
            "pipeline": f"/_ingest/pipeline/{name}",
            "ism-masked": f"/_plugins/_ism/policies/{name}",
            "ism-quarantine": f"/_plugins/_ism/policies/{name}",
            "template-masked": f"/_index_template/{name}",
            "template-quarantine": f"/_index_template/{name}",
        }[resource]
        if not await _put_verified(
            client, f"rollback {resource} {name}", target, body, kind=kind, lines=lines
        ):
            return False
    return True


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="klaxon masking deploy",
        description=(
            "Deploy the Option B masking artifacts to the indexer in one "
            "idempotent, ordered, self-verifying step (pipeline, ISM policies, "
            "index templates, masked data stream, security roles). Preflight "
            "aborts on drift, missing credentials, salt mismatch or a running "
            "sync. Credentials come ONLY from KLAXON_INDEXER_URL/USER/PASSWORD "
            "(or a gitignored local .env via --env); the password, salt, tokens "
            "and raw data are never logged."
        ),
    )
    parser.add_argument("--tenant", metavar="TENANT", required=True, help="Tenant to deploy.")
    parser.add_argument(
        "--root", type=Path, default=None, help="Repo root (default: auto)."
    )
    parser.add_argument(
        "--env",
        metavar="FILE",
        default=None,
        help="Local dotenv file with KLAXON_INDEXER_* vars (default: first "
        "existing of .env.live, tests/live/.env).",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=None,
        metavar="N",
        help="Masked-stream ISM delete-after (default 30; quarantine always 90).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the full plan and preflight result WITHOUT writing anything.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Proceed even if a sync job appears to be running/very recent.",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Re-deploy the last snapshot (tenants/<tenant>/generated/backup/"
        "<ts>/) via the same ordered path. Pipeline rollback is safe: no data "
        "loss, the sync job can simply re-run.",
    )
    return parser.parse_args(argv)


async def _run(
    live: Any,
    cfg: TenantConfig,
    salt: str,
    *,
    retention_days: int,
    dry_run: bool,
    force: bool,
    rollback: bool,
) -> int:
    lines: list[str] = []
    if not live.verify_ssl:
        print(
            f"deploy[{cfg.tenant}] WARNING: KLAXON_INDEXER_VERIFY_SSL=false — "
            "TLS verification is DISABLED. Use it only against a self-signed "
            "lab cluster; for anything else trust the cluster CA "
            "(SSL_CERT_FILE / system trust store) instead.",
            file=sys.stderr,
        )
    async with httpx.AsyncClient(
        base_url=live.url,
        auth=(live.user, live.password),
        verify=live.verify_ssl,
        timeout=_TIMEOUT,
        headers={"Content-Type": "application/json"},
    ) as client:
        if rollback:
            snapshot = _latest_snapshot_dir(cfg)
            if snapshot is None:
                print(f"deploy[{cfg.tenant}] no snapshot to roll back to.", file=sys.stderr)
                return 1
            if dry_run:
                print(f"deploy[{cfg.tenant}] rollback dry run — would re-deploy snapshot {snapshot}:")
                for path in sorted(snapshot.iterdir()):
                    if path.is_file() and path.name.endswith(".json"):
                        print(f"  {path.name}")
                return 0
            ok = await _rollback(client, cfg, snapshot, lines)
            print(f"deploy[{cfg.tenant}] rollback from {snapshot}:")
            for line in lines:
                print(f"  {line}")
            if not ok:
                return 1
            smoke = await _smoke_test(client, cfg, salt, lines)
            for line in lines[-1:]:
                print(f"  {line}")
            return 0 if smoke else 1

        # --- preflight (fail-fast, before any write) ---
        problems: list[str] = []
        drift = check_artifacts(cfg, retention_days=retention_days)
        if drift:
            problems.append(
                "generated artifacts drifted from fields.yaml — run "
                "`klaxon masking generate --tenant <tenant>` first:"
            )
            problems.extend(f"  {d}" for d in drift)
        deployed = await _get_deployed_pipeline(client, cfg)
        if deployed is not None:
            ok_salt, _msg = check_deployed_salt(deployed, salt)
            if not ok_salt:
                problems.append(
                    "SALT MISMATCH: the currently deployed pipeline was baked "
                    "with a different salt than the current env salt. Tokens "
                    "already written to the masked stream would no longer match "
                    "a fresh deploy. Re-deploy with the same "
                    "KLAXON_ANONYMIZATION_SALT."
                )
        if not force and await _sync_recently_active(client, cfg):
            problems.append(
                "a sync job appears to be running/very recent (checkpoint "
                f"updated within {SYNC_RUNNING_WINDOW_SECONDS}s) — aborting. "
                "Wait for the sync to finish or pass --force."
            )
        selftest = run_generator_selftest(cfg, salt)
        if selftest:
            problems.append("generator self-test FAILED — the pipeline to deploy "
                            "is not byte-identical to derive_token:")
            problems.extend(f"  {p}" for p in selftest)

        if problems:
            print(f"deploy[{cfg.tenant}] PREFLIGHT FAILED — nothing deployed:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
            return 1

        # Build the deploy plan (roles from the fragment; mappings are fetched
        # inside _deploy_core and only needed for a real deploy).
        roles, _mappings_cfg = _parse_roles_fragment(cfg)
        plan = _deploy_plan(cfg, roles)

        if dry_run:
            print(f"deploy[{cfg.tenant}] dry run — would deploy (no writes):")
            for item in plan:
                print(f"  {item}")
            print("  smoke test: _simulate user.name + free-text uid= share one token")
            return 0

        # Snapshot the current state before overwriting (for --rollback).
        ts_dir = _new_snapshot_dir(cfg)
        await _snapshot_current(client, cfg, ts_dir, lines)

        print(f"deploy[{cfg.tenant}] deploying in order:")
        ok = await _deploy_core(
            client, cfg, salt, retention_days=retention_days, lines=lines
        )
        for line in lines:
            print(f"  {line}")
        if not ok:
            print(f"deploy[{cfg.tenant}] FAILED — a previous snapshot is at {ts_dir} "
                  "(`klaxon masking deploy --rollback`).", file=sys.stderr)
            return 1

        smoke_lines: list[str] = []
        smoke_ok = await _smoke_test(client, cfg, salt, smoke_lines)
        for line in smoke_lines:
            print(f"  {line}")
        if not smoke_ok:
            print(f"deploy[{cfg.tenant}] FAILED at smoke test — snapshot at {ts_dir}.", file=sys.stderr)
            return 1
        print(f"deploy[{cfg.tenant}] ok: all artifacts deployed and verified.")
        return 0


def deploy_main(argv: list[str] | None = None) -> int:
    """Console entry for `klaxon masking deploy`. 0 = ok, 1 = failure, 2 = usage."""
    args = _parse_args(argv)
    try:
        cfg = load_tenant_config(args.tenant, args.root)
    except (FileNotFoundError, ValueError) as exc:
        print(f"deploy[{args.tenant}] error: {exc}", file=sys.stderr)
        return 2

    live, missing = resolve_live_config(args.env)
    if live is None:
        print(
            f"deploy[{args.tenant}] ERROR: indexer credentials not set. "
            f"Missing: {', '.join(missing)}. Set KLAXON_INDEXER_URL, "
            "KLAXON_INDEXER_USER and KLAXON_INDEXER_PASSWORD (or a local .env "
            "file via --env). The password is never logged.",
            file=sys.stderr,
        )
        return 1

    salt_env = cfg.salt_env
    if not os.environ.get(salt_env, "").strip():
        print(
            f"deploy[{args.tenant}] ERROR: {salt_env} is not set. Deploy would "
            "bake a random salt that diverges from the response layer. Set it "
            "to a stable secret (secrets.token_hex(32)).",
            file=sys.stderr,
        )
        return 1
    salt = resolve_salt(salt_env)

    retention_days = args.retention_days or 30
    try:
        return asyncio.run(
            _run(
                live,
                cfg,
                salt,
                retention_days=retention_days,
                dry_run=args.dry_run,
                force=args.force,
                rollback=args.rollback,
            )
        )
    except httpx.TransportError as exc:
        print(
            f"deploy[{args.tenant}] error: indexer unreachable: {exc}",
            file=sys.stderr,
        )
        return 1
