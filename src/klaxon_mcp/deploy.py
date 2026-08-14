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
    1. pipeline            PUT /_ingest/pipeline/klaxon-mask-<tenant> (skipped
                           when already identical)
    2. ISM policies (both) GET-first compare/skip; versioned PUT
                           (?if_seq_no&if_primary_term, one 409 retry)
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
import re
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

# Keys the ISM plugin adds when it stores/re-serves a policy: a GET body carries
# them, the PUT body never does. Dropped before any fingerprint comparison so
# "identical" means the deployable policy CONTENT matches on a live cluster —
# otherwise a re-run could neither skip nor verify an ISM policy.
_ISM_SERVER_KEYS = frozenset(
    {"policy_id", "last_updated_time", "schema_version", "error_notification"}
)

# Sentinel: a key is NOT in ISM_SERVER_DEFAULTS (distinct from a default whose
# value happens to be None).
_UNSET = object()

# Sentinel marking an ISM_SERVER_DEFAULTS entry as pure metadata: its value is
# never meaningful and is never compared.
_ISM_METADATA = object()

# Known OpenSearch ISM server defaults & metadata the plugin adds when the PUT
# body omitted them. These are OpenSearch ISM behaviors, NOT Klaxon's — a
# re-served policy carries them, so the deploy verify must not report them as
# drift. An explicit value in the sent body is always respected (never
# clobbered): a key is only dropped from the DEPLOYED side when it is ABSENT in
# the sent side AND (for defaults) the deployed value equals the default. Pure
# metadata (`last_updated_time`) is never compared anywhere. THIS is the single
# place to add future ISM defaults.
ISM_SERVER_DEFAULTS: dict[str, Any] = {
    # Default `retry` ISM injects into any action that omitted `retry`.
    "retry": {"count": 3, "backoff": "exponential", "delay": "1m"},
    # Default `copy_alias` ISM injects into a rollover action that omitted it.
    "copy_alias": False,
    # Metadata timestamp ISM injects into every `ism_template[]` entry; its
    # value changes on every update and is never part of a meaningful diff.
    "last_updated_time": _ISM_METADATA,
}

# Pure-metadata keys: their values are never meaningful and are always ignored.
# Derived from ISM_SERVER_DEFAULTS so that constant stays the single source.
_ISM_METADATA_KEYS: frozenset[str] = frozenset(
    key for key, value in ISM_SERVER_DEFAULTS.items() if value is _ISM_METADATA
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


def _normalized_for_compare(kind: str, obj: Any) -> Any:
    """Normalize a resource body for the fingerprint comparison.

    Drops the OpenSearch wrapper keys around a served resource plus per-kind
    server-managed fields (the ISM plugin's policy_id / last_updated_time /
    schema_version / error_notification) that a GET returns but a PUT body
    never carries.
    """
    obj = _drop_wrapper_keys(obj)
    if kind == "ism" and isinstance(obj, dict):
        return {k: v for k, v in obj.items() if k not in _ISM_SERVER_KEYS}
    return obj


def _fingerprint_for(kind: str, obj: Any) -> str:
    """Fingerprint a normalized body for the comparison.

    ISM durations are canonicalized first (`_normalize_ism_durations`) because
    the indexer may re-serve an equal duration in another unit (e.g. `30d` as
    `43200m`); every other kind is hashed exactly as normalized, so the pipeline
    and template verify path is unchanged.
    """
    if kind == "ism":
        obj = _normalize_ism_durations(obj)
    return _fingerprint(obj)


# ISM duration fields the plugin may re-serve in a different-but-equal form
# (e.g. "30d" vs "43200m"). Canonicalized to total seconds on BOTH sides of the
# fingerprint compare; genuinely different durations still differ. Size fields
# (`min_size`) and counts are deliberately NOT touched.
_ISM_DURATION_FIELDS = frozenset({"min_index_age", "min_rollover_age"})

_DURATION_UNIT_SECONDS = {
    "ms": 0.001,
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "w": 604800,
    "M": 2_592_000,
    "y": 31_536_000,
}

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([a-zA-Z]+)\s*$")


def _canonical_duration(value: Any) -> Any:
    """A duration string in canonical seconds, or the value unchanged when it is
    not a parseable ISM duration (sizes like `50gb` and plain numbers are left
    alone)."""
    if not isinstance(value, str):
        return value
    match = _DURATION_RE.match(value)
    if not match:
        return value
    seconds = _DURATION_UNIT_SECONDS.get(match.group(2).lower())
    if seconds is None:
        return value
    try:
        number = float(match.group(1))
    except ValueError:
        return value
    return number * seconds


def _normalize_ism_durations(obj: Any) -> Any:
    """Recursively canonicalize ISM duration fields so a policy the indexer
    re-served in an equivalent unit still fingerprints equal to what was sent."""
    if isinstance(obj, dict):
        return {
            key: (
                _canonical_duration(value)
                if key in _ISM_DURATION_FIELDS
                else _normalize_ism_durations(value)
            )
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [_normalize_ism_durations(value) for value in obj]
    return obj


def _normalize_ism_server_defaults(sent: Any, deployed: Any) -> tuple[Any, Any]:
    """Drop known ISM server defaults/metadata from a sent/deployed policy pair.

    OpenSearch ISM re-serves a policy with resolved defaults and metadata that
    the PUT body omitted (see `ISM_SERVER_DEFAULTS`) — these are ISM behaviors,
    not drift. Three steps, applied to the (already envelope-extracted +
    canonicalized) pair:

      1. `_strip_ism_metadata` — pure metadata (`last_updated_time`) is never
         compared, wherever ISM injected it, on BOTH sides and in every branch;
      2. `_canonicalize_ism_template` — ISM stores `ism_template` as a LIST of
         entries while the artifact uses a single dict; canonicalize both sides
         to the list form;
      3. `_drop_ism_server_defaults` — a default-valued key (`retry`,
         `copy_alias`) that is ABSENT in `sent` but present on the deployed
         side with the known default is dropped, so both sides compare equal.

    An explicit value in `sent` is never touched, so genuine drift still fails
    with a precise field path.
    """
    return _drop_ism_server_defaults(
        _canonicalize_ism_template(_strip_ism_metadata(sent)),
        _canonicalize_ism_template(_strip_ism_metadata(deployed)),
    )


def _strip_ism_metadata(obj: Any) -> Any:
    """Recursively remove pure-metadata keys (`last_updated_time`). Their values
    change on every update and are never part of a meaningful diff, wherever the
    plugin injected them."""
    if isinstance(obj, dict):
        return {
            key: _strip_ism_metadata(value)
            for key, value in obj.items()
            if key not in _ISM_METADATA_KEYS
        }
    if isinstance(obj, list):
        return [_strip_ism_metadata(value) for value in obj]
    return obj


def _canonicalize_ism_template(obj: Any) -> Any:
    """OpenSearch ISM stores `ism_template` as a LIST of entries; the Klaxon
    artifact carries a single dict. Canonicalize both forms to the list form so
    a re-served policy compares equal (an ISM storage behavior, not drift)."""
    if isinstance(obj, dict) and "ism_template" in obj:
        current = obj["ism_template"]
        if isinstance(current, dict):
            entries: list[dict[Any, Any]] = [dict(current)]
        elif isinstance(current, list):
            entries = [
                dict(entry) for entry in current if isinstance(entry, dict)
            ]
        else:
            return obj
        return {**obj, "ism_template": entries}
    return obj


def _drop_ism_server_defaults(sent: Any, deployed: Any) -> tuple[Any, Any]:
    """Pairwise: drop a deployed default when `sent` omitted the key. Metadata
    and the `ism_template` shape are handled upstream (`_strip_ism_metadata` /
    `_canonicalize_ism_template`)."""
    if isinstance(sent, dict) and isinstance(deployed, dict):
        sent_norm = dict(sent)
        deployed_norm = dict(deployed)
        for key in set(sent_norm) | set(deployed_norm):
            default = ISM_SERVER_DEFAULTS.get(key, _UNSET)
            if default is _UNSET or default is _ISM_METADATA:
                continue
            if key not in sent_norm and deployed_norm.get(key) == default:
                # Sent omitted the key and ISM injected its default -> not drift.
                del deployed_norm[key]
        for key in set(sent_norm) & set(deployed_norm):
            sent_norm[key], deployed_norm[key] = _drop_ism_server_defaults(
                sent_norm[key], deployed_norm[key]
            )
        return sent_norm, deployed_norm
    if isinstance(sent, list) and isinstance(deployed, list):
        sent_items = list(sent)
        deployed_items = list(deployed)
        for index in range(min(len(sent_items), len(deployed_items))):
            sent_items[index], deployed_items[index] = _drop_ism_server_defaults(
                sent_items[index], deployed_items[index]
            )
        return sent_items, deployed_items
    return sent, deployed


def _json_diff(a: Any, b: Any, path: str = "$") -> list[str]:
    """Human-readable field-level differences between two JSON-ish values.

    Each entry is a JSON path (e.g. `$.states[0].transitions[0].conditions.
    min_index_age`) plus the sent vs deployed values, so a genuine drift is
    diagnosable instead of a bare "fingerprint differs".
    """
    if isinstance(a, dict) and isinstance(b, dict):
        diffs: list[str] = []
        for key in sorted(set(a) | set(b)):
            child = f"{path}.{key}"
            if key not in a:
                diffs.append(f"{child}: absent in sent, deployed={b[key]!r}")
            elif key not in b:
                diffs.append(f"{child}: absent in deployed, sent={a[key]!r}")
            else:
                diffs.extend(_json_diff(a[key], b[key], child))
        return diffs
    if isinstance(a, list) and isinstance(b, list):
        diffs = []
        if len(a) != len(b):
            diffs.append(f"{path}: length {len(a)} != {len(b)}")
        for index, (left, right) in enumerate(zip(a, b)):
            diffs.extend(_json_diff(left, right, f"{path}[{index}]"))
        return diffs
    if a != b:
        return [f"{path}: {a!r} != {b!r}"]
    return []


def _ism_policy_from_envelope(parsed: Any) -> dict[str, Any] | None:
    """The ACTUAL ISM policy from a GET response envelope, or None.

    The ISM plugin does not return the policy flat. The response carries the
    version metadata (`_id`, `_version`, `_seq_no`, `_primary_term`) next to a
    `policy` key that itself wraps the stored document under ANOTHER `policy`
    key (the shape observed on the live cluster that broke the verify):

        {"_id": ..., "_version": ..., "_seq_no": ...,
         "policy": {
             "policy_id": ..., "last_updated_time": ..., "schema_version": ...,
             "policy": {"description": ..., "states": [...]}
         }}

    Older OpenSearch versions / test doubles return the single-nested shape
    (`"policy": {"description": ...}`), so both are accepted — the innermost
    policy dict is always what the fingerprint must compare.
    """
    if not isinstance(parsed, dict):
        return None
    outer = parsed.get("policy")
    if not isinstance(outer, dict):
        return None
    nested = outer.get("policy")
    if isinstance(nested, dict):
        return nested
    return outer


def _extract_resource(kind: str, path: str, parsed: Any) -> dict[str, Any] | None:
    """The resource body from a GET response, per resource kind."""
    if not isinstance(parsed, dict):
        return None
    if kind == "pipeline":
        name = path.rsplit("/", 1)[1]
        body = parsed.get(name)
        return body if isinstance(body, dict) else None
    if kind == "ism":
        return _ism_policy_from_envelope(parsed)
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


async def _verify_after_put(
    client: httpx.AsyncClient,
    label: str,
    path: str,
    body: Any,
    *,
    kind: str,
    lines: list[str],
) -> bool:
    """GET the resource back and assert the deployed content matches what was sent."""
    sent = _normalized_for_compare(kind, _sent_resource(kind, body))
    received = await _get_resource(client, kind, path)
    if received is None:
        lines.append(f"[fail] {label}: PUT ok but GET back failed/empty — verify")
        return False
    received_norm = _normalized_for_compare(kind, received)
    if kind == "ism":
        sent, received_norm = _normalize_ism_server_defaults(sent, received_norm)
    if _fingerprint_for(kind, received_norm) != _fingerprint_for(kind, sent):
        lines.append(
            f"[fail] {label}: deployed resource does not match what was sent "
            "(verify) — fingerprint differs"
        )
        for diff_line in _json_diff(sent, received_norm)[:10]:
            lines.append(f"  {diff_line}")
        return False
    lines.append(f"[ok] {label} (verified)")
    return True


async def _put_verified(
    client: httpx.AsyncClient,
    label: str,
    path: str,
    body: Any,
    *,
    kind: str,
    lines: list[str],
    skip_if_identical: bool = False,
) -> bool:
    """PUT a resource, then GET it back and assert the fingerprint matches.

    With `skip_if_identical=True` the current resource is GET first and the PUT
    is skipped (idempotent no-op) when it already matches the artifact.
    Appends an `[ok]`/`[skip]`/`[fail]` line. Returns success.
    """
    if skip_if_identical:
        existing = await _get_resource(client, kind, path)
        if existing is not None and _fingerprint_for(
            kind, _normalized_for_compare(kind, existing)
        ) == _fingerprint_for(
            kind, _normalized_for_compare(kind, _sent_resource(kind, body))
        ):
            lines.append(f"[skip] {label} unchanged")
            return True
    resp = await client.put(path, content=json.dumps(body))
    if not resp.is_success:
        lines.append(
            f"[fail] {label}: PUT returned HTTP {resp.status_code} — {_error_detail(resp)}"
        )
        return False
    return await _verify_after_put(client, label, path, body, kind=kind, lines=lines)


async def _get_ism_policy(
    client: httpx.AsyncClient, path: str
) -> tuple[dict[str, Any] | None, int | None, int | None]:
    """GET an ISM policy: (policy body, seq_no, primary_term).

    `(None, None, None)` when the policy is absent (404) or not a readable
    policy. `seq_no`/`primary_term` come from the SAME response as the body, so
    the shared ISM write path reuses one GET for both the compare and the
    versioned update (no second request).
    """
    resp = await client.get(path)
    if resp.status_code == 404 or not resp.is_success:
        return None, None, None
    try:
        parsed = resp.json()
    except ValueError:
        return None, None, None
    if not isinstance(parsed, dict):
        return None, None, None
    body = _ism_policy_from_envelope(parsed)
    if body is None:
        return None, None, None
    seq_no = parsed.get("_seq_no")
    primary_term = parsed.get("_primary_term")
    return body, seq_no, primary_term


async def _put_ism_policy(
    client: httpx.AsyncClient,
    label: str,
    path: str,
    body: dict[str, Any],
    *,
    lines: list[str],
) -> bool:
    """Deploy an ISM policy with optimistic concurrency (no 409 on re-deploy).

    THE shared ISM write path — used by BOTH `deploy` and `--rollback`, for the
    masked AND quarantine policies. It replaces the duplicated plain-PUT in the
    rollback path, which died with HTTP 409 "version conflict, document already
    exists" whenever it touched an existing ISM policy.

    ISM policies are versioned documents: updating an existing policy requires
    `?if_seq_no=<seq>&if_primary_term=<term>` taken from a FRESH GET; a plain
    PUT on an existing policy returns HTTP 409. So, unlike the other resources:

      1. GET the policy first (fresh, inside this helper; ONE GET reused) —
         404 -> plain PUT (create);
      2. 200 -> compare the deployed policy (server-managed fields ignored)
         with the artifact: identical -> `[skip] {label} unchanged` (no write
         at all — makes a re-deploy / a repeat rollback a no-op); different ->
         PUT with the GET's seq/term (versioned update);
      3. a 409 (a concurrent change landed between GET and PUT) is retried once
         with a fresh GET + PUT (a stale seq is NEVER reused); a second 409
         fails with a clear message;
      4. every PUT is verified with a GET-back fingerprint check.
    """
    sent = _sent_resource("ism", body)
    for attempt in (1, 2):
        existing, seq_no, primary_term = await _get_ism_policy(client, path)
        if existing is None:
            # Missing -> create with a plain PUT (no version params).
            resp = await client.put(path, content=json.dumps(body))
            if not resp.is_success:
                lines.append(
                    f"[fail] {label}: PUT returned HTTP {resp.status_code} — "
                    f"{_error_detail(resp)}"
                )
                return False
            return await _verify_after_put(
                client, label, path, body, kind="ism", lines=lines
            )
        sent_norm, existing_norm = _normalize_ism_server_defaults(
            _normalized_for_compare("ism", sent),
            _normalized_for_compare("ism", existing),
        )
        if _fingerprint_for("ism", existing_norm) == _fingerprint_for(
            "ism", sent_norm
        ):
            lines.append(f"[skip] {label} unchanged")
            return True
        # Existing but different -> update with optimistic concurrency.
        if seq_no is None or primary_term is None:
            lines.append(
                f"[fail] {label}: existing policy GET carried no seq_no/"
                "primary_term — cannot issue a versioned update"
            )
            return False
        params: dict[str, Any] = {
            "if_seq_no": seq_no,
            "if_primary_term": primary_term,
        }
        resp = await client.put(path, params=params, content=json.dumps(body))
        if resp.status_code == 409:
            if attempt == 1:
                lines.append(
                    f"[retry] {label}: version conflict (HTTP 409) — re-reading "
                    "the policy and retrying once"
                )
                continue
            lines.append(
                f"[fail] {label}: version conflict (HTTP 409) persisted after "
                "one retry — the policy changed concurrently between GET and "
                "PUT; re-run the deploy"
            )
            return False
        if not resp.is_success:
            lines.append(
                f"[fail] {label}: PUT returned HTTP {resp.status_code} — "
                f"{_error_detail(resp)}"
            )
            return False
        return await _verify_after_put(
            client, label, path, body, kind="ism", lines=lines
        )
    return False  # pragma: no cover


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

    # 1. Pipeline (GET-first compare: re-deploying an identical pipeline is a no-op).
    if not await _put_verified(
        client,
        f"pipeline {cfg.pipeline_name}",
        f"/_ingest/pipeline/{cfg.pipeline_name}",
        pipeline,
        kind="pipeline",
        lines=lines,
        skip_if_identical=True,
    ):
        return False
    # 2. ISM policies (both) — versioned documents: GET-first compare/skip,
    #    versioned update (if_seq_no/if_primary_term), one 409 retry.
    if not await _put_ism_policy(
        client,
        f"ISM {cfg.ism_policy_name}",
        f"/_plugins/_ism/policies/{cfg.ism_policy_name}",
        ism,
        lines=lines,
    ):
        return False
    if not await _put_ism_policy(
        client,
        f"ISM {cfg.quarantine_ism_policy_name}",
        f"/_plugins/_ism/policies/{cfg.quarantine_ism_policy_name}",
        quarantine_ism,
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
        # ISM policies are versioned documents — the shared _put_ism_policy
        # helper GET-first-compares/skips and issues a versioned PUT (plain PUT
        # on an existing policy would 409). Everything else keeps the plain
        # PUT + GET-back verify.
        if kind == "ism":
            ok = await _put_ism_policy(
                client, f"rollback {resource} {name}", target, body, lines=lines
            )
        else:
            ok = await _put_verified(
                client, f"rollback {resource} {name}", target, body, kind=kind, lines=lines
            )
        if not ok:
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
