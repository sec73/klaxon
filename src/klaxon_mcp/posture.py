# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Read-only security/DSGVO posture check: facts + gaps, never a verdict.

This is the deep-check half of the DSGVO posture tool (`klaxon_posture_check`
on the MCP server). It follows the GDPR-checker principle: report only what can
be established, no legal judgment, no pass/fail on overall compliance.

Every check returns one `check: status — fact` line with the source it was
derived from (config field / CLI check / indexer API). Statuses are OK / WARN /
unknown only. The tool is itself callable from chat, so the output MUST NOT
contain PII, tokens, salts, hostnames, usernames, IPs, or sampled values — only
counts, booleans, statuses, index patterns, durations and role names. The salt
is never emitted, not even partially or hashed.

If a check cannot be established (e.g. the indexer is unreachable), it says so
explicitly ("unknown — <reason>") instead of silently skipping or guessing.
"""

from __future__ import annotations

import fnmatch
from datetime import UTC, datetime, timedelta
from typing import Any

import yaml

from .artifact_io import check_artifacts
from .clients import IndexerClient, TransportError
from .config import AnonymizationConfig, Config, quarantine_pattern_overlap
from .masked_stream import (
    DEFAULT_RETENTION_DAYS,
    QUARANTINE_RETENTION_DAYS,
    build_roles_fragment,
)
from .sync_masked import preflight_report
from .tenants import TenantConfig
from .tokens import MIN_SALT_HEX

# The recommended salt length (secrets.token_hex(32) = 64 hex chars = 256 bits).
_RECOMMENDED_SALT_HEX = 64


def _fmt_utc(ts: datetime) -> str:
    return ts.astimezone(UTC).strftime("%H:%M UTC")


def _masking_line(anon: AnonymizationConfig) -> str:
    if not anon.enabled:
        return (
            "masking: WARN — anonymization feature is disabled "
            "(KLAXON_ANONYMIZE_EXTERNAL_LLM=false); no field is masked "
            "(source: config.anonymization.enabled)"
        )
    if not anon.mask_fields:
        return (
            "masking: WARN — anonymization enabled but mask_fields is empty; "
            "no field is masked (source: config.anonymization.mask_fields)"
        )
    return (
        f"masking: OK — {len(anon.mask_fields)} field(s) masked, aggregation "
        f"keys {'on' if anon.mask_aggregation_keys else 'off'}, free-text users "
        f"{'on' if anon.mask_free_text_users else 'off'} "
        "(source: config.anonymization.mask_fields / mask_aggregation_keys / "
        "mask_free_text_users)"
    )


def _gate_line(anon: AnonymizationConfig) -> str:
    if anon.llm_is_local:
        return (
            "response_gate: OK — llm_base_url is loopback (local model), output "
            "is not sent to an external model "
            "(source: config.anonymization.llm_base_url loopback check)"
        )
    if anon.whitelist_enabled:
        return (
            "response_gate: OK — LLM endpoint is not local but the response gate "
            "(residual-PII whitelist) is active "
            "(source: config.anonymization.whitelist_enabled)"
        )
    return (
        "response_gate: WARN — LLM endpoint is NOT loopback (external model) AND "
        "the response gate is inactive — residual personal data is not blocked "
        "(source: config.anonymization.llm_base_url / whitelist_enabled)"
    )


async def _data_stream_names(client: IndexerClient, pattern: str) -> list[str]:
    """The names of data streams matching `pattern` on the indexer."""
    resp = await client.get(f"/_data_stream/{pattern}")
    if not resp.ok:
        return []
    parsed = resp.json()
    if not isinstance(parsed, dict):
        return []
    return [
        str(ds.get("name"))
        for ds in parsed.get("data_streams") or []
        if isinstance(ds, dict) and ds.get("name")
    ]


async def _mode_line(
    client: IndexerClient, cfg: TenantConfig, masked_streams: tuple[str, ...]
) -> str:
    masked_pattern = f"{cfg.masked_stream}*"
    quarantine_pattern = f"{cfg.quarantine_stream}*"
    try:
        masked_live = await _data_stream_names(client, masked_pattern)
        quarantine_live = await _data_stream_names(client, quarantine_pattern)
    except TransportError as exc:
        return (
            f"mode: unknown — indexer not reachable: {exc} "
            f"(source: GET /_data_stream/{masked_pattern})"
        )

    masked_exists = bool(masked_live)
    quarantine_exists = bool(quarantine_live)
    cfg_masked = ", ".join(masked_streams) if masked_streams else "none configured"
    if masked_exists:
        live = ", ".join(masked_live)
        # The DEPLOYED data stream name must be covered by the configured
        # masked_streams allowlist, or Klaxon queries it with a pattern that
        # matches nothing (the divergence this guard exists to catch: stream
        # `klaxon-masked-<tenant>-v5` vs a config of `...-v5-*`).
        covered = any(
            fnmatch.fnmatchcase(name, pattern)
            for name in masked_live
            for pattern in masked_streams
        ) if masked_streams else False
        if not covered:
            status = "WARN"
            fact = (
                f"masked stream present ({live}) but NOT covered by the "
                f"masked_streams config ({cfg_masked}) — Klaxon queries would "
                "match nothing; align the config pattern with the data stream "
                "name"
            )
        else:
            status = "OK"
            fact = f"masked stream present ({live}); masked_streams config: {cfg_masked}"
    else:
        status = "WARN"
        fact = (
            f"response-layer masking only — {cfg.masked_stream_pattern} is not "
            f"present on the indexer (Option B not deployed); masked_streams "
            f"config: {cfg_masked}"
        )
    if quarantine_exists:
        fact += "; quarantine stream present"
    else:
        fact += "; quarantine stream not present (planned, not implemented)"
    return (
        f"mode: {status} — {fact} "
        f"(source: config.anonymization.masked_streams + GET /_data_stream/{masked_pattern})"
    )


async def _get_deployed_pipeline(
    client: IndexerClient, cfg: TenantConfig
) -> tuple[str, Any]:
    """The deployed pipeline, as ("ok", pipeline) / ("not_deployed", None) /
    ("unknown", reason)."""
    try:
        resp = await client.get(f"/_ingest/pipeline/{cfg.pipeline_name}")
    except TransportError as exc:
        return "unknown", str(exc)
    if not resp.ok:
        return "not_deployed", None
    parsed = resp.json()
    if not isinstance(parsed, dict):
        return "not_deployed", None
    return "ok", parsed.get(cfg.pipeline_name)


def _config_fields_drift(cfg: TenantConfig, config: Config) -> list[str]:
    """Effective Klaxon `mask_fields` (env/YAML) vs fields.yaml — single source
    of truth. Reported by the posture check REGARDLESS of whether the Option B
    pipeline is deployed, so an env override drifting from the tenant's
    fields.yaml is never silently masked by the "not deployed" path."""
    problems: list[str] = []
    structured_expected = set(cfg.all_masked_fields)
    klaxon_structured = set(config.anonymization.mask_fields)
    if klaxon_structured != structured_expected:
        problems.append(
            f"effective Klaxon config mask_fields {sorted(klaxon_structured)} "
            f"do not match fields.yaml {sorted(structured_expected)}"
        )
    return problems


async def _pipeline_drift_line(
    client: IndexerClient, cfg: TenantConfig, config: Config
) -> str:
    generated = check_artifacts(cfg)
    if generated:
        return (
            f"pipeline_drift: WARN — generated artifacts drifted from fields.yaml: "
            f"{'; '.join(generated)} (source: check_artifacts)"
        )
    config_drift = _config_fields_drift(cfg, config)
    state, payload = await _get_deployed_pipeline(client, cfg)
    if state == "unknown":
        return (
            f"pipeline_drift: unknown — indexer not reachable: {payload} "
            f"(source: GET /_ingest/pipeline/{cfg.pipeline_name})"
        )
    if state == "not_deployed":
        base = (
            f"pipeline_drift: WARN — pipeline {cfg.pipeline_name} is not deployed "
            f"(Option B not deployed); fingerprint check not applicable "
            f"(source: GET /_ingest/pipeline/{cfg.pipeline_name})"
        )
        if config_drift:
            return base + "; " + "; ".join(config_drift)
        return base
    deployed: dict[str, Any] = payload if isinstance(payload, dict) else {}
    problems = preflight_report(cfg, deployed, config)
    if problems:
        return (
            f"pipeline_drift: WARN — {'; '.join(problems)} "
            "(source: verify-config / preflight_report)"
        )
    return (
        "pipeline_drift: OK — fingerprint matches fields.yaml "
        "(source: verify-config / fingerprint_matches)"
    )


def _salt_strength_line(anon: AnonymizationConfig) -> str:
    salt = anon.salt or ""
    chars = len(salt.strip())
    if chars == 0:
        return (
            "salt_strength: WARN — salt is not configured (random per-process "
            "fallback; tokens are unstable across restarts) "
            "(source: KLAXON_ANONYMIZATION_SALT)"
        )
    bits = chars * 4
    if chars < MIN_SALT_HEX:
        return (
            f"salt_strength: WARN — ~{bits} bits, below the {MIN_SALT_HEX}-hex "
            "weak_salt minimum (source: KLAXON_ANONYMIZATION_SALT / weak_salt)"
        )
    if chars < _RECOMMENDED_SALT_HEX:
        return (
            f"salt_strength: WARN — ~{bits} bits (>= weak_salt minimum but below "
            f"the recommended {_RECOMMENDED_SALT_HEX}-hex / 256-bit length) "
            "(source: KLAXON_ANONYMIZATION_SALT)"
        )
    return (
        "salt_strength: OK — >= 256 bits "
        "(source: KLAXON_ANONYMIZATION_SALT length only; the salt itself is "
        "never emitted)"
    )


async def _quarantine_backlog_line(
    client: IndexerClient, cfg: TenantConfig, hours: int
) -> str:
    since = datetime.now(UTC) - timedelta(hours=hours)
    endpoint = f"/{cfg.quarantine_stream_pattern}/_count"
    try:
        resp = await client.post(
            endpoint,
            body={
                "query": {
                    "range": {"@timestamp": {"gte": since.astimezone(UTC).isoformat(timespec="seconds")}}
                }
            },
        )
    except TransportError as exc:
        return f"quarantine_backlog: unknown — indexer not reachable: {exc} (source: POST {endpoint})"
    if not resp.ok:
        return (
            f"quarantine_backlog: unknown — count failed (HTTP {resp.status_code}) "
            f"(source: POST {endpoint})"
        )
    parsed = resp.json()
    count = parsed.get("count") if isinstance(parsed, dict) else None
    if not isinstance(count, int):
        return (
            f"quarantine_backlog: unknown — count response carries no count "
            f"(source: POST {endpoint})"
        )
    if count == 0:
        return f"quarantine_backlog: OK — 0 docs in the last {hours}h (source: POST {endpoint})"
    return (
        f"quarantine_backlog: WARN — {count} doc(s) since {_fmt_utc(since)} in "
        f"the last {hours}h — investigate cause (source: POST {endpoint})"
    )


def _role_index_patterns(spec: Any) -> list[str]:
    """The index_patterns a roles-fragment role grants (from its YAML spec)."""
    out: list[str] = []
    perms = spec.get("index_permissions") if isinstance(spec, dict) else None
    if isinstance(perms, list):
        for entry in perms:
            if not isinstance(entry, dict):
                continue
            for pat in entry.get("index_patterns") or []:
                if isinstance(pat, str):
                    out.append(pat)
    return out


async def _rbac_line(client: IndexerClient, cfg: TenantConfig) -> str:
    fragment = build_roles_fragment(cfg)
    try:
        expected = yaml.safe_load(fragment)
    except yaml.YAMLError:
        expected = None
    if not isinstance(expected, dict) or not expected:
        return (
            "rbac: unknown — the roles fragment could not be parsed "
            "(source: build_roles_fragment)"
        )
    endpoint = "/_plugins/_security/api/roles"
    try:
        resp = await client.get(endpoint)
    except TransportError as exc:
        return f"rbac: unknown — indexer not reachable: {exc} (source: GET {endpoint})"
    if not resp.ok:
        return (
            f"rbac: unknown — security roles API not reachable (HTTP "
            f"{resp.status_code}); is the OpenSearch security plugin enabled? "
            f"(source: GET {endpoint})"
        )
    parsed = resp.json()
    actual = None
    if isinstance(parsed, dict):
        # OpenSearch Security serves the roles map DIRECTLY as the response
        # object ({role_name: spec, ...}); some proxies/gateways wrap it under a
        # "roles" key. Accept both — a dict whose values are role specs.
        if isinstance(parsed.get("roles"), dict):
            actual = parsed["roles"]
        elif parsed and all(isinstance(v, dict) for v in parsed.values()):
            actual = parsed
    if not isinstance(actual, dict):
        return f"rbac: unknown — roles API response has no roles map (source: GET {endpoint})"

    parts: list[str] = []
    for role_name, spec in expected.items():
        grants = ", ".join(_role_index_patterns(spec)) or "no index_permissions"
        present = "present" if role_name in actual else "missing"
        parts.append(f"{role_name} {present} (grants: {grants})")
    status = "OK" if all(role in actual for role in expected) else "WARN"
    return (
        f"rbac: {status} — {'; '.join(parts)} "
        f"(source: roles-<tenant>.yaml fragment vs GET {endpoint})"
    )


def _retention_line(cfg: TenantConfig) -> str:
    return (
        f"retention: OK — masked {DEFAULT_RETENTION_DAYS}d / quarantine "
        f"{QUARANTINE_RETENTION_DAYS}d "
        "(source: masked_stream.DEFAULT_RETENTION_DAYS / "
        "QUARANTINE_RETENTION_DAYS)"
    )


def _startup_line(anon: AnonymizationConfig) -> str:
    overlaps = [s for s in anon.masked_streams if quarantine_pattern_overlap(s)]
    if overlaps:
        return (
            f"startup_fail_closed: WARN — masked_streams contains a pattern that "
            f"could match the quarantine stream: {', '.join(overlaps)} "
            "(source: config.quarantine_pattern_overlap)"
        )
    return (
        "startup_fail_closed: OK — effective config resolved at startup; no "
        "masked_streams pattern overlaps the quarantine stream "
        "(source: Config.from_env() / config.quarantine_pattern_overlap)"
    )


async def posture_check(
    client: IndexerClient,
    config: Config,
    anon: AnonymizationConfig,
    cfg: TenantConfig,
    *,
    hours: int = 24,
) -> list[str]:
    """Run all nine posture checks and return the fact lines, in order."""
    lines: list[str] = [
        _masking_line(anon),
        _gate_line(anon),
        await _mode_line(client, cfg, anon.masked_streams),
        await _pipeline_drift_line(client, cfg, config),
        _salt_strength_line(anon),
        await _quarantine_backlog_line(client, cfg, hours),
        await _rbac_line(client, cfg),
        _retention_line(cfg),
        _startup_line(anon),
    ]
    return lines
