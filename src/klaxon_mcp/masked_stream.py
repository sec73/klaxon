# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Option B: a separate, masked data stream for LLM-safe reporting.

The raw Wazuh streams (`wazuh-events-v5-*`, `wazuh-findings-v5-*`) are never
touched. A periodic sync job reindexes a recent time window from the raw stream
through a generated ingest pipeline into `klaxon-masked-<tenant>-v5-*`, which
carries its own short ISM retention. Report/LLM consumers query only the masked
stream.

The masking field list lives EXACTLY ONCE in `tenants/<tenant>/fields.yaml`.
Everything else — the Klaxon config fragment (`anonymization.mask_fields` +
`gdpr_checker.custom_patterns`) and the ingest pipeline (whose Painless script
is built from the same YAML) — is generated from it. Drift between the two is
detected by CI (`verify-masking-config`), the sync-job preflight, and the
`klaxon verify-config` command.

Security notes (read before deploying):
  * Ingest pipelines cannot read process environment at index time, so the salt
    from `KLAXON_ANONYMIZATION_SALT` is baked into the DEPLOYED pipeline at
    generate/apply time. That places the salt inside the cluster, visible to
    anyone allowed `GET /_ingest/pipeline`. Restrict pipeline read access to
    administrators; do NOT give report/LLM consumers that permission. The
    committed pipeline *template* carries a `__SALT__` placeholder so the secret
    never enters version control.
  * A masking failure never drops a document: the `on_failure` processor sets
    `klaxon.masking_error` and the (unmodified, raw) document is still indexed
    so the failure is visible. Consumers MUST filter on `NOT exists
    klaxon.masking_error`; the sync job and `verify-config` surface any flagged
    documents.
  * `related.hash` is intentionally NOT masked (file hashes are security IOCs,
    not personal data). The pipeline table never contains it.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
from importlib import metadata
from typing import Any

from . import __version__ as _package_version
from .painless import (
    _FREETEXT_PATTERN_ORDER as _FREETEXT_PATTERN_ORDER,  # noqa: PLC0414 — facade re-export
)
from .painless import (
    _MASK_FAMILY,
    _PATTERNS,
    _active_free_text_patterns,
    _painless_script,
)
from .tenants import (
    FieldSpec,
    TenantConfig,
    build_config_fragment,
    fields_yaml_sha256,
    find_repo_root,
    find_tenant_dir,
    load_tenant_config,
)
from .tokens import (
    TOKEN_RE as TOKEN_RE,  # noqa: PLC0414 — masked_stream facade re-export
)
from .tokens import (
    derive_token as derive_token,  # noqa: PLC0414 — masked_stream facade re-export
)
from .tokens import (
    token as token,  # noqa: PLC0414 — used here and re-exported
)

logger = logging.getLogger("klaxon_mcp.masked_stream")

# Explicit re-export for mypy strict: names other modules and tests import from
# klaxon_mcp.masked_stream.
__all__ = [
    "DEFAULT_INITIAL_LOOKBACK_HOURS",
    "DEFAULT_OVERLAP_HOURS",
    "DEFAULT_RETENTION_DAYS",
    "TEMPLATE_PRIORITY",
    "TOKEN_RE",
    "_FREETEXT_PATTERN_ORDER",
    "FieldSpec",
    "TenantConfig",
    "build_config_fragment",
    "build_deployable_pipeline",
    "build_index_template",
    "build_ism_policy",
    "build_pipeline",
    "build_pipeline_template",
    "deploy_pipeline",
    "derive_token",
    "effective_mask_fields_from_config",
    "fields_yaml_sha256",
    "find_repo_root",
    "find_tenant_dir",
    "fingerprint_matches",
    "generator_version",
    "load_tenant_config",
    "pipeline_field_names",
    "pipeline_mask_doc",
    "pipeline_provenance",
    "resolve_salt",
    "token",
]

# --------------------------------------------------------------------------- #
# Constants (retention/rollover are easy to change here)
# --------------------------------------------------------------------------- #

DEFAULT_RETENTION_DAYS = 30
HOT_ROLLOVER_MIN_SIZE = "50gb"
HOT_ROLLOVER_MIN_AGE = "1d"
TEMPLATE_PRIORITY = 200
ISM_PRIORITY = 100
DEFAULT_OVERLAP_HOURS = 1
DEFAULT_INITIAL_LOOKBACK_HOURS = 24

# OpenSearch ingest pipelines REJECT `_meta` in the PUT body (HTTP 400
# parse_exception: "doesn't support one or more provided configuration
# parameters [_meta]"). Provenance therefore rides in the DEPLOYABLE pipeline's
# `description` after this marker; the committed template keeps `_meta` for CI
# drift. `pipeline_provenance()` reads either form.
PROVENANCE_DESCRIPTION_MARKER = "\nklaxon-provenance: "

_COMMON_WORDS = frozenset(
    {
        "user", "data", "root", "host", "server", "system", "login",
        "account", "group", "name", "id", "admin", "agent", "manager",
        "index", "log", "level", "rule", "event", "file", "process",
        "network", "service", "session", "message", "value", "time",
        "type", "status", "error", "info", "warning", "debug", "trace",
        "audit", "policy", "role", "result", "total", "size", "count",
        "default", "custom",
    }
)


def generator_version() -> str:
    """The Klaxon package version stamped into generated artifacts' provenance.

    Uses the installed distribution version (authoritative after `pip install .`),
    falling back to the module `__version__` when the package is not installed
    (e.g. bare test collection).
    """
    try:
        return metadata.version("klaxon-mcp")
    except metadata.PackageNotFoundError:
        return _package_version


def resolve_salt(salt_env: str = "KLAXON_ANONYMIZATION_SALT") -> str:
    """The per-tenant salt from the environment, or a generated one (warned).

    The salt is what makes pipeline tokens non-reversible. It is baked into the
    deployed pipeline at apply time (ingest pipelines cannot read process env);
    see the module docstring for the RBAC requirement this implies. A generated
    salt is random per run, so tokens will rotate — set the env var for a stable
    salt across deploys and sync runs.
    """
    raw = os.environ.get(salt_env)
    if raw and raw.strip():
        return raw.strip()
    generated = secrets.token_hex(32)
    logger.warning(
        "%s is not set. A random salt was generated for the masking pipeline; "
        "tokens will rotate on every generate/apply run, so previously written "
        "masked documents will no longer correlate. Set %s to a stable secret.",
        salt_env,
        salt_env,
    )
    return generated


# Ingest pipeline (Painless) — the emitter and pattern table live in
# painless.py; this module builds the pipeline JSON around `_painless_script`.


def build_pipeline(cfg: TenantConfig, salt: str) -> dict[str, Any]:
    """The `PUT /_ingest/pipeline/klaxon-mask-<tenant>` body.

    The salt is carried as the script processor's `params.salt` (ingest
    pipelines cannot read process env, so the deployable pipeline embeds the
    real salt there; the committed template uses `__SALT__` so the secret never
    enters git). `_meta` carries the provenance fingerprint (source path, sha256
    of fields.yaml, tenant, generator version) plus the field table, which is
    what drift checks (`verify-config`, sync preflight, salt-check) compare.

    OpenSearch rejects `_meta` in ingest pipelines, so the body actually PUT to
    the indexer is `build_deployable_pipeline()` — same logic, provenance moved
    into `description`. `_meta` here is the committed/template form used for CI
    drift.
    """
    sha = fields_yaml_sha256(cfg)
    return {
        "description": (
            f"Mask personal data into {cfg.masked_stream_pattern} (generated "
            f"from {cfg.source_rel})."
        ),
        "version": 1,
        "processors": [
            {
                "script": {
                    "lang": "painless",
                    "source": _painless_script(cfg),
                    "params": {"salt": salt},
                    "on_failure": [
                        {
                            "set": {
                                "field": "klaxon.masking_error",
                                "value": "{{ _ingest.on_failure_message }}",
                            }
                        }
                    ],
                }
            }
        ],
        "_meta": {
            "source": cfg.source_rel,
            "sha256": sha,
            "tenant": cfg.tenant,
            "generator_version": generator_version(),
            "generated_by": "klaxon masking generate",
            "fields": list(cfg.all_masked_fields),
            "free_text_fields": list(cfg.free_text_fields),
        },
    }


def build_pipeline_template(cfg: TenantConfig) -> dict[str, Any]:
    """The committed, salt-free pipeline template (CI-diffable, secret-free)."""
    return build_pipeline(cfg, "__SALT__")


def build_deployable_pipeline(cfg: TenantConfig, salt: str) -> dict[str, Any]:
    """The pipeline body PUT to OpenSearch: real salt, NO `_meta`.

    OpenSearch rejects `_meta` in ingest pipelines (HTTP 400 parse_exception), so
    the provenance that `_meta` carries on the committed template is instead
    embedded (JSON) in the `description` field after
    `PROVENANCE_DESCRIPTION_MARKER`. The deployed pipeline stays fingerprintable
    by `fingerprint_matches` / `pipeline_field_names` via `pipeline_provenance()`.
    """
    pipeline = build_pipeline(cfg, salt)
    meta = pipeline.pop("_meta")
    pipeline["description"] = (
        pipeline["description"]
        + PROVENANCE_DESCRIPTION_MARKER
        + json.dumps(meta, sort_keys=True, separators=(",", ":"))
    )
    return pipeline


def deploy_pipeline(cfg: TenantConfig) -> dict[str, Any]:
    """The deployable pipeline with the real salt from the environment."""
    return build_deployable_pipeline(cfg, resolve_salt(cfg.salt_env))


# --------------------------------------------------------------------------- #
# ISM policy + index template
# --------------------------------------------------------------------------- #


def build_ism_policy(cfg: TenantConfig, retention_days: int = DEFAULT_RETENTION_DAYS) -> dict[str, Any]:
    """The ISM policy: hot (rollover) -> delete after `retention_days`."""
    return {
        "policy": {
            "description": (
                f"Short retention for the masked stream {cfg.masked_stream_pattern}."
            ),
            "default_state": "hot",
            "states": [
                {
                    "name": "hot",
                    "actions": [
                        {
                            "rollover": {
                                "min_size": HOT_ROLLOVER_MIN_SIZE,
                                "min_index_age": HOT_ROLLOVER_MIN_AGE,
                            }
                        }
                    ],
                    "transitions": [
                        {
                            "state_name": "delete",
                            "conditions": {"min_index_age": f"{retention_days}d"},
                        }
                    ],
                },
                {"name": "delete", "actions": [{"delete": {}}], "transitions": []},
            ],
            "ism_template": {
                "index_patterns": [cfg.masked_stream_pattern],
                "priority": ISM_PRIORITY,
            },
        }
    }


def build_index_template(
    cfg: TenantConfig, mappings: dict[str, Any] | None = None
) -> dict[str, Any]:
    """The composable index template for the masked data stream.

    `mappings` is the `mappings` object copied from the Wazuh events stream (so
    queries behave identically); when omitted (None — the offline generator
    path), the `mappings` key is not emitted and the operator merges them at
    deploy time (see `--apply-masked-infra`, which fetches them from the
    indexer). Only `klaxon-masked-<tenant>-v5-*` matches — Wazuh streams are
    never touched.

    The ISM policy is attached the OpenSearch-native way: the policy's
    `ism_template` (see `build_ism_policy`) auto-applies it to newly created
    backing indices. `index.lifecycle.name` is intentionally NOT set — it is an
    Elasticsearch ILM setting that OpenSearch rejects (HTTP 400 "expected
    [index.lifecycle.name] to be private but it was not").
    """
    template: dict[str, Any] = {
        "settings": {
            "index.default_pipeline": cfg.pipeline_name,
            "number_of_shards": 1,
            "number_of_replicas": 1,
        }
    }
    if mappings is not None:
        template["mappings"] = mappings
    return {
        "index_patterns": [cfg.masked_stream_pattern],
        "priority": TEMPLATE_PRIORITY,
        "template": template,
        "data_stream": {},
    }


# --------------------------------------------------------------------------- #
# Python reference of the pipeline masking (for unit tests)
# --------------------------------------------------------------------------- #


def _compile_patterns() -> dict[str, re.Pattern[str]]:
    return {name: re.compile(source) for name, source in _PATTERNS.items()}


def pipeline_mask_doc(source: dict[str, Any], cfg: TenantConfig, salt: str) -> dict[str, Any]:
    """The Python twin of the Painless pipeline, so its logic is testable here.

    Mirrors `_painless_script` step for step: copy, mask structured fields
    (arrays element-wise, missing fields no-op, idempotent on tokens), then the
    free-text pass (known-identity registry + context patterns + email/IP).
    """
    patterns = _compile_patterns()
    masked = dict(source)

    def tok(family: str, value: str) -> str:
        return token(family, value, salt)

    # Structured fields.
    for spec in cfg.fields:
        if spec.field not in masked:
            continue
        v = masked[spec.field]
        if spec.array:
            if isinstance(v, list):
                masked[spec.field] = [
                    tok(spec.family, item) if isinstance(item, str) else item
                    for item in v
                ]
        elif isinstance(v, str):
            masked[spec.field] = tok(spec.family, v)

    # Free-text pass.
    def mask_re(text: str, name: str, family: str) -> str:
        if not text:
            return text
        pattern = patterns[name]

        def repl(m: re.Match[str]) -> str:
            return tok(family, m.group(1) if m.lastindex and m.group(1) is not None else m.group(0))

        return pattern.sub(repl, text)

    for field in cfg.free_text_fields:
        value = masked.get(field)
        if not isinstance(value, str):
            continue
        out = value
        # Known identities first (per-document USER registry, word-boundary).
        # The registry reads the RAW original source, not the already-tokenised
        # `masked` map — exactly like the Painless maskRegistry(out, source).
        for spec in cfg.fields:
            if spec.family != "USER" or spec.field not in source:
                continue
            raw_values = source[spec.field]
            if not isinstance(raw_values, list):
                raw_values = [raw_values] if isinstance(raw_values, str) else []
            for raw in raw_values:
                if not isinstance(raw, str) or len(raw) < 2:
                    continue
                replacement = tok("USER", raw)
                if replacement == raw:
                    continue
                out = re.sub(
                    rf"(?<!\w){re.escape(raw)}(?!\w)", replacement, out
                )
        for name in _active_free_text_patterns(cfg):
            out = mask_re(out, name, _MASK_FAMILY[name])
        masked[field] = out

    return masked


def pipeline_provenance(pipeline: dict[str, Any]) -> dict[str, Any]:
    """The provenance metadata of a pipeline, from `_meta` or `description`.

    The committed template carries `_meta`; the deployed pipeline (OpenSearch
    rejects `_meta`) carries the same data JSON-encoded in `description` after
    `PROVENANCE_DESCRIPTION_MARKER`. Returns `{}` when neither is readable.
    """
    meta = pipeline.get("_meta")
    if isinstance(meta, dict):
        return meta
    description = pipeline.get("description")
    if isinstance(description, str) and PROVENANCE_DESCRIPTION_MARKER in description:
        _, _, blob = description.partition(PROVENANCE_DESCRIPTION_MARKER)
        try:
            parsed = json.loads(blob)
        except (TypeError, ValueError):
            return {}
        if isinstance(parsed, dict):
            return parsed
    return {}


def pipeline_field_names(pipeline: dict[str, Any]) -> tuple[str, ...]:
    """The effective field list a pipeline masks, from its provenance."""
    meta = pipeline_provenance(pipeline)
    fields = meta.get("fields") or []
    free_text = meta.get("free_text_fields") or []
    return tuple(str(f) for f in (*fields, *free_text))


def effective_mask_fields_from_config(cfg: TenantConfig) -> tuple[str, ...]:
    """What the Klaxon config MUST mask for this tenant (field + free text)."""
    return tuple((*cfg.all_masked_fields, *cfg.free_text_fields))


def fingerprint_matches(pipeline: dict[str, Any], cfg: TenantConfig) -> bool:
    """Whether a deployed pipeline was generated from the current fields.yaml."""
    meta = pipeline_provenance(pipeline)
    return (
        meta.get("sha256") == fields_yaml_sha256(cfg)
        and set(pipeline_field_names(pipeline)) == set(effective_mask_fields_from_config(cfg))
    )
