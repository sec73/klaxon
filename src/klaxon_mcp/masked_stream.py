# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Option B: a separate, masked data stream for LLM-safe reporting.

The raw Wazuh streams (`wazuh-events-v5-*`, `wazuh-findings-v5-*`) are never
touched. A periodic sync job reindexes a recent time window from the raw stream
through a generated ingest pipeline into `klaxon-masked-<tenant>-v5*` (the data
stream is named `klaxon-masked-<tenant>-v5`; the `*` pattern is what queries
and the LLM allowlist use — NOT `...-v5-*`, which matches neither the stream
name nor its backing indices and would silently return 0 documents), which
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
  * A masking failure is FAIL-CLOSED: the `on_failure` processor preserves the
    original destination + failure reason, flags `klaxon.masking_error`, and
    REROUTES the (unmodified, raw) document to the quarantine stream
    `klaxon-quarantine-<tenant>-v5-*` — it never stays in the masked stream
    (verified against OpenSearch 3.6.0: the failure message is exposed via the
    `{{ _ingest.on_failure_message }}` template, not a script variable, so the
    on_failure block captures it with a `set` processor and reroutes in a
    script). The consumer-side `NOT exists klaxon.masking_error` filter is
    defense-in-depth only, not the guarantee. The sync job FAILS any run whose
    window produced a quarantine document (checkpoint not advanced), and
    `verify-config` aborts when the deployed pipeline lacks the quarantine
    routing. See docs/option-b-masked-stream.md.
  * `related.hash` is intentionally NOT masked (file hashes are security IOCs,
    not personal data). The pipeline table never contains it.
"""

from __future__ import annotations

import copy
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
    _FREETEXT_VALUE_TYPES as _FREETEXT_VALUE_TYPES,  # noqa: PLC0414 — facade re-export
)
from .painless import (
    _MASK_FAMILY,
    _PATTERNS,
    _active_username_patterns,
    _painless_script,
    _quarantine_on_failure_processors,
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
from .tokens import token_hex as token_hex  # noqa: PLC0414 — facade re-export
from .tokens import weak_salt

logger = logging.getLogger("klaxon_mcp.masked_stream")

# Explicit re-export for mypy strict: names other modules and tests import from
# klaxon_mcp.masked_stream.
__all__ = [
    "DEFAULT_INITIAL_LOOKBACK_HOURS",
    "DEFAULT_OVERLAP_HOURS",
    "DEFAULT_RETENTION_DAYS",
    "QUARANTINE_RETENTION_DAYS",
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
    "build_quarantine_index_template",
    "build_quarantine_ism_policy",
    "build_roles_fragment",
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
    "pipeline_has_quarantine_on_failure",
    "pipeline_mask_doc",
    "pipeline_provenance",
    "resolve_salt",
    "token",
    "token_hex",
    "weak_salt",
]

# --------------------------------------------------------------------------- #
# Constants (retention/rollover are easy to change here)
# --------------------------------------------------------------------------- #

DEFAULT_RETENTION_DAYS = 30
# The quarantine stream keeps masking-failure documents LONGER than the masked
# stream (forensics): hot -> delete after this many days.
QUARANTINE_RETENTION_DAYS = 90
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
    salt across deploys and sync runs. A configured salt shorter than 32 hex
    chars (16 bytes / 128 bits) is weak for the HMAC key and triggers a warning.
    """
    raw = os.environ.get(salt_env)
    if raw and raw.strip():
        salt = raw.strip()
        if weak_salt(salt):
            logger.warning(
                "%s is set but shorter than 32 hex chars (16 bytes / 128 bits). "
                "The salt is the HMAC key; a weak salt makes enumerable values "
                "(usernames, internal IPs) easy to re-identify by brute force. "
                "Generate one with `python -c \"import secrets; print("
                "secrets.token_hex(32))\"` (256 bits).",
                salt_env,
            )
        return salt
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
                    # FAIL-CLOSED on_failure: a masking-failure document is
                    # rerouted OUT of the masked stream into the quarantine
                    # stream (klaxon-quarantine-<tenant>-v5-raw), preserving the
                    # original destination + failure reason. It NEVER stays in
                    # the masked stream (see _quarantine_on_failure_processors).
                    "on_failure": _quarantine_on_failure_processors(cfg),
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
    indexer). Only `klaxon-masked-<tenant>-v5*` matches — Wazuh streams are
    never touched.

    `index_patterns` is `klaxon-masked-<tenant>-v5*` (NOT `...-v5-*`): OpenSearch
    requires the template to match the DATA STREAM NAME
    (`klaxon-masked-<tenant>-v5`, no trailing dash) to create the stream, and
    the same pattern also covers its `...-v5-000001` backing indices. The SAME
    `...-v5*` pattern is used for queries, the LLM allowlist
    (`masked_streams`), the ISM `ism_template` and the report role — one naming
    scheme end to end, so a config that says `...-v5-*` can never silently match
    nothing. `index.lifecycle.name` is intentionally NOT set — it is an
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
        "index_patterns": [f"{cfg.masked_stream}*"],
        "priority": TEMPLATE_PRIORITY,
        "template": template,
        "data_stream": {},
    }


def build_quarantine_ism_policy(
    cfg: TenantConfig, retention_days: int = QUARANTINE_RETENTION_DAYS
) -> dict[str, Any]:
    """The ISM policy for the quarantine data stream.

    Same shape as the masked stream's policy, but with a LONGER retention
    (default 90 days) — quarantine documents are forensics, kept after the
    masked copies are gone. Attached the OpenSearch-native way via the policy's
    `ism_template`, matching the quarantine backing-index pattern.
    """
    return {
        "policy": {
            "description": (
                f"Longer forensic retention for the quarantine stream "
                f"{cfg.quarantine_stream_pattern} (masking failures)."
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
                "index_patterns": [cfg.quarantine_stream_pattern],
                "priority": ISM_PRIORITY,
            },
        }
    }


def build_quarantine_index_template(
    cfg: TenantConfig, mappings: dict[str, Any] | None = None
) -> dict[str, Any]:
    """The composable index template for the quarantine data stream.

    Deliberately in the `klaxon-quarantine-` namespace (NOT `klaxon-masked-`):
    the pattern `klaxon-quarantine-<tenant>-v5*` can never overlap the LLM
    allowlist `klaxon-masked-<tenant>-v5*`, so an LLM query can never read
    quarantine data through Klaxon.

    The settings carry NO `index.default_pipeline` — quarantine documents must
    NEVER re-enter the masking pipeline (their values are already raw, and
    re-masking could drop the quarantine evidence or re-trigger the failure).
    `mappings` is copied from the Wazuh events stream like the masked stream
    (omitted in the offline generator, merged by `--apply-masked-infra`).
    """
    template: dict[str, Any] = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 1,
            # Intentionally NO index.default_pipeline — see docstring.
        }
    }
    if mappings is not None:
        template["mappings"] = mappings
    return {
        "index_patterns": [f"{cfg.quarantine_stream}*"],
        "priority": TEMPLATE_PRIORITY,
        "template": template,
        "data_stream": {},
    }


def build_roles_fragment(cfg: TenantConfig) -> str:
    """The OpenSearch security-plugin roles fragment for one tenant (YAML).

    Applied by the operator/CI (merge into `roles.yml` or the security API).
    Least privilege per the fail-closed access model:

      * `klaxon_llm_report_<tenant>` — read on the MASKED stream ONLY. It can
        never read the quarantine stream (no `klaxon-quarantine-` pattern).
      * `klaxon_ops_<tenant>` — read on the QUARANTINE stream + the raw
        `wazuh-events-v5-*` (forensics). No LLM mapping.
      * `klaxon_sync_<tenant>` — the sync-job service user: read the raw stream
        (reindex source), write the masked + quarantine streams (reindex dest;
        the quarantine write is what makes the fail-closed on_failure routing
        succeed at the security plugin), and `crud` on the checkpoint index.
        WITHOUT the quarantine write, the security plugin REJECTS the on_failure
        `_index` reroute and the masking-failure document is dropped entirely —
        a useful fail-closed backstop.

    The provenance fingerprint rides in the header comment (the security plugin
    has no `description` field on roles, and `roles.yml` is a file, not JSON).
    """
    llm_role = f"klaxon_llm_report_{cfg.tenant}"
    ops_role = f"klaxon_ops_{cfg.tenant}"
    sync_role = f"klaxon_sync_{cfg.tenant}"
    sha = fields_yaml_sha256(cfg)
    provenance = json.dumps(
        {
            "source": cfg.source_rel,
            "sha256": sha,
            "tenant": cfg.tenant,
            "generator_version": generator_version(),
            "generated_by": "klaxon masking generate",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"""# generated from {cfg.source_rel} (sha256: {sha}) — do not edit by hand.
# klaxon-mask-{cfg.tenant}: OpenSearch security-plugin roles fragment.
# Apply via the security API / merge into roles.yml (operator/CI job).
# klaxon-provenance: {provenance}
#
# Fail-closed access model:
#   * LLM/report role reads ONLY klaxon-masked-{cfg.tenant}-v5* — it can never
#     read the quarantine stream (no klaxon-quarantine- pattern).
#   * Ops/security role reads the quarantine stream + raw wazuh-events-v5-*.
#   * Sync-job service user additionally WRITES the quarantine stream; without
#     that write the security plugin rejects the on_failure reroute and the
#     masking-failure document is dropped (a useful fail-closed backstop).
# Map the sync user to {sync_role} ONLY — never to the LLM/report role.

{llm_role}:
  reserved: false
  hidden: false
  static: false
  cluster_permissions: []
  index_permissions:
    - index_patterns:
        - "{cfg.masked_stream_pattern}"
      allowed_actions:
        - "read"
  tenant_permissions: []

{ops_role}:
  reserved: false
  hidden: false
  static: false
  cluster_permissions: []
  index_permissions:
    - index_patterns:
        - "{cfg.quarantine_stream_pattern}"
        - "{cfg.raw_stream}"
      allowed_actions:
        - "read"
  tenant_permissions: []

{sync_role}:
  reserved: false
  hidden: false
  static: false
  cluster_permissions: []
  index_permissions:
    - index_patterns:
        - "{cfg.masked_stream_pattern}"
        - "{cfg.quarantine_stream_pattern}"
      allowed_actions:
        - "write"
    - index_patterns:
        - "{cfg.raw_stream}"
      allowed_actions:
        - "read"
    - index_patterns:
        - "{cfg.sync_state_index}"
      allowed_actions:
        - "crud"
  tenant_permissions: []
"""


def pipeline_has_quarantine_on_failure(pipeline: dict[str, Any]) -> bool:
    """Whether a deployed pipeline's on_failure does the fail-closed routing.

    The sync-job preflight and `verify-config` abort when a deployed pipeline
    predates the quarantine routing (or was hand-edited to remove it): without
    it, masking failures would stay in the masked stream.
    """
    for proc in pipeline.get("processors") or []:
        if not isinstance(proc, dict):
            continue
        script = proc.get("script")
        if not isinstance(script, dict):
            continue
        on_failure = script.get("on_failure")
        if not isinstance(on_failure, list):
            continue
        for handler in on_failure:
            if not isinstance(handler, dict):
                continue
            handler_script = handler.get("script")
            if not isinstance(handler_script, dict):
                continue
            source = handler_script.get("source")
            if isinstance(source, str) and (
                "original_index" in source
                and "masking_error" in source
                and "_index" in source
                and "quarantine" in source
            ):
                return True
    return False


# --------------------------------------------------------------------------- #
# Python reference of the pipeline masking (for unit tests)
# --------------------------------------------------------------------------- #


def _compile_patterns() -> dict[str, re.Pattern[str]]:
    return {name: re.compile(source) for name, source in _PATTERNS.items()}


def _path_get(doc: dict[str, Any], path: str) -> Any:
    """The value at a dotted path in a doc, or None when any segment is missing.

    Tries the LITERAL dotted key first (some Wazuh docs flatten `user.name`
    into a single top-level key), then navigates the nested `user: {name: ...}`
    form — so both representations of a real event are masked. Mirrors the
    Painless `pathGet`.
    """
    if path in doc:
        return doc[path]
    current: Any = doc
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _path_set(doc: dict[str, Any], path: str, value: Any) -> None:
    """Set the value at a dotted path, creating intermediate maps when absent.

    If the doc already carries the literal dotted key, set it directly;
    otherwise navigate/create the nested maps. Mirrors the Painless `pathPut`.
    """
    if path in doc:
        doc[path] = value
        return
    current = doc
    parts = path.split(".")
    for part in parts[:-1]:
        nxt = current.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            current[part] = nxt
        current = nxt
    current[parts[-1]] = value


def pipeline_mask_doc(source: dict[str, Any], cfg: TenantConfig, salt: str) -> dict[str, Any]:
    """The Python twin of the Painless pipeline, so its logic is testable here.

    Mirrors `_painless_script` step for step: deep-copy, mask structured fields
    at their (possibly NESTED) dotted path (arrays element-wise, missing fields
    no-op, idempotent on tokens), then the free-text pass (known-identity
    registry + context patterns + email/IP). The source is DEEP-copied first so
    nested-path masking never mutates the raw document the free-text registry
    reads; the registry reuses the exact structured token for a raw username in
    prose, wherever the structured field lives.
    """
    patterns = _compile_patterns()
    masked = copy.deepcopy(source)

    def tok(family: str, value: str) -> str:
        return token(family, value, salt)

    # Structured fields.
    for spec in cfg.fields:
        v = _path_get(masked, spec.field)
        if v is None:
            continue
        if spec.array:
            if isinstance(v, list):
                _path_set(
                    masked,
                    spec.field,
                    [
                        tok(spec.family, item) if isinstance(item, str) else item
                        for item in v
                    ],
                )
        elif isinstance(v, str):
            _path_set(masked, spec.field, tok(spec.family, v))

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
        # Value-type passes first (EMAIL/IP), then the registry, then the
        # username context patterns — mirrors the Painless maskFreeText and the
        # response layer: an e-mail whose local part is a structured username
        # masks as a WHOLE e-mail, never split by the registry.
        for name in _FREETEXT_VALUE_TYPES:
            out = mask_re(out, name, _MASK_FAMILY[name])
        # Known identities reuse the exact structured token. The registry reads
        # the RAW original source, not the already-tokenised `masked` map —
        # exactly like the Painless maskRegistry(out, source) — at the
        # structured field's (possibly NESTED) dotted path.
        if cfg.mask_free_text_users:
            for spec in cfg.fields:
                if spec.family != "USER":
                    continue
                raw_values = _path_get(source, spec.field)
                if raw_values is None:
                    continue
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
        for name in _active_username_patterns(cfg):
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
