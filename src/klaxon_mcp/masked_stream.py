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

import hashlib
import json
import logging
import os
import re
import secrets
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

import yaml

from . import __version__ as _package_version
from .validation import validate_tenant

logger = logging.getLogger("klaxon_mcp.masked_stream")

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

# A value already in this shape is a token: never re-mask it (idempotent).
TOKEN_RE = re.compile(r"^\[(?:IP|USER|HOST|AGENT)_[0-9a-f]{16}\]$")

# Field names from fields.yaml flow verbatim into the generated Klaxon config
# fragment (unquoted YAML) and the Painless field table. The charset is what a
# WCS/ECS dotted field name needs — the absence of ':', '#', quotes, whitespace
# and control characters is what keeps the generated YAML well-formed.
_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")

_FAMILIES = frozenset({"IP", "USER", "HOST", "AGENT"})

# Painless regex source strings. These are ALSO compiled by the Python reference
# implementation (`pipeline_mask_doc`) so the pipeline logic is unit-testable
# without a cluster; both must stay in lock-step with the response-layer
# patterns in anonymization.py.
_PATTERNS: dict[str, str] = {
    "EMAIL": r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "IPV6": r"(?i)\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b",
    "IPV4": r"(?i)\b(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}\b",
    "USER_NOUN": r"(?i)\b(?:user|username|user[-_ ]?name|account)\b\s*(?:name)?\s*[:=]\s*(?:\"|'|`)?([\w.@%+=-]{2,64})",
    "USER_AUTH": r"(?i)\b(?:login|logon|sign[- ]?in|authenticat(?:e|ed|ion))\b\s+(?:as|for|by)\s+(?:\buser\b\s+)?([\w.@%+=-]{2,64})\b",
    "UID_EQ": r"(?i)\buid\s*=\s*([^\W\d_][\w.@%+=-]{1,63})\b",
    "FOR_USER": r"(?i)\b(?:for|by)\s+user\s+([\w.@%+=-]{2,64})\b",
    "SSH_PUBKEY": r"(?i)\bAccepted\s+publickey\s+for\s+([\w.@%+=-]{2,64})\b",
    "UID_PAREN": r"(?i)\b(?:by|as|for)\s+([\w.@%+=-]{2,64})\s*\(\s*uid\s*=\s*\d+\s*\)",
}

# Order matters for the free-text pass (value types first, then usernames).
_FREETEXT_PATTERN_ORDER = (
    "EMAIL",
    "IPV6",
    "IPV4",
    "USER_NOUN",
    "USER_AUTH",
    "UID_EQ",
    "FOR_USER",
    "SSH_PUBKEY",
    "UID_PAREN",
)

# Always-on free-text patterns (EMAIL/IP + the two basic username-noun/auth
# context patterns) — mirrors the response layer's `mask_text`, where the
# broader username registry and context patterns are gated on
# `mask_free_text_users` while these always run.
_FREETEXT_ALWAYS_ON = ("EMAIL", "IPV6", "IPV4", "USER_NOUN", "USER_AUTH")


def _active_free_text_patterns(cfg: TenantConfig) -> tuple[str, ...]:
    if cfg.mask_free_text_users:
        return _FREETEXT_PATTERN_ORDER
    return _FREETEXT_ALWAYS_ON

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


# --------------------------------------------------------------------------- #
# Field model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class FieldSpec:
    """One masking field from fields.yaml."""

    field: str
    family: str
    array: bool = False

    def to_painless_row(self) -> list[Any]:
        return [self.field, self.family, self.array]


@dataclass(frozen=True)
class TenantConfig:
    """The single source of truth for one tenant's masking."""

    tenant: str
    salt_env: str
    mask_free_text_users: bool
    fields: tuple[FieldSpec, ...]
    free_text_fields: tuple[str, ...]
    source_path: str

    @property
    def pipeline_name(self) -> str:
        return f"klaxon-mask-{self.tenant}"

    @property
    def ism_policy_name(self) -> str:
        return f"klaxon-masked-retention-{self.tenant}"

    @property
    def index_template_name(self) -> str:
        return f"klaxon-masked-{self.tenant}"

    @property
    def masked_stream(self) -> str:
        return f"klaxon-masked-{self.tenant}-v5"

    @property
    def masked_stream_pattern(self) -> str:
        return f"{self.masked_stream}-*"

    @property
    def raw_stream(self) -> str:
        return "wazuh-events-v5-*"

    @property
    def sync_state_index(self) -> str:
        return "klaxon-sync-state"

    @property
    def sync_state_doc_id(self) -> str:
        return f"klaxon-sync-{self.tenant}"

    @property
    def all_masked_fields(self) -> tuple[str, ...]:
        return tuple(f.field for f in self.fields)

    @property
    def source_rel(self) -> str:
        """Repo-root-relative source path, for committed/portable artifacts."""
        return f"tenants/{self.tenant}/fields.yaml"


def find_repo_root(start: str | Path | None = None) -> Path:
    """Locate the repo root by walking up from `start` (default: cwd) to the
    nearest ancestor that contains a `tenants/` directory (the Option B marker).

    Falls back to `start`/cwd if no ancestor qualifies. The lookup is
    independent of where the package is installed, so it works both from the
    `src/` layout and from a site-packages install (e.g. `pip install .` in
    CI, where `__file__` lives outside the checkout).
    """
    current = Path(start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "tenants").is_dir():
            return candidate
    return current


def find_tenant_dir(tenant: str, root: str | Path | None = None) -> Path:
    """The `tenants/<tenant>` directory (repo root by default).

    The tenant name is validated here — the single choke point before it is
    used as a path component, a resource name and an index-pattern component
    everywhere downstream (`klaxon-mask-<tenant>`, `klaxon-masked-<tenant>-v5-*`,
    sync-state doc id, ...).
    """
    base = Path(root) if root is not None else find_repo_root()
    return base / "tenants" / validate_tenant(tenant)


def _validate_field_name(field: str, path: str) -> None:
    """Reject a field name that could break the generated YAML/Painless output."""
    if not _FIELD_NAME_RE.match(field):
        raise ValueError(
            f"invalid field name {field!r} in {path}: permitted charset is "
            "[A-Za-z0-9_.@-] (dotted ECS-style names, e.g. 'source.ip', "
            "'@timestamp')."
        )


def load_tenant_config(
    tenant: str, root: str | Path | None = None
) -> TenantConfig:
    """Parse and validate `tenants/<tenant>/fields.yaml`."""
    tenant_dir = find_tenant_dir(tenant, root)
    path = tenant_dir / "fields.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"missing masking source of truth: {path}. Create it first."
        )
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    if data.get("tenant") != tenant:
        raise ValueError(
            f"tenants/{tenant}/fields.yaml must declare tenant: {tenant!r}, "
            f"got {data.get('tenant')!r}"
        )
    salt_env = str(data.get("salt_env", "KLAXON_ANONYMIZATION_SALT"))
    mask_free_text_users = bool(data.get("mask_free_text_users", True))

    fields: list[FieldSpec] = []
    seen: set[str] = set()
    for entry in data.get("fields", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("field"), str):
            raise ValueError(f"invalid field entry in {path}: {entry!r}")
        field = entry["field"]
        _validate_field_name(field, str(path))
        if field in seen:
            raise ValueError(f"duplicate field {field!r} in {path}")
        seen.add(field)
        family = str(entry.get("family", "USER")).upper()
        if family not in _FAMILIES:
            raise ValueError(f"field {field!r}: unknown family {family!r}")
        if field == "related.hash":
            # File hashes are security IOCs, not personal data. Hard-refuse.
            raise ValueError(
                f"field {field!r} is intentionally not maskable (IOC); remove it "
                "from fields.yaml."
            )
        fields.append(
            FieldSpec(field=field, family=family, array=bool(entry.get("array", False)))
        )

    free_text_fields: list[str] = []
    for entry in data.get("free_text_fields", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("field"), str):
            raise ValueError(f"invalid free_text_fields entry in {path}: {entry!r}")
        field = entry["field"]
        _validate_field_name(field, str(path))
        if field in seen:
            raise ValueError(f"{field!r} listed as both field and free_text_field")
        free_text_fields.append(field)

    if not fields:
        raise ValueError(f"{path} declares no fields")

    return TenantConfig(
        tenant=tenant,
        salt_env=salt_env,
        mask_free_text_users=mask_free_text_users,
        fields=tuple(fields),
        free_text_fields=tuple(free_text_fields),
        source_path=str(path),
    )


def fields_yaml_sha256(cfg: TenantConfig) -> str:
    """sha256 of the fields.yaml source file (the provenance fingerprint)."""
    digest = hashlib.sha256()
    with open(cfg.source_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Token derivation (the pipeline construction)
# --------------------------------------------------------------------------- #


def token_hex(family: str, value: str, salt: str) -> str:
    """16 hex chars of SHA-256 over `family:value:salt` (the pipeline scheme)."""
    if not value:
        return value
    if TOKEN_RE.fullmatch(value):
        return value  # already a token: idempotent, never re-mask
    digest = hashlib.sha256(f"{family}:{value}:{salt}".encode("utf-8")).hexdigest()
    return digest[:16]


def token(family: str, value: str, salt: str) -> str:
    """The display token `[FAMILY_<16 hex>]` used by the masked stream."""
    if not value:
        return value
    if TOKEN_RE.fullmatch(value):
        return value
    return f"[{family}_{token_hex(family, value, salt)}]"


def derive_token(value: str, family: str, salt: str) -> str:
    """The single token-derivation entry point: `derive_token(value, family, salt)`.

    `token()` is the implementation (SHA-256 over `family:value:salt`, first 16
    hex chars, displayed as `[FAMILY_<16 hex>]`, idempotent on existing tokens).
    `derive_token` is the name the token-schema self-test and the docs use for
    the pipeline scheme, so the Painless script and the Python side are compared
    against one canonical function.
    """
    return token(family, value, salt)


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


# --------------------------------------------------------------------------- #
# Klaxon config fragment
# --------------------------------------------------------------------------- #


def _gdpr_kind(family: str) -> str:
    return {
        "IP": "IP_ADDRESS",
        "USER": "USERNAME",
        "HOST": "HOSTNAME",
        "AGENT": "AGENT_ID",
    }[family]


def _gdpr_priority(family: str) -> str:
    return "high" if family in {"IP", "USER"} else "medium"


def build_config_fragment(cfg: TenantConfig) -> str:
    """The Klaxon `anonymization:` + `gdpr_checker:` YAML fragment for a tenant.

    Deterministic: same fields.yaml -> same fragment.
    """
    mask_fields = "\n".join(f"    - {f.field}" for f in cfg.fields)
    custom = "\n".join(
        f"    - field: {f.field}\n      type: {_gdpr_kind(f.family)}\n"
        f"      priority: {_gdpr_priority(f.family)}"
        for f in cfg.fields
    )
    free_text = "\n".join(f"    - {f}" for f in cfg.free_text_fields)
    sha = fields_yaml_sha256(cfg)
    return (
        f"# generated from {cfg.source_rel} (sha256: {sha})\n"
        f"# Hand-edit only via {cfg.source_rel} + "
        "`klaxon masking generate`. CI enforces this.\n"
        "anonymization:\n"
        "  mask_aggregation_keys: true\n"
        f"  mask_free_text_users: {str(cfg.mask_free_text_users).lower()}\n"
        "  mask_fields:\n"
        f"{mask_fields}\n"
        "  masked_streams:\n"
        f"    - {cfg.masked_stream_pattern}\n"
        + (f"  mask_free_text_fields:\n{free_text}\n" if free_text else "")
        + "gdpr_checker:\n"
        "  custom_patterns:\n"
        f"{custom}\n"
    )


# --------------------------------------------------------------------------- #
# Ingest pipeline (Painless)
# --------------------------------------------------------------------------- #


def _painless_script(cfg: TenantConfig) -> str:
    """The Painless source for the masking pipeline, built from fields.yaml.

    The salt is NOT embedded in the source: the script reads `params.salt`, set
    on the script processor (the template carries `__SALT__` so the secret never
    enters git; the deployable pipeline carries the real salt). The script
    contains no hardcoded field names either — the field table is injected as
    the `FIELDS`/`FREE_TEXT` lists below.

    The emission rules are pinned against the LIVE cluster (see `klaxon masking
    test`): Painless requires every function declaration to precede any
    top-level statement, AND functions can only read their parameters, local
    variables and other functions (NOT `params`, NOT top-level `def`s) — so all
    shared data (the salt, the field table) is threaded into the functions from
    the main logic. The hash uses the ingest-context `String.sha256()`
    augmentation (byte-identical to `MessageDigest "SHA-256"`), the free-text
    regexes are regex literals wrapped in `Pattern` functions (the cluster does
    not whitelist `Pattern.compile`), and the known-identity registry does a
    manual word-boundary replacement (the cluster's `String.replaceAll` is not
    usable and `Pattern.compile` is unavailable for a per-value dynamic regex).
    `ctx` IS the ingest document (no nested `_source`).
    """
    field_rows = ",\n    ".join(
        json.dumps(f.to_painless_row()) for f in cfg.fields
    )
    free_text_rows = ", ".join(json.dumps(f) for f in cfg.free_text_fields)

    pattern_fns = "\n".join(
        f'Pattern {name}() {{ return /{_painless_regex(name)}/; }}'
        for name in _FREETEXT_PATTERN_ORDER
    )
    pattern_uses = "\n".join(
        f'        out = maskPattern({name}(), out, "{_MASK_FAMILY[name]}", SALT);'
        for name in _active_free_text_patterns(cfg)
    )
    registry_line = (
        "    // Known identities first, so free text reuses the exact structured token.\n"
        "    out = maskRegistry(out, source, FIELDS, SALT);"
        if cfg.mask_free_text_users
        else "    // mask_free_text_users: false -> registry + broader username patterns skipped."
    )
    return f"""// Generated from {cfg.source_rel} — do not edit by hand.
// klaxon-mask-{cfg.tenant}: deterministic masking for {cfg.masked_stream_pattern}.

// ---- Functions first. Painless requires EVERY function declaration to precede
// any top-level statement, and functions can only read their parameters, local
// variables and other functions (NOT `params`, NOT top-level defs) — so all
// shared data (salt, field table) is threaded in from the main logic. ----

String sha256hex(String input) {{
    // SHA-256 via the ingest String augmentation; first 16 hex chars of the
    // digest (byte-identical to MessageDigest "SHA-256").
    return input.sha256().substring(0, 16);
}}

String token(String family, String value, String SALT) {{
    if (value == null) return value;
    if (value.isEmpty()) return value;  // empty stays empty, mirrors derive_token
    if (TOKEN_RE().matcher(value).matches()) return value;  // idempotent
    return "[" + family + "_" + sha256hex(family + ":" + value + ":" + SALT) + "]";
}}

Pattern TOKEN_RE() {{
    // Already-tokenised values are passed through unchanged (idempotency).
    return /^\\[(?:IP|USER|HOST|AGENT)_[0-9a-f]{{16}}\\]$/;
}}

String maskPattern(Pattern p, String text, String family, String SALT) {{
    if (text == null) return text;
    Matcher m = p.matcher(text);
    int last = 0;
    StringBuilder out = new StringBuilder();
    while (m.find()) {{
        out.append(text.substring(last, m.start()));
        // Value-type patterns (EMAIL/IPV6/IPV4) have no capturing group; ask for
        // the whole match then. Calling group(1) on a group-less pattern THROWS
        // "No group 1" in Java, so guard with groupCount() (mirrors the Python
        // twin's `m.lastindex` check).
        String matched = (m.groupCount() >= 1 && m.group(1) != null) ? m.group(1) : m.group(0);
        out.append(token(family, matched, SALT));
        last = m.end();
    }}
    out.append(text.substring(last));
    return out.toString();
}}

boolean isWordChar(int c) {{
    // Mirrors Java/Painless `\\w` for word-boundary decisions (ASCII codes:
    // a-z, A-Z, 0-9, _). `text.charAt(...)` (a char) widens to int implicitly.
    return (c >= 97 && c <= 122) || (c >= 65 && c <= 90)
        || (c >= 48 && c <= 57) || c == 95;
}}

String replaceWordBoundary(String text, String needle, String replacement) {{
    // Manual word-boundary find+replace: no Pattern.compile / replaceAll needed
    // (neither is whitelisted on restricted clusters). Equivalent to replacing
    // every `(?<!\\w)needle(?!\\w)` occurrence, left to right.
    if (needle.isEmpty()) return text;
    StringBuilder sb = new StringBuilder();
    int i = 0;
    while (true) {{
        int idx = text.indexOf(needle, i);
        if (idx < 0) {{ sb.append(text.substring(i)); break; }}
        int end = idx + needle.length();
        boolean leftOk = idx == 0 || !isWordChar(text.charAt(idx - 1));
        boolean rightOk = end >= text.length() || !isWordChar(text.charAt(end));
        if (leftOk && rightOk) {{
            sb.append(text.substring(i, idx));
            sb.append(replacement);
        }} else {{
            sb.append(text.substring(i, end));
        }}
        i = end;
    }}
    return sb.toString();
}}

String maskRegistry(String text, Map source, List FIELDS, String SALT) {{
    if (text == null) return text;
    String out = text;
    for (def entry : FIELDS) {{
        if (entry[1] != "USER") continue;
        String f = entry[0];
        if (!source.containsKey(f)) continue;
        def v = source.get(f);
        List vals = new ArrayList();
        if (v instanceof List) {{ for (item in v) {{ if (item instanceof String) vals.add(item); }} }}
        else if (v instanceof String) vals.add(v);
        for (raw in vals) {{
            String rawStr = (String) raw;
            if (rawStr.length() < 2) continue;
            String tok = token("USER", rawStr, SALT);
            if (tok == rawStr) continue; // already a token, nothing to do
            out = replaceWordBoundary(out, rawStr, tok);
        }}
    }}
    return out;
}}

String maskFreeText(String text, Map source, List FIELDS, String SALT) {{
    if (text == null) return text;
    String out = text;
{registry_line}
{pattern_uses}
    return out;
}}

// Free-text regexes as Pattern functions (regex literals). The free-text pass
// references them by name; functions may call functions regardless of order, so
// these live with the other functions.
{pattern_fns}

// ---- Top-level definitions (functions first, then statements). The salt is
// read from params.salt so it is never embedded in the source. ----

def SALT = params.salt;  // injected as the script processor's params.salt
def FIELDS = [
    {field_rows}
];
def FREE_TEXT = [
    {free_text_rows}
];

// ---- Main logic. In an ingest script processor `ctx` IS the document (the
// root map) — there is no nested `_source` object. ----

Map masked = new HashMap();
for (key in ctx.keySet()) {{ masked.put(key, ctx.get(key)); }}

for (def entry : FIELDS) {{
    String f = entry[0];
    String family = entry[1];
    boolean array = entry[2];
    if (!masked.containsKey(f)) continue;            // missing field: no-op
    def v = masked.get(f);
    if (array) {{
        if (v instanceof List) {{
            List out = new ArrayList();
            for (item in v) {{
                if (item instanceof String) out.add(token(family, item, SALT));
                else out.add(item);
            }}
            masked.put(f, out);
        }}
    }} else {{
        if (v instanceof String) masked.put(f, token(family, v, SALT));
    }}
}}

for (f in FREE_TEXT) {{
    if (masked.containsKey(f) && masked.get(f) instanceof String) {{
        // Registry reads the RAW original source: free text must re-tokenise the
        // same raw username to the exact structured token.
        masked.put(f, maskFreeText(masked.get(f), ctx, FIELDS, SALT));
    }}
}}

// Commit atomically: only on full success does the document change. A failure is
// caught by the on_failure processor, which flags klaxon.masking_error and keeps
// the (original) document so it can be filtered and fixed.
ctx.clear();
ctx.putAll(masked);
"""


# Painless pattern name -> family (for tokenizing value-type matches).
_MASK_FAMILY = {
    "EMAIL": "EMAIL",
    "IPV6": "IP",
    "IPV4": "IP",
    "USER_NOUN": "USER",
    "USER_AUTH": "USER",
    "UID_EQ": "USER",
    "FOR_USER": "USER",
    "SSH_PUBKEY": "USER",
    "UID_PAREN": "USER",
}


def _painless_regex(name: str) -> str:
    """The regex source emitted into the Painless regex literal for a pattern.

    Same matching semantics as `_PATTERNS[name]`, hardened against the cluster's
    `script.painless.regex.limit-factor` (default 6): greedy quantifiers in the
    value-type patterns read up to ~6x the input (Painless counts every character
    the matcher touches, and a `find()` loop that never matches runs at the
    limit), tripping on dot/digit-heavy log lines. Possessive quantifiers make
    the scan linear (~1x input) while matching the exact same values — the local
    part/domain/TLD runs are never followed by another character of the same
    class inside a token, so giving up backtracking changes nothing. The Python
    twin keeps the greedy source (`re` has no possessive quantifiers and no such
    limit); both match the same values, so the token identity holds.
    """
    regex = _PATTERNS[name]
    if name == "EMAIL":
        # Local part possessive only (`++` compiles here; `{2,}++` does not).
        # The domain `[A-Za-z0-9.-]+` MUST stay greedy: `.` is in its class, so
        # a possessive domain would eat the dot the TLD's `\.` needs and stop
        # matching real e-mails like noreply@example.com.
        regex = regex.replace(
            "[A-Za-z0-9._%+-]+@",
            "[A-Za-z0-9._%+-]++@",
            1,
        )
    return regex


def build_pipeline(cfg: TenantConfig, salt: str) -> dict[str, Any]:
    """The `PUT /_ingest/pipeline/klaxon-mask-<tenant>` body.

    The salt is carried as the script processor's `params.salt` (ingest
    pipelines cannot read process env, so the deployable pipeline embeds the
    real salt there; the committed template uses `__SALT__` so the secret never
    enters git). `_meta` carries the provenance fingerprint (source path, sha256
    of fields.yaml, tenant, generator version) plus the field table, which is
    what drift checks (`verify-config`, sync preflight, salt-check) compare.
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


def deploy_pipeline(cfg: TenantConfig) -> dict[str, Any]:
    """The deployable pipeline with the real salt from the environment."""
    return build_pipeline(cfg, resolve_salt(cfg.salt_env))


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
    deploy time (see `apply-masked-infra`, which fetches them from the indexer).
    Only `klaxon-masked-<tenant>-v5-*` matches — Wazuh streams are never touched.
    """
    template: dict[str, Any] = {
        "settings": {
            "index.default_pipeline": cfg.pipeline_name,
            "index.lifecycle.name": cfg.ism_policy_name,
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


def pipeline_field_names(pipeline: dict[str, Any]) -> tuple[str, ...]:
    """The effective field list a pipeline masks, from its `_meta`."""
    meta = pipeline.get("_meta") or {}
    fields = meta.get("fields") or []
    free_text = meta.get("free_text_fields") or []
    return tuple(str(f) for f in (*fields, *free_text))


def effective_mask_fields_from_config(cfg: TenantConfig) -> tuple[str, ...]:
    """What the Klaxon config MUST mask for this tenant (field + free text)."""
    return tuple((*cfg.all_masked_fields, *cfg.free_text_fields))


def fingerprint_matches(pipeline: dict[str, Any], cfg: TenantConfig) -> bool:
    """Whether a deployed pipeline was generated from the current fields.yaml."""
    meta = pipeline.get("_meta") or {}
    return (
        meta.get("sha256") == fields_yaml_sha256(cfg)
        and set(pipeline_field_names(pipeline)) == set(effective_mask_fields_from_config(cfg))
    )
