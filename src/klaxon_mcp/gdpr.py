# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The DSGVO plausibility checker: find sensitive fields, suggest masking.

The anonymization layer masks *configured* fields; this module is the other
half of the story — it looks at an index and asks "what *should* be configured",
so the operator can discover personal data they did not know was collected.

Classification is threefold, in decreasing certainty:

  1. **Custom rules** from `gdpr_checker.custom_patterns` in config.yaml. The
     operator's own knowledge always wins over heuristics.
  2. **Field-name patterns**: `source.ip` is an IP by construction; `user.name`
     is a username; `host.hostname` / `wazuh.agent.name` are hostnames;
     `user.email` is an e-mail. These are structural — a dotted ECS-style name
     says what a field means without looking at a single document.
  3. **Sampled values**: a few documents are pulled and the actual values are
     checked against value patterns. This catches the fields a name pattern
     missed (a custom field holding IPs) and the free-text fields that embed
     personal data (`event.original` with an IP or username inside).

Priorities follow the spec: IPs, usernames and e-mails are directly personal
(high); hostnames and agent ids are indirectly personal (medium); everything
else is low. Fields already in the anonymization `mask_fields` are reported as
covered, not re-suggested.

The side effects — updating `config.yaml`'s `anonymization.mask_fields`,
appending to `gdpr_check.log`, writing `gdpr_compliance_report.json` — are
deliberately small and live here so both the MCP tool and the CLI share them.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .clients import IndexerClient, Response, TransportError
from .fields import FieldInfo, fetch_field_caps
from .tables import table

logger = logging.getLogger("klaxon_mcp.gdpr")

# --------------------------------------------------------------------------- #
# Kinds, priorities, suggested masks
# --------------------------------------------------------------------------- #

IP_ADDRESS = "IP_ADDRESS"
USERNAME = "USERNAME"
EMAIL = "EMAIL"
USER_ID = "USER_ID"
HOSTNAME = "HOSTNAME"
AGENT_ID = "AGENT_ID"
DOMAIN = "DOMAIN"
FREETEXT = "FREETEXT"

PRIORITIES = ("high", "medium", "low")
_PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# The mask a field would get once added to anonymization.mask_fields. Generic
# labels (the use_hash=false form) are shown because they read better as a
# suggestion; the real placeholder family is derived from the field name at
# masking time.
_SUGGESTED_MASK: dict[str, str] = {
    IP_ADDRESS: "[IP_ADDRESS]",
    EMAIL: "[EMAIL]",
    USERNAME: "[USERNAME]",
    USER_ID: "[USERNAME]",
    HOSTNAME: "[HOSTNAME]",
    AGENT_ID: "[AGENT_ID]",
    DOMAIN: "[HOSTNAME]",
    FREETEXT: "[USERNAME]",
}

# --------------------------------------------------------------------------- #
# Value patterns (shared by content classification and the cheap hit scan)
# --------------------------------------------------------------------------- #


def _ipv4() -> str:
    octet = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
    return rf"\b(?:{octet}\.){{3}}{octet}\b"


_IPV4_RE = re.compile(_ipv4())
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_FQDN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
)
_USERNAME_AUTH_RE = re.compile(
    r"(?i)\b(?:login|logon|sign[- ]?in|authenticat(?:e|ed|ion))\b"
    r"\s+(?:as|for|by)\s+(?:\buser\b\s+)?[A-Za-z0-9_.@%+=-]{2,64}\b"
)
_USERNAME_NOUN_RE = re.compile(
    r"(?i)\b(?:user|username|account)\b\s*(?:name)?\s*[:=]\s*"
    r"[A-Za-z0-9_.@%+=-]{2,64}"
)

# Fields whose values are raw log lines — the free-text carriers where an IP or
# username can hide inside otherwise unsuspicious text.
_FREETEXT_HINT_RE = re.compile(
    r"original|\.message$|\.log$|raw|payload|details|description|text|event\.name",
    re.IGNORECASE,
)


def _value_kind(value: str) -> str | None:
    """Whole-value classification: the value *is* an IP, e-mail or hostname."""
    stripped = value.strip()
    if not stripped:
        return None
    if _EMAIL_RE.fullmatch(stripped):
        return EMAIL
    if _IPV4_RE.fullmatch(stripped) or _IPV6_RE.fullmatch(stripped):
        return IP_ADDRESS
    if _FQDN_RE.fullmatch(stripped) and "://" not in stripped:
        return HOSTNAME
    return None


def _embeds_personal_data(value: str) -> bool:
    """Whether free text contains an IP, e-mail or username formulation."""
    return bool(
        _IPV4_RE.search(value)
        or _IPV6_RE.search(value)
        or _EMAIL_RE.search(value)
        or _USERNAME_AUTH_RE.search(value)
        or _USERNAME_NOUN_RE.search(value)
    )


# --------------------------------------------------------------------------- #
# Field-name patterns. Ordered: the first match wins, so the specific entries
# (user.name vs user.id) come before the generic ones that would swallow them.
# --------------------------------------------------------------------------- #

_NAME_PATTERNS: tuple[tuple[str, str, str], ...] = (
    (r"(^|\.)user\.name$", USERNAME, "high"),
    (r"(^|\.)username$", USERNAME, "high"),
    (r"(^|\.)user\.id$", USER_ID, "high"),
    (r"email", EMAIL, "high"),
    (r"(^|\.)ip$", IP_ADDRESS, "high"),
    (r"hostname", HOSTNAME, "medium"),
    (r"(^|\.)host\.name$", HOSTNAME, "medium"),
    (r"(^|\.)agent\.name$", HOSTNAME, "medium"),
    (r"(^|\.)agent\.id$", AGENT_ID, "medium"),
    (r"\.domain$", DOMAIN, "medium"),
)

_NAME_PATTERN_RES = tuple(
    (re.compile(pattern), kind, priority)
    for pattern, kind, priority in _NAME_PATTERNS
)


def _field_matches(field: str, pattern: str) -> bool:
    """Exact, suffix, or simple `*` glob match against a dotted field name."""
    if "*" in pattern:
        import fnmatch

        return fnmatch.fnmatchcase(field, pattern)
    return field == pattern or field.endswith("." + pattern)


def _name_match(field: str) -> tuple[str, str] | None:
    for regex, kind, priority in _NAME_PATTERN_RES:
        if regex.search(field):
            return kind, priority
    return None


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class SensitiveField:
    field: str
    kind: str
    priority: str
    evidence: str
    suggested_mask: str
    already_configured: bool = False


@dataclass
class CheckResult:
    index: str
    mapped_total: int
    sensitive: list[SensitiveField]
    sampled_fields: int
    sample_size: int
    caps_failed: Response | None = None

    @property
    def new_fields(self) -> list[str]:
        """Sensitive fields not yet covered by the anonymization list."""
        return [f.field for f in self.sensitive if not f.already_configured]

    @property
    def action_required(self) -> bool:
        return bool(self.new_fields)


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #


def is_freetext(field: str, field_types: list[str]) -> bool:
    """Whether a field plausibly carries free text (raw log lines etc.)."""
    if "text" in field_types:
        return True
    return bool(_FREETEXT_HINT_RE.search(field))


def classify_field(
    field: str,
    field_types: list[str],
    sampled: list[str],
    custom_patterns: tuple[dict[str, Any], ...],
    already_masked: set[str],
) -> SensitiveField | None:
    """Classify one field, or return None when it is not DSGVO-relevant."""
    covered = field in already_masked

    # 1. Custom rules first: the operator's knowledge beats every heuristic.
    for rule in custom_patterns:
        fpat = rule.get("field")
        if not isinstance(fpat, str) or not _field_matches(field, fpat):
            continue
        regex = rule.get("regex")
        if isinstance(regex, str) and regex:
            try:
                content = re.compile(regex)
            except re.error:
                content = None
            if content is not None and not any(content.search(v) for v in sampled):
                continue
        kind = str(rule.get("type", USERNAME))
        priority = str(rule.get("priority", "high")).lower()
        if priority not in _PRIORITY_ORDER:
            priority = "high"
        return SensitiveField(
            field,
            kind,
            priority,
            "custom rule",
            _SUGGESTED_MASK.get(kind, _SUGGESTED_MASK[USERNAME]),
            covered,
        )

    # 2. Field-name patterns.
    named = _name_match(field)
    if named is not None:
        kind, priority = named
        return SensitiveField(
            field,
            kind,
            priority,
            "field-name pattern",
            _SUGGESTED_MASK[kind],
            covered,
        )

    # 3. Sampled content. Whole-value matches first; free-text embedding second.
    if sampled:
        kinds = {k for v in sampled if (k := _value_kind(v)) is not None}
        for kind in (IP_ADDRESS, EMAIL, HOSTNAME):
            if kind in kinds:
                label = {
                    IP_ADDRESS: "an IP address",
                    EMAIL: "an e-mail address",
                    HOSTNAME: "a hostname",
                }[kind]
                return SensitiveField(
                    field, kind, "high" if kind != HOSTNAME else "medium",
                    f"sampled value is {label}", _SUGGESTED_MASK[kind], covered,
                )
        if is_freetext(field, field_types) and any(
            _embeds_personal_data(v) for v in sampled
        ):
            return SensitiveField(
                field,
                FREETEXT,
                "medium",
                "free text embedding personal data (IP/e-mail/username)",
                _SUGGESTED_MASK[FREETEXT],
                covered,
            )

    return None


def analyze(
    fields: list[FieldInfo],
    sampled: dict[str, list[str]],
    custom_patterns: tuple[dict[str, Any], ...],
    already_masked: set[str],
) -> list[SensitiveField]:
    """Classify every mapped field; sort by priority, then name."""
    out: list[SensitiveField] = []
    for info in fields:
        found = classify_field(
            info.name,
            info.types,
            sampled.get(info.name, []),
            custom_patterns,
            already_masked,
        )
        if found is not None:
            out.append(found)
    out.sort(key=lambda s: (_PRIORITY_ORDER.get(s.priority, 9), s.field))
    return out


def scan_hits(
    parsed: Any, custom_patterns: tuple[dict[str, Any], ...]
) -> list[str]:
    """Cheap scan of a search response: which sensitive fields appear in hits.

    No sampling, no extra requests — walks the `_source` of the hits it already
    has and matches the field names against the patterns. Used by `search` when
    `KLAXON_GDPR_CHECK_ON_SEARCH=true` to keep every response GDPR-visible.
    """
    found: set[str] = set()

    def visit(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                child = f"{path}.{key}" if path else key
                if isinstance(value, (dict, list)):
                    visit(value, child)
                elif isinstance(value, (str, int, float, bool)):
                    if _name_match(child) is not None or _custom_matches_field(
                        child, custom_patterns
                    ):
                        found.add(child)

    hits: list[Any] = []
    if isinstance(parsed, dict):
        node = parsed.get("hits")
        if isinstance(node, dict) and isinstance(node.get("hits"), list):
            hits = node["hits"]
    for hit in hits:
        source = hit.get("_source") if isinstance(hit, dict) else None
        if isinstance(source, dict):
            visit(source, "")
    return sorted(found)


def _custom_matches_field(
    field: str, custom_patterns: tuple[dict[str, Any], ...]
) -> bool:
    for rule in custom_patterns:
        fpat = rule.get("field")
        if isinstance(fpat, str) and _field_matches(field, fpat):
            return True
    return False


# --------------------------------------------------------------------------- #
# Sampling actual values
# --------------------------------------------------------------------------- #


def _collect(node: Any, prefix: str, out: dict[str, list[str]]) -> None:
    """Flatten a _source document into dotted field path -> string values.

    Both shapes are accepted: nested objects (`{"source": {"ip": ...}}`) and
    literal dotted keys (`{"source.ip": ...}`), which is the same tolerance the
    `field_coverage` tool applies. Values are capped at 5 per field — the
    sample only needs to establish the *kind*, not a census.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, (dict, list)):
                _collect(value, path, out)
            elif isinstance(value, (str, int, float, bool)):
                bucket = out.setdefault(path, [])
                if len(bucket) < 5 and str(value) not in bucket:
                    bucket.append(str(value))
    elif isinstance(node, list):
        for item in node:
            _collect(item, prefix, out)


async def sample_values(
    client: IndexerClient,
    index: str,
    fields: list[FieldInfo],
    size: int,
) -> tuple[dict[str, list[str]], int]:
    """Sample documents and collect up to 5 distinct string values per field.

    The full `_source` is requested — a Wazuh 5 event carries roughly 40
    populated fields, so a few documents are cheap and the flattening catches
    fields no name pattern would suspect. Returns (values by field, documents
    sampled). A failure is not an error: content-based classification is a
    supplement, and the caller falls back to name patterns alone.
    """
    if size <= 0 or not fields:
        return {}, 0

    body: dict[str, Any] = {
        "size": min(size, 100),
        "_source": True,
        "query": {"match_all": {}},
        "track_total_hits": False,
    }
    response = await client.post(f"/{index}/_search", body=body)
    if not response.ok:
        return {}, 0

    parsed = response.json()
    hits: list[Any] = []
    if isinstance(parsed, dict):
        node = parsed.get("hits")
        if isinstance(node, dict) and isinstance(node.get("hits"), list):
            hits = node["hits"]

    values: dict[str, list[str]] = {}
    for hit in hits:
        source = hit.get("_source") if isinstance(hit, dict) else None
        if isinstance(source, dict):
            _collect(source, "", values)

    return values, len(hits)


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_table(fields: list[SensitiveField]) -> str:
    if not fields:
        return "(no DSGVO-relevant fields found)"
    rows = [
        [
            f.field,
            f.kind,
            f.priority,
            f.evidence,
            f.suggested_mask,
            "yes" if f.already_configured else "no",
        ]
        for f in fields
    ]
    return table(
        ["FIELD", "TYPE", "PRIORITY", "EVIDENCE", "MASK", "COVERED"], rows
    )


def render_json(result: CheckResult) -> str:
    """Machine-readable report, the shape scripts and SIEM forwarders parse."""
    payload: dict[str, Any] = {
        "index": result.index,
        "checked_fields": result.mapped_total,
        "sensitive_fields": [
            {
                "field": f.field,
                "type": f.kind,
                "priority": f.priority,
                "suggested_mask": f.suggested_mask,
                "already_configured": f.already_configured,
                "evidence": f.evidence,
            }
            for f in result.sensitive
        ],
        "action_required": result.action_required,
        "fields_to_add": result.new_fields,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def env_hint(new_fields: list[str]) -> str:
    """The environment-variable equivalent of adding the fields."""
    if not new_fields:
        return ""
    return f'KLAXON_ANONYMIZATION_MASK_FIELDS="' + ",".join(new_fields) + '"'


async def run_check(
    client: IndexerClient,
    index: str,
    prefix: str | None,
    sample_size: int,
    custom_patterns: tuple[dict[str, Any], ...],
    already_masked: set[str],
    exclude: set[str] | None = None,
) -> CheckResult:
    """The shared orchestration: caps -> sample -> analyze.

    Shared by the MCP tool and both CLI entry points so the three renderers
    always agree on what a check means. A field_caps failure is a CheckResult
    carrying the failed response, never an exception.
    """
    excluded = exclude or set()
    try:
        caps = await fetch_field_caps(client, index, prefix)
    except TransportError as exc:
        raise RuntimeError(str(exc)) from exc
    if not caps.ok:
        return CheckResult(index, 0, [], 0, sample_size, caps_failed=caps.response)

    fields = [f for f in caps.fields if f.name not in excluded]
    sampled, _ = await sample_values(client, index, fields, sample_size)
    sensitive = analyze(fields, sampled, custom_patterns, already_masked)
    return CheckResult(
        index=index,
        mapped_total=len(caps.fields),
        sensitive=sensitive,
        sampled_fields=len(sampled),
        sample_size=sample_size,
    )


# --------------------------------------------------------------------------- #
# Side effects: config update, audit log, compliance report
# --------------------------------------------------------------------------- #


def load_config_doc(config_file: str) -> dict[str, Any] | None:
    """Read the whole YAML config, or None when absent/unreadable."""
    try:
        import yaml
    except ImportError:
        return None
    if not os.path.exists(config_file):
        return {}
    try:
        with open(config_file, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) else {}


def update_mask_fields(
    config_file: str, new_fields: list[str]
) -> tuple[bool, list[str], str | None]:
    """Merge `new_fields` into `anonymization.mask_fields` of the YAML file.

    Returns (changed, merged_list, warning). The warning explains when the
    change cannot take effect — most importantly when
    KLAXON_ANONYMIZATION_MASK_FIELDS is set, because the environment overrides
    the file.
    """
    try:
        import yaml
    except ImportError:
        return False, list(new_fields), (
            "pyyaml is not installed; config.yaml cannot be updated. Use "
            "KLAXON_ANONYMIZATION_MASK_FIELDS instead."
        )

    doc = load_config_doc(config_file)
    if doc is None:
        return False, list(new_fields), (
            f"could not read {config_file}; no fields added."
        )

    anon = doc.get("anonymization")
    if not isinstance(anon, dict):
        anon = {}
        doc["anonymization"] = anon
    current = anon.get("mask_fields")
    merged = list(current) if isinstance(current, list) else []
    added = [f for f in new_fields if f not in merged]
    merged.extend(added)
    anon["mask_fields"] = merged

    try:
        with open(config_file, "w", encoding="utf-8") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True)
    except OSError as exc:
        return False, merged, f"could not write {config_file}: {exc}"

    warning: str | None = None
    if os.environ.get("KLAXON_ANONYMIZATION_MASK_FIELDS"):
        warning = (
            "KLAXON_ANONYMIZATION_MASK_FIELDS is set and overrides config.yaml. "
            "Unset it, or set it to the merged list, for the file to take effect."
        )
    return bool(added), merged, warning


class GdprLog:
    """Append-only audit log for check actions, e.g. gdpr_check.log."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = threading.Lock()

    def write(self, *lines: str) -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            parent = os.path.dirname(self._path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with self._lock, open(self._path, "a", encoding="utf-8") as fh:
                for line in lines:
                    fh.write(f"{ts} - [DSGVO-Prüfer] {line}\n")
        except OSError as exc:
            logger.error("could not write gdpr log %s: %s", self._path, exc)


def write_compliance_report(report_path: str, payload: dict[str, Any]) -> str | None:
    """Write the JSON compliance report; returns an error message or None."""
    try:
        parent = os.path.dirname(report_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
    except OSError as exc:
        return f"could not write {report_path}: {exc}"
    return None
