# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The anonymization layer: mask PII before data leaves for a non-local LLM.

Klaxon is an MCP tool server. Tool results are returned to the MCP client, which
feeds them to the chat model. When that model runs outside the operator's
network (DeepSeek cloud, Mistral API, ...), the results physically leave the
building. This layer makes sure they leave without personal data.

Three steps, in order:

  1. **Structured pass** (`mask_json` / `mask_overview`): a deep walk over the
     parsed response. Values under configured fields (`source.ip`, `user.name`,
     `wazuh.agent.name`, ...) are replaced with deterministic placeholders, and
     IP addresses, e-mails and dotted hostnames are masked in every string
     value. This is the pass that knows *what a field means*, so it can mask a
     bare username that no regex could recognise.

  2. **Text pass** (`mask_text`): a safety net over the fully rendered tool
     output (tables, summaries, footers) that masks e-mails, IP addresses and
     usernames in their log context (`user=...`, `login as/for/by ...`)
     anywhere. Usernames outside those near-certain formulations are not
     guessed at — that is the structured pass's job, and guessing would corrupt
     output.

  3. **Verify + block** (`verify` / `finish`): the masked output is scanned for
     residuals. When the whitelist is enabled (the default), a residual IP or
     e-mail means the response is *withheld* — returned as a notice, not as
     data — so no unmasked PII can reach an external model. Every exchange is
     logged with a timestamp to llm_prompts.log, which is the GDPR audit trail.

No PII is persisted by default: the prompt log stores the MASKED output only.
KLAXON_ANONYMIZATION_LOG_RAW=true changes that deliberately (a log of raw
events is itself a personal-data store, and the operator is warned when it is
switched on).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import gdpr as _gdpr
from . import overview as _overview
from .clients import Response
from .config import AnonymizationConfig
from .field_kinds import field_kind as _field_kind
from .patterns import _EMAIL_RE, _FQDN_RE, _IPV4_RE, _IPV6_RE
from .tokens import weak_salt

logger = logging.getLogger("klaxon_mcp.anonymization")

# --------------------------------------------------------------------------- #
# Placeholder families
# --------------------------------------------------------------------------- #

IP = "IP"
HOST = "HOST"
USER = "USER"
AGENT = "AGENT"
EMAIL = "EMAIL"

# use_hash=false labels, following the spec's generic forms.
_NO_HASH_LABELS: dict[str, str] = {
    IP: "[IP_ADDRESS]",
    HOST: "[HOSTNAME]",
    USER: "[USERNAME]",
    AGENT: "[AGENT_ID]",
    EMAIL: "[EMAIL]",
}

# Fallback secret when neither KLAXON_ANONYMIZATION_SALT nor a persisted salt
# file is configured: one random value per process, shared by every Anonymizer
# in it. Config resolution normally provides a stable salt; this only guards
# direct construction.
_PROCESS_SALT: str | None = None


def _process_salt() -> str:
    global _PROCESS_SALT
    if _PROCESS_SALT is None:
        _PROCESS_SALT = secrets.token_hex(32)
    return _PROCESS_SALT

# A counter per family is enough to keep the compliance report bounded.
_MAX_TRACKED_VALUES = 50_000


# --------------------------------------------------------------------------- #
# Aggregation key mapping. `search` responses carry a raw `aggregations` block;
# bucket keys are computed on indexed values and would otherwise leak the same
# personal data the `_source` pass masks (a terms agg on `related.hosts` returns
# `nc02web`, `yun`, ...). The request body is walked to record which aggregation
# name derives its keys from which field, and the response walker then tokenises
# those keys with the very same deterministic token function the `_source` pass
# uses — so one entity maps to one token in both places.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AggSpec:
    """Field mapping for one aggregation, used to mask its bucket keys.

    Only aggregations whose keys derive from a source field are recorded:
    `terms`-family and `multi_terms` carry an ordered `fields` tuple, `composite`
    carries `(source_name, field)` pairs in request order. Everything else
    (date_histogram, histogram, range, filters, metrics, scripted aggs) is
    `agg_type=None`, and its keys are never tokenised — a key is masked only when
    its recorded source field is in `mask_fields`.

    `children` records the nested sub-aggregations declared in the request's
    `aggs` tree (name -> spec, in declaration order). OpenSearch nests these
    DIRECTLY inside each bucket — siblings of `key`/`doc_count`, with no
    `aggregations` wrapper — so the response walker needs this per-parent
    hierarchy to find them, and to resolve same-named sub-aggregations under
    different parents to the field of *that* level (a flat name map would pick
    the wrong field on a collision).
    """

    agg_type: str | None
    fields: tuple[str, ...] = ()
    sources: tuple[tuple[str, str], ...] = ()
    children: tuple[tuple[str, AggSpec], ...] = ()

    def child(self, name: str) -> AggSpec | None:
        """The spec of a nested sub-aggregation of this aggregation, by name."""
        for child_name, child in self.children:
            if child_name == name:
                return child
        return None


def parse_agg_fields(body: Any) -> dict[str, AggSpec]:
    """Map aggregation name -> AggSpec for a forwarded search request body.

    Walks the top-level `aggs` tree recursively, so nested sub-aggregations
    (`agents -> categories`) are recorded under their own names. Opaque bodies
    (saved searches, scripted aggs, unknown shapes) simply yield no spec for
    that aggregation, and its keys pass through unmasked — never guessed at.
    """
    specs: dict[str, AggSpec] = {}
    if isinstance(body, dict):
        aggs = body.get("aggs")
        if isinstance(aggs, dict):
            _walk_aggs(aggs, specs)
    return specs


def _walk_aggs(aggs: dict[str, Any], specs: dict[str, AggSpec]) -> None:
    for name, agg in aggs.items():
        specs[name] = _agg_spec(agg)
        nested = agg.get("aggs") if isinstance(agg, dict) else None
        if isinstance(nested, dict):
            _walk_aggs(nested, specs)


def _agg_spec(agg: Any) -> AggSpec:
    """The AggSpec for one request-body aggregation object.

    Records the aggregation's own type/field mapping AND the nested
    sub-aggregations declared under its `aggs` key (`children`), so the
    response walker can descend through buckets at every depth.
    """
    body = _agg_body_spec(agg)
    return AggSpec(
        body.agg_type,
        body.fields,
        body.sources,
        children=_child_specs(agg),
    )


def _agg_body_spec(agg: Any) -> AggSpec:
    """Aggregation type/field mapping only (no `children`) for one request agg."""
    if not isinstance(agg, dict):
        return AggSpec(None)
    for kind in ("terms", "significant_terms", "significant_text"):
        inner = agg.get(kind)
        if isinstance(inner, dict) and isinstance(inner.get("field"), str):
            return AggSpec(kind, (inner["field"],))
    inner = agg.get("multi_terms")
    if isinstance(inner, dict) and isinstance(inner.get("terms"), list):
        fields = tuple(
            t["field"]
            for t in inner["terms"]
            if isinstance(t, dict) and isinstance(t.get("field"), str)
        )
        if fields:
            return AggSpec("multi_terms", fields)
        return AggSpec(None)
    inner = agg.get("composite")
    if isinstance(inner, dict) and isinstance(inner.get("sources"), list):
        sources: list[tuple[str, str]] = []
        for entry in inner["sources"]:
            if not isinstance(entry, dict):
                continue
            for name, source_spec in entry.items():
                spec = _agg_spec(source_spec)
                if spec.fields:
                    sources.append((name, spec.fields[0]))
        if sources:
            return AggSpec("composite", sources=tuple(sources))
        return AggSpec(None)
    if "top_hits" in agg:
        # A marker, not a field mapping: the response embeds documents whose
        # `_source` must run through the normal document-masking path.
        return AggSpec("top_hits")
    return AggSpec(None)


def _child_specs(agg: Any) -> tuple[tuple[str, AggSpec], ...]:
    """(name, spec) pairs for the nested sub-aggregations of one request agg.

    OpenSearch nests these DIRECTLY inside each response bucket (siblings of
    `key`/`doc_count`), so the walker needs the per-parent hierarchy — a flat
    name map would resolve same-named sub-aggregations under different parents
    to the wrong field.
    """
    if not isinstance(agg, dict):
        return ()
    nested = agg.get("aggs")
    if not isinstance(nested, dict):
        return ()
    return tuple((name, _agg_spec(sub)) for name, sub in nested.items())


# --------------------------------------------------------------------------- #
# Value-type patterns. Full-match is used for whole values, search for the
# embedded pass; both must agree on what an IPv4 address is so that verify()
# (which searches) never flags something mask_text() (which also searches)
# already replaced.
# --------------------------------------------------------------------------- #


# Usernames in free text, scoped to formulations that are near-certainly a
# username in a security log. Two families, applied AFTER the value-type passes
# so an IP or e-mail is already a placeholder and can never be captured here:
#   1. `user name`, `user=name`, `username: name`, `account=name`
#   2. `login as/for/by name`, `authenticated as name`, `sign in as name`
# The connector set is deliberately small: bare "from" or "with" would capture
# source addresses and ordinary prose ("Prevent access from external hosts").
_USERNAME_NOUN_RE = re.compile(
    r"(?i)\b(?:user|username|user[-_ ]?name|account)\b\s*(?:name)?\s*[:=]\s*"
    r"(?:\"|'|`)?(?P<name>[A-Za-z0-9_.@%+=-]{2,64})"
)
_USERNAME_AUTH_RE = re.compile(
    r"(?i)\b(?:login|logon|sign[- ]?in|authenticat(?:e|ed|ion))\b"
    r"\s+(?:as|for|by)\s+(?:\buser\b\s+)?(?P<name>[A-Za-z0-9_.@%+=-]{2,64})\b"
)

# Values the registry-based free-text pass must not blindly replace: common
# English words that are not evidence of a username on their own. The context
# patterns still mask them inside username formulations.
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

# Unicode-aware name characters for usernames in free text (this deployment has
# German data): \w is the Unicode word class, so umlauts are covered.
_NAME_CHARS = r"\w.@%+=-"
_LETTER = r"[^\W\d_]"  # a Unicode letter (not a digit/underscore): uid=0 stays an id

# Gap 1: username forms in free text that the structured fields may miss. Each
# captures `name` and runs only when mask_free_text_users is on. `uid=` requires
# a leading letter so numeric ids (`uid=0`) are never mistaken for usernames.
_UID_EQ_RE = re.compile(
    rf"(?i)\buid\s*=\s*(?P<name>{_LETTER}[{_NAME_CHARS}]{{1,63}})\b"
)
_FOR_USER_RE = re.compile(
    rf"(?i)\b(?:for|by)\s+user\s+(?P<name>[{_NAME_CHARS}]{{2,64}})\b"
)
_SSH_PUBKEY_RE = re.compile(
    rf"(?i)\bAccepted\s+publickey\s+for\s+(?P<name>[{_NAME_CHARS}]{{2,64}})\b"
)
_UID_PAREN_RE = re.compile(
    rf"(?i)\b(?:by|as|for)\s+(?P<name>[{_NAME_CHARS}]{{2,64}})\s*"
    r"\(\s*uid\s*=\s*\d+\s*\)"
)
# Bare "user <name>", guarded against the common English words that follow
# "user" in prose ("user session", "user data", "user account", ...). The guard
# is derived from the full _COMMON_WORDS stoplist, so a common word is never
# masked by this pattern alone.
_USER_BARE_GUARD = "|".join(re.escape(w) + r"\b" for w in sorted(_COMMON_WORDS))
_USER_BARE_RE = re.compile(
    rf"(?i)\buser\s+(?!{_USER_BARE_GUARD})"
    rf"(?P<name>[{_NAME_CHARS}]{{2,64}})\b"
)
_USERNAME_CONTEXT_PATTERNS = (
    _UID_EQ_RE,
    _FOR_USER_RE,
    _SSH_PUBKEY_RE,
    _UID_PAREN_RE,
    _USER_BARE_RE,
)

_EMAIL = "EMAIL"
_IP = "IP"
_USER = "USER"

# A value already in this shape is a token from the masked stream (Option B) or
# ingest-time masking: leave it alone, never re-mask (idempotent). Kept in sync
# with masked_stream.TOKEN_RE.
_TOKEN_RE = re.compile(r"^\[(?:IP|USER|HOST|AGENT)_[0-9a-f]{16}\]$")


class Anonymizer:
    """Mask, verify, block and log tool output for external LLM clients.

    Deterministic by construction: with hashing on, the token is an
    HMAC-SHA256(key = salt, message = `kind:value`) (first 16 hex chars), so
    the same value always maps to the same token and no cross-request state is
    required. The in-memory counters only feed the compliance report.
    """

    def __init__(self, config: AnonymizationConfig) -> None:
        self.config = config
        if config.salt and weak_salt(config.salt):
            logger.warning(
                "Anonymization salt is shorter than 32 hex chars (16 bytes / 128 "
                "bits). The salt is the HMAC key; a weak salt makes enumerable "
                "values (usernames, internal IPs) easy to re-identify by brute "
                "force. Generate one with `python -c \"import secrets; print("
                "secrets.token_hex(32))\"` (256 bits) via KLAXON_ANONYMIZATION_SALT."
            )
        self._salt = (config.salt or _process_salt()).encode("utf-8")
        self._lock = threading.Lock()
        self._exchanges = 0
        self._blocked = 0
        self._per_tool: Counter[str] = Counter()
        self._blocked_per_tool: Counter[str] = Counter()
        self._counts: dict[str, Counter[str]] = {
            kind: Counter() for kind in _NO_HASH_LABELS
        }
        self._field_hits: Counter[str] = Counter()
        self._started = datetime.now(timezone.utc)

        if config.enabled and not config.llm_base_url:
            logger.warning(
                "Anonymization is enabled but KLAXON_LLM_BASE_URL is not set, so "
                "the client is assumed to be an external (non-local) model and "
                "tool results are masked. If the model actually runs locally, set "
                "KLAXON_LLM_BASE_URL to a loopback address (e.g. "
                "http://localhost:11434 for Ollama) and tool results pass through "
                "unchanged."
            )
        if config.log_raw:
            logger.warning(
                "KLAXON_ANONYMIZATION_LOG_RAW=true writes the unmasked RAW tool "
                "output to %s. That file is then a personal-data store: restrict "
                "its permissions and treat it as data under the GDPR, not as "
                "disposable log output.",
                config.log_path,
            )

    # ------------------------------------------------------------------ #
    # Activation
    # ------------------------------------------------------------------ #

    @property
    def active(self) -> bool:
        return self.config.active

    # ------------------------------------------------------------------ #
    # Placeholders
    # ------------------------------------------------------------------ #

    def _token(self, kind: str, value: str) -> str:
        """Deterministic, keyed token for a value in one placeholder family.

        HMAC-SHA256(key = salt, message = `kind:value`), truncated to the first
        16 hex chars (64 bits) of the full digest: dictionary reversal of a
        single token is infeasible, and the same value in different families
        gets different tokens. The `[PREFIX_xxxx]` display shape is unchanged,
        so existing consumers keep parsing it. use_hash=false falls back to the
        generic labels.
        """
        if not self.config.use_hash:
            return _NO_HASH_LABELS[kind]
        digest = hmac.new(
            self._salt, f"{kind}:{value}".encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"[{kind}_{digest[:16]}]"

    def _register(self, kind: str, value: str) -> str:
        """Record a masked value for the report and return its token."""
        with self._lock:
            counts = self._counts[kind]
            if len(counts) < _MAX_TRACKED_VALUES:
                counts[value] += 1
        return self._token(kind, value)

    # ------------------------------------------------------------------ #
    # Structured pass
    # ------------------------------------------------------------------ #

    def _field_for_path(self, path: str) -> tuple[str, str] | None:
        """(kind, matched_field) when `path` names a configured mask field."""
        for field in self.config.mask_fields:
            if not field:
                continue
            same = path == field
            nested = (
                len(path) > len(field)
                and path.endswith(field)
                and path[-len(field) - 1] == "."
            )
            if same or nested:
                return _field_kind(field), field
        return None

    def _mask_string_value(
        self, path: str, value: str, identities: Mapping[str, str] | None = None
    ) -> str:
        """Mask a single string leaf of the response, given its dotted path."""
        if not value:
            return value
        if _TOKEN_RE.fullmatch(value):
            # Already a token (masked stream): idempotent passthrough.
            return value

        matched = self._field_for_path(path)
        if matched is not None:
            kind, field = matched
            with self._lock:
                self._field_hits[field] += 1
            return self._register(kind, value)

        # Unconfigured field: mask by value type. Whole-value matches first
        # (a field that holds nothing but an IP is an IP), then embedded
        # occurrences inside free text. Free-text fields additionally get the
        # username pass (known identities + context patterns) when enabled.
        stripped = value.strip()
        if _EMAIL_RE.fullmatch(stripped):
            return self._register(_EMAIL, stripped)
        if _IPV4_RE.fullmatch(stripped) or _IPV6_RE.fullmatch(stripped):
            return self._register(_IP, stripped)
        if _FQDN_RE.fullmatch(stripped) and "://" not in stripped:
            return self._register(HOST, stripped)
        if self._is_free_text_field(path):
            return self.mask_text(value, identities)
        return self.mask_text(value)

    def mask_json(
        self, obj: Any, path: str = "", identities: Mapping[str, str] | None = None
    ) -> Any:
        """Deep-walk a parsed response and mask personal data in place-free."""
        return self._mask_json(
            obj, path, skip_aggregations=False, identities=identities
        )

    def _mask_json(
        self,
        obj: Any,
        path: str = "",
        skip_aggregations: bool = False,
        identities: Mapping[str, str] | None = None,
    ) -> Any:
        """The structural pass; optionally leaves the `aggregations` subtree alone.

        With `skip_aggregations` (aggregation-key masking active) the top-level
        `aggregations` block is not walked here — `mask_aggregations` owns it and
        already tokenised its keys. Walking it again would run the value-type
        pass over tokenised keys and drift aggregation tokens apart from their
        `_source` twins. `identities` (raw value -> token for the response's
        known usernames) feeds the free-text username pass.
        """
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for key, value in obj.items():
                if skip_aggregations and not path and key == "aggregations":
                    out[key] = value
                    continue
                child_path = f"{path}.{key}" if path else key
                if key == "_source" and self.config.mask_free_text_users:
                    # Per-document identities: the free-text pass must not
                    # borrow identities from other documents in the same
                    # response, or a username in one hit would mask the same
                    # word in ordinary prose in another.
                    local = self._collect_identities(value, child_path)
                    out[key] = self._mask_json(
                        value, child_path, skip_aggregations, local
                    )
                else:
                    out[key] = self._mask_json(
                        value, child_path, skip_aggregations, identities
                    )
            return out
        if isinstance(obj, list):
            # List indices do not belong to the field path.
            return [
                self._mask_json(item, path, skip_aggregations, identities)
                for item in obj
            ]
        if isinstance(obj, str):
            return self._mask_string_value(path, obj, identities)
        # Non-string scalar leaf (int/float/bool) under a configured mask field
        # must not pass through raw just because it is not a string — a numeric
        # user.id / agent.id is personal data like its string twin. None stays
        # None (a missing value, not a value); non-configured scalars
        # (doc_count, totals, metric values) are never touched.
        if obj is not None:
            matched = self._field_for_path(path)
            if matched is not None:
                kind, field = matched
                with self._lock:
                    self._field_hits[field] += 1
                return self._register(kind, str(obj))
        return obj

    def mask_response(
        self,
        response: Response,
        agg_map: Mapping[str, AggSpec] | None = None,
    ) -> Response:
        """A clone of the response with the JSON body masked, or the original.

        `agg_map` (from `parse_agg_fields` over the forwarded request) drives
        aggregation-key masking when `mask_aggregation_keys` is on: keys whose
        source field is in `mask_fields` become the same deterministic tokens the
        `_source` pass produces. Aggregation keys are tokenised before the
        structural pass, which then skips the `aggregations` subtree so no pass
        double-masks a key. The original is returned unchanged when
        anonymization is inactive or the body is not JSON — a non-JSON body gets
        its free-text pass in `finish`.
        """
        if not self.active:
            return response
        parsed = response.json()
        if not isinstance(parsed, (dict, list)):
            return response
        # Free-text identities are built per document (inside the walk, at each
        # `_source`), so a username in one hit never masks prose in another.
        if self.config.mask_aggregation_keys:
            masked = self.mask_aggregations(parsed, agg_map)
            masked = self._mask_json(masked, "", skip_aggregations=True)
        else:
            masked = self.mask_json(parsed)
        return Response(
            response.status_code,
            json.dumps(masked, indent=2, ensure_ascii=False),
            response.url,
        )

    # ------------------------------------------------------------------ #
    # Aggregation-key masking
    # ------------------------------------------------------------------ #

    def mask_aggregations(
        self,
        obj: Any,
        agg_map: Mapping[str, AggSpec] | None,
        identities: Mapping[str, str] | None = None,
    ) -> Any:
        """Mask personal data in the `aggregations` block of a search response.

        Only fires when `mask_aggregation_keys` is on. Returns a copy of the
        parsed response with every bucket key whose source field is in
        `mask_fields` replaced by the deterministic token the `_source` pass
        produces — at EVERY nesting depth. OpenSearch nests sub-aggregations
        DIRECTLY inside buckets (siblings of `key`/`doc_count`, no
        `aggregations` wrapper); the walker descends through them via the
        request-built agg hierarchy, so a nested `terms` on `related.user`
        under a top-level `terms` on `related.hosts` gets its keys tokenised
        exactly like the top-level ones. Counts and metadata — `doc_count`,
        `doc_count_error_upper_bound`, `sum_other_doc_count` — and the keys of
        non-field aggregations (date_histogram, histogram, range, filters,
        metrics) are left byte-identical. Embedded `top_hits` documents run
        through the normal `_source` masking path.
        """
        if not self.active or not self.config.mask_aggregation_keys:
            return obj
        if not isinstance(obj, dict) or "aggregations" not in obj:
            return obj
        out = dict(obj)
        out["aggregations"] = self._mask_agg_map(
            out["aggregations"], agg_map or {}, identities=identities
        )
        return out

    def _mask_agg_map(
        self,
        aggs: Any,
        agg_map: Mapping[str, AggSpec],
        identities: Mapping[str, str] | None = None,
    ) -> Any:
        """Walk a response `aggregations` map (name -> aggregation object)."""
        if not isinstance(aggs, dict):
            return aggs
        return {
            name: self._mask_agg_obj(
                agg_obj, agg_map.get(name), agg_map, identities=identities
            )
            for name, agg_obj in aggs.items()
        }

    def _mask_agg_obj(
        self,
        agg_obj: Any,
        spec: AggSpec | None,
        agg_map: Mapping[str, AggSpec],
        identities: Mapping[str, str] | None = None,
    ) -> Any:
        """Mask one aggregation object: buckets, after_key, nested aggs, top_hits.

        Reached both for top-level aggregations (with `spec` from the flat
        `agg_map`) and for nested sub-aggregations (with `spec` resolved from the
        parent's `children`, so the field is correct for THIS level).
        """
        if not isinstance(agg_obj, dict):
            return agg_obj
        out: dict[str, Any] = {}
        for key, value in agg_obj.items():
            if key == "buckets":
                out[key] = self._mask_buckets(
                    value, spec, agg_map, identities=identities
                )
            elif (
                key == "after_key"
                and spec is not None
                and spec.agg_type == "composite"
            ):
                # Composite pagination: the tokenised after_key must match the
                # tokenised bucket keys, or the next page never matches.
                out[key] = self._mask_composite_key(value, spec)
            elif spec is not None and spec.agg_type == "top_hits" and key == "hits":
                # top_hits embeds documents; mask their `_source` through the
                # same document-masking path as the top-level hits. The response
                # carries no "top_hits" marker — the spec (from the request) is
                # what tells us this is one.
                out[key] = self.mask_json(value, "top_hits", identities=identities)
            elif key == "aggregations":
                out[key] = self._mask_agg_map(value, agg_map, identities=identities)
            elif key == "top_hits":
                # A response that does carry an explicit top_hits marker.
                out[key] = self.mask_json(value, "top_hits", identities=identities)
            else:
                # doc_count, doc_count_error_upper_bound, sum_other_doc_count,
                # the aggregation definition and metric values: never touched.
                out[key] = value
        return out

    def _mask_buckets(
        self,
        buckets: Any,
        spec: AggSpec | None,
        agg_map: Mapping[str, AggSpec],
        identities: Mapping[str, str] | None = None,
    ) -> Any:
        if isinstance(buckets, list):
            return [
                self._mask_bucket(bucket, spec, agg_map, identities=identities)
                for bucket in buckets
            ]
        if isinstance(buckets, dict):
            # Named `filters` buckets: the dict key is a filter label, never a
            # field value, so it is not tokenised. The spec still flows through
            # (a keyed agg's agg_type is None, so `_mask_key` never fires) so
            # sub-aggregations nested inside each named bucket are walked with
            # the correct child field.
            return {
                name: self._mask_bucket(bucket, spec, agg_map, identities=identities)
                for name, bucket in buckets.items()
            }
        return buckets

    def _mask_bucket(
        self,
        bucket: Any,
        spec: AggSpec | None,
        agg_map: Mapping[str, AggSpec],
        identities: Mapping[str, str] | None = None,
    ) -> Any:
        if not isinstance(bucket, dict):
            return bucket
        out: dict[str, Any] = {}
        # The masked `key` is computed once up front so `key_as_string` can be
        # REBUILT from it (never segment-wise): the masked key list is the
        # source of truth, so the joined `key_as_string` can carry no raw
        # remnant and never mixes token families for one raw value.
        masked_key = self._mask_key(bucket["key"], spec) if "key" in bucket else None
        for key, value in bucket.items():
            if key == "key":
                out[key] = masked_key
            elif key == "key_as_string":
                out[key] = self._mask_key_as_string(
                    value, spec, masked_key=masked_key
                )
            elif key == "aggregations":
                # The "aggregations"-wrapper shape (some proxies nest sub-aggs
                # under it); real OpenSearch nests them directly, handled below.
                out[key] = self._mask_agg_map(value, agg_map, identities=identities)
            else:
                # Nested sub-aggregations sit DIRECTLY in the bucket, siblings of
                # `key`/`doc_count`, with no "aggregations" wrapper. A direct
                # child whose name is a known sub-aggregation of THIS aggregation
                # (from the request tree) is a nested agg node: mask its buckets
                # and recurse deeper — at every depth, with the field for this
                # level (name collisions across parents resolve per level).
                child_spec = spec.child(key) if spec is not None else None
                if child_spec is not None:
                    out[key] = self._mask_agg_obj(
                        value, child_spec, agg_map, identities=identities
                    )
                else:
                    # doc_count and any bucket metadata are never touched.
                    out[key] = value
        return out

    def _mask_key(self, value: Any, spec: AggSpec | None) -> Any:
        """Mask a bucket key according to the recorded aggregation type."""
        if spec is None or spec.agg_type is None:
            return value
        if spec.agg_type == "composite":
            return self._mask_composite_key(value, spec)
        if spec.agg_type == "multi_terms":
            if not isinstance(value, list):
                return value
            return [
                self._mask_key_value(field, item)
                for field, item in zip(spec.fields, value)
            ]
        field = spec.fields[0] if spec.fields else ""
        return self._mask_key_value(field, value)

    def _mask_key_as_string(
        self, value: Any, spec: AggSpec | None, masked_key: Any = None
    ) -> Any:
        """Rebuild `key_as_string` from the already-masked `key`.

        The masked key list is the source of truth — never mask `key_as_string`
        segment-wise (fragile when a raw value contains "|", and the token
        family would only be guessable). For `multi_terms` the masked keys are
        joined with "|"; for the terms family `key_as_string` equals the masked
        key token. A `key_as_string` therefore can never carry a raw remnant
        (the leak) and always shares the key's token family — no more `[IP_]`
        vs `[HOST_]` for the same raw value. Unmasked fields' values stay
        verbatim (an original formatted value, e.g. a date, is preserved).
        """
        if spec is None or spec.agg_type is None:
            return value
        if spec.agg_type == "multi_terms":
            if masked_key is None or not isinstance(masked_key, list):
                return value
            return "|".join(str(item) for item in masked_key)
        if (
            spec.agg_type in {"terms", "significant_terms", "significant_text"}
            and spec.fields
        ):
            if self._field_for_path(spec.fields[0]) is None:
                # Unmasked field: key AND key_as_string stay untouched.
                return value
            if masked_key is not None:
                return masked_key
        return value

    def _mask_composite_key(self, value: Any, spec: AggSpec) -> Any:
        """Tokenise the named entries of a composite `key` / `after_key`."""
        if not isinstance(value, dict):
            return value
        out = dict(value)
        for name, field in spec.sources:
            if name in out:
                out[name] = self._mask_key_value(field, out[name])
        return out

    def _mask_key_value(self, field: str, value: Any) -> Any:
        """The same deterministic token the `_source` pass uses for `field`.

        Fires only when `field` is a configured mask field. Anything else —
        including a value that is already a token (masked at ingest elsewhere) —
        is either left alone or re-tokenised deterministically; the walker never
        guesses at a value by its type here. Non-string keys (numeric terms
        keys / composite after_key) on a configured field are tokenised too, so
        they stay identical to their `_source` twins.
        """
        matched = self._field_for_path(field) if value is not None else None
        if matched is None:
            return value
        kind, matched_field = matched
        with self._lock:
            self._field_hits[matched_field] += 1
        if not isinstance(value, str):
            return self._register(kind, str(value))
        if not value:
            return value
        if _TOKEN_RE.fullmatch(value):
            # Already a token (masked stream aggregation key / after_key): leave
            # it, never re-tokenise (idempotent).
            return value
        return self._register(kind, value)

    # ------------------------------------------------------------------ #
    # Free-text username masking (Gap 1)
    # ------------------------------------------------------------------ #

    def _is_username_path(self, path: str) -> bool:
        """Whether a dotted path plausibly holds a username value."""
        if path == "user" or path.endswith(
            (".user", ".user.name", ".user.id", ".username")
        ):
            return True
        matched = self._field_for_path(path)
        return matched is not None and matched[0] == USER

    def _collect_identities(
        self,
        obj: Any,
        path: str = "",
        identities: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """raw username -> token for every structured username field in a subtree.

        Called on a raw document's `_source` before that document is masked, so
        the free-text pass reuses the exact token the structured pass will
        produce for the same value — and never borrows identities from another
        document in the same response.
        """
        if identities is None:
            identities = {}
        if isinstance(obj, dict):
            for key, value in obj.items():
                child = f"{path}.{key}" if path else key
                self._collect_identities(value, child, identities)
        elif isinstance(obj, list):
            for item in obj:
                self._collect_identities(item, path, identities)
        elif isinstance(obj, str) and obj and self._is_username_path(path):
            if not _TOKEN_RE.fullmatch(obj):
                # An already-tokenised value is NOT a raw identity to
                # re-tokenise (that would double-mask free text on a re-run).
                identities.setdefault(obj, self._register(USER, obj))
        return identities

    def _is_free_text_field(self, path: str) -> bool:
        """Whether a field plausibly carries free text (raw log lines etc.)."""
        if _gdpr.is_freetext(path, []):
            return True
        return any(
            path == f or path.endswith("." + f)
            for f in self.config.mask_free_text_fields
        )

    def _replace_known_identities(
        self, text: str, identities: Mapping[str, str]
    ) -> str:
        """Replace known raw usernames in free text with their tokens.

        Whole-word only (Unicode-aware) and case-insensitive, and never for
        common English words (that is the context patterns' job); a distinctive
        value such as `marcomoenig` is replaced wherever it appears, including
        inside `uid=marcomoenig,ou=users,...`. Case-insensitive so a case-shifted
        variant of a structured username still maps to the same token.
        """
        for raw, token in identities.items():
            if not raw or len(raw) < 2 or raw.lower() in _COMMON_WORDS:
                continue
            if _TOKEN_RE.fullmatch(raw):
                continue  # already a token: replacing with itself is a no-op
            pattern = re.compile(
                rf"(?<!\w){re.escape(raw)}(?!\w)", re.IGNORECASE
            )
            text = pattern.sub(token, text)
        return text

    def mask_overview(self, result: Any) -> Any:
        """Mask the PII-bearing keys of a parsed findings Overview.

        Agent names are hostnames and get the HOST placeholder; rule titles get
        the embedded value-type pass (IPs/e-mails inside them). Severity levels
        and categories are enumeration values, not personal data, and are left
        alone.
        """
        if not self.active:
            return result

        name_of: dict[str, str] = {}
        for bucket in result.agents:
            name_of.setdefault(bucket.key, self._register(HOST, bucket.key))

        return _overview.Overview(
            total=result.total,
            total_is_lower_bound=result.total_is_lower_bound,
            severity=result.severity,
            severity_other=result.severity_other,
            agents=[
                _overview.Bucket(name_of.get(b.key, b.key), b.count)
                for b in result.agents
            ],
            agents_other=result.agents_other,
            agent_cardinality=result.agent_cardinality,
            agent_severity={
                name_of.get(key, key): value
                for key, value in result.agent_severity.items()
            },
            titles=[
                _overview.Bucket(self.mask_text(b.key), b.count)
                for b in result.titles
            ],
            titles_other=result.titles_other,
            title_cardinality=result.title_cardinality,
            categories=result.categories,
            categories_other=result.categories_other,
        )

    # ------------------------------------------------------------------ #
    # Text pass (safety net)
    # ------------------------------------------------------------------ #

    def mask_text(
        self, text: str, identities: Mapping[str, str] | None = None
    ) -> str:
        """Mask personal data anywhere in rendered output.

        E-mails, then IP addresses, then usernames in their log context. The
        order matters: the username pass runs after the value-type passes so a
        source address can never be captured as a username. When
        `mask_free_text_users` is on, the broader username context patterns and
        the per-response known-identity registry are applied as well.
        """
        if not text:
            return text
        text = _EMAIL_RE.sub(lambda m: self._register(_EMAIL, m.group(0)), text)
        text = _IPV6_RE.sub(lambda m: self._register(_IP, m.group(0)), text)
        text = _IPV4_RE.sub(lambda m: self._register(_IP, m.group(0)), text)
        if self.config.mask_free_text_users:
            # Known identities first: a case-shifted or Unicode variant of a
            # structured username reuses the exact structured token before any
            # context pattern re-tokenises it from the literal text.
            if identities:
                text = self._replace_known_identities(text, identities)
            text = _USERNAME_NOUN_RE.sub(self._mask_username, text)
            text = _USERNAME_AUTH_RE.sub(self._mask_username, text)
            for pattern in _USERNAME_CONTEXT_PATTERNS:
                text = pattern.sub(self._mask_username, text)
        else:
            text = _USERNAME_NOUN_RE.sub(self._mask_username, text)
            text = _USERNAME_AUTH_RE.sub(self._mask_username, text)
        return text

    def _mask_username(self, match: re.Match[str]) -> str:
        """Replace only the username capture inside a context match.

        `match.start`/`match.end` are offsets into the full string; the spans
        have to be translated to be relative to the matched substring, which is
        what re.sub substitutes back.
        """
        base = match.start(0)
        start, end = match.span("name")
        name = match.group("name")
        if _TOKEN_RE.fullmatch(name):
            # Already a Klaxon token: leave the match untouched (idempotent).
            return match.group(0)
        return (
            match.group(0)[: start - base]
            + self._register(_USER, name)
            + match.group(0)[end - base :]
        )

    # ------------------------------------------------------------------ #
    # Verify + block
    # ------------------------------------------------------------------ #

    def verify(self, text: str) -> list[str]:
        """Scan for anything the masker should have caught but did not.

        Scoped to the value types the masker guarantees — IP addresses and
        e-mails — because those are the ones a residual is unambiguous for. A
        hostname in a URL or an index name is not a residual; an IP address is.
        """
        found: list[str] = []
        if _EMAIL_RE.search(text):
            found.append(_EMAIL)
        if _IPV4_RE.search(text) or _IPV6_RE.search(text):
            found.append(_IP)
        return found

    def finish(self, tool: str, raw: str, masked: str) -> str:
        """Verify, block-or-return, log. Returns the string the tool returns.

        `raw` is the unmasked output and is logged only when RAW logging is on;
        `masked` is the fully masked output the caller returns.
        """
        residuals = self.verify(masked)
        blocked = bool(residuals) and self.config.whitelist_enabled
        self._log_exchange(tool, raw, masked, residuals=residuals, blocked=blocked)
        if blocked:
            with self._lock:
                self._blocked += 1
                self._blocked_per_tool[tool] += 1
            logger.warning(
                "blocked %s response: residual PII (%s) after anonymization; "
                "response withheld. See %s.",
                tool,
                ", ".join(residuals),
                self.config.log_path,
            )
            return self._block_notice(tool, residuals)
        return masked

    def _block_notice(self, tool: str, residuals: list[str]) -> str:
        return (
            "=== GDPR BLOCKED BY KLAXON ANONYMIZATION ===\n"
            f"[BLOCKED] The {tool} response still contained unmasked PII "
            f"({', '.join(residuals)}) after anonymization. To keep personal data "
            f"from leaving the network the response was withheld. The exchange was "
            f"logged to {self.config.log_path}. This is a masking gap, not a "
            f"prompt that can be reworded — review the anonymization rules and "
            f"the raw data before retrying."
        )

    # ------------------------------------------------------------------ #
    # Audit logging
    # ------------------------------------------------------------------ #

    def _clip(self, text: str) -> str:
        limit = self.config.log_max_len
        if limit <= 0 or len(text) <= limit:
            return text
        return f"{text[:limit]}…[truncated {len(text)} chars]"

    def _log_exchange(
        self,
        tool: str,
        raw: str,
        masked: str,
        *,
        residuals: list[str],
        blocked: bool,
    ) -> None:
        with self._lock:
            self._exchanges += 1
            self._per_tool[tool] += 1

        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        lines: list[str] = []
        if self.config.log_raw:
            lines.append(f"{ts} - [EXTERNAL_LLM] - {tool} RAW: {self._clip(raw)}")
        if blocked:
            lines.append(
                f"{ts} - [EXTERNAL_LLM] - {tool} BLOCKED: residual PII "
                f"({', '.join(residuals)}) after anonymization; response withheld."
            )
        else:
            lines.append(f"{ts} - [EXTERNAL_LLM] - {tool} MASKED: {self._clip(masked)}")
        self._write(lines)

    def _write(self, lines: list[str]) -> None:
        path = self.config.log_path
        try:
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            with self._lock, open(path, "a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
        except OSError as exc:
            logger.error("could not write anonymization log %s: %s", path, exc)

    # ------------------------------------------------------------------ #
    # Status, compliance report, export
    # ------------------------------------------------------------------ #

    def status_text(self) -> str:
        """Short human-readable state, safe to show an external model."""
        if not self.config.enabled:
            return (
                "Anonymization: DISABLED. Set KLAXON_ANONYMIZE_EXTERNAL_LLM=true "
                "to mask personal data before tool results go to the chat model."
            )
        if self.config.llm_is_local:
            mode = "LOCAL model — tool results pass through unchanged"
        else:
            mode = "EXTERNAL model — tool results are masked"
        endpoint = self.config.llm_base_url or "(unknown — assumed external)"
        return "\n".join(
            [
                "Anonymization: ENABLED",
                f"  LLM base URL:      {endpoint}",
                f"  classification:    {mode}",
                f"  tokens:            HMAC-SHA256 (use_hash={self.config.use_hash}, "
                f"salt={'set' if self.config.salt else 'per-process'})",
                f"  free-text users:   {self.config.mask_free_text_users}",
                f"  whitelist (block on residual PII): {self.config.whitelist_enabled}",
                f"  prompt log:        {self.config.log_path}",
            ]
        )

    def report_text(self) -> str:
        """The DSGVO/GDPR compliance report. Placeholders and counts only — no
        raw personal data, so the report is safe to share with auditors."""
        with self._lock:
            exchanges = self._exchanges
            blocked = self._blocked
            per_tool = dict(self._per_tool)
            blocked_tools = dict(self._blocked_per_tool)
            counts = {kind: dict(self._counts[kind]) for kind in _NO_HASH_LABELS}
            field_hits = dict(self._field_hits)

        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        active = self.config.enabled and not self.config.llm_is_local
        mode = (
            "LOCAL — masking not applied"
            if self.config.llm_is_local and self.config.enabled
            else ("EXTERNAL — masking applied" if active else "disabled")
        )
        lines = [
            "Klaxon DSGVO/GDPR Anonymization Report",
            "=======================================",
            f"generated:            {now}",
            f"anonymization:        {mode}",
            f"master switch:        KLAXON_ANONYMIZE_EXTERNAL_LLM="
            f"{str(self.config.enabled).lower()}",
            f"LLM base URL:         {self.config.llm_base_url or '(unset — assumed external)'}",
            f"token derivation:     HMAC-SHA256 (use_hash={self.config.use_hash}, "
            f"salt={'set' if self.config.salt else 'per-process'})",
            f"whitelist (block):    {self.config.whitelist_enabled}",
            f"prompt log:           {self.config.log_path}",
            f"raw output logged:    {self.config.log_raw}",
            "",
            "Exchanges since server start:",
            f"  processed:  {exchanges}",
            f"  blocked:    {blocked}",
            "  per tool:",
        ]
        if per_tool:
            for tool in sorted(per_tool):
                blocked_here = blocked_tools.get(tool, 0)
                blocked_suffix = f" ({blocked_here} blocked)" if blocked_here else ""
                lines.append(f"    {tool}: {per_tool[tool]}{blocked_suffix}")
        else:
            lines.append("    (none)")

        lines.extend(["", "Values masked by type (distinct / occurrences):"])
        any_masked = False
        for kind in (IP, HOST, USER, AGENT, EMAIL):
            by_value = counts[kind]
            if not by_value:
                continue
            any_masked = True
            total = sum(by_value.values())
            example = next(iter(by_value))
            lines.append(
                f"  {kind:<6} {len(by_value):>4} distinct / {total:>5} occurrences"
                f"  (e.g. {self._token(kind, example)})"
            )
        if not any_masked:
            lines.append("  (nothing masked yet)")

        if field_hits:
            lines.extend(["", "Masked fields (hits by configured field):"])
            for field in sorted(field_hits, key=lambda f: -field_hits[f]):
                lines.append(f"  {field}: {field_hits[field]}")
        return "\n".join(lines)

    @classmethod
    def export_masked_log(cls, log_path: str, out_path: str | None = None) -> str:
        """Re-emit the anonymized (MASKED/BLOCKED) lines of the prompt log.

        RAW lines are dropped, so the export contains no unmasked personal data
        and is the artifact to hand over for data-subject access requests
        (Auskunftsanfragen). Returns the text; when out_path is given it is
        also written there.
        """
        kept: list[str] = []
        # A RAW line is identified by its header, not by the substring: a MASKED
        # line whose JSON body happens to contain " RAW:" is not a raw log line
        # and must be kept.
        raw_header = re.compile(r"\[EXTERNAL_LLM\] - \S+ RAW: ")
        try:
            with open(log_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if raw_header.search(line):
                        continue
                    kept.append(line.rstrip("\n"))
        except OSError as exc:
            return f"export failed: {exc}"
        text = "\n".join(kept) + ("\n" if kept else "")
        if out_path:
            try:
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(text)
            except OSError as exc:
                return f"export failed: {exc}"
        return text
