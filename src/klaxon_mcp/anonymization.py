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
import json
import logging
import os
import re
import threading
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from . import overview as _overview
from .clients import Response
from .config import AnonymizationConfig

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

# Dotted field-name suffix -> placeholder family. The suffix match runs against
# the full dotted path, so "user.name" also covers "source.user.name". A
# configured mask field not listed here falls back to USER — masking it as a
# generic identifier is the safe reading.
_FIELD_KIND: dict[str, str] = {
    ".ip": IP,
    "user.name": USER,
    "user.id": USER,
    "source.user.name": USER,
    "destination.user.name": USER,
    "host.hostname": HOST,
    "host.name": HOST,
    "agent.name": HOST,
    "wazuh.agent.name": HOST,
    "agent.id": AGENT,
    "wazuh.agent.id": AGENT,
    "source.domain": HOST,
    "destination.domain": HOST,
    "url.domain": HOST,
}

# A counter per family is enough to keep the compliance report bounded.
_MAX_TRACKED_VALUES = 50_000


def _field_kind(field: str) -> str:
    """The placeholder family for a configured mask field.

    Exact keys first (user.name), then the shortest matching dotted suffix
    (".ip" catches source.ip, destination.ip, related.ip, ...). Anything unknown
    falls back to USER — masking it as a generic identifier is the safe reading.
    """
    if field in _FIELD_KIND:
        return _FIELD_KIND[field]
    for suffix, kind in _FIELD_KIND.items():
        if field.endswith(suffix):
            return kind
    return USER


# --------------------------------------------------------------------------- #
# Value-type patterns. Full-match is used for whole values, search for the
# embedded pass; both must agree on what an IPv4 address is so that verify()
# (which searches) never flags something mask_text() (which also searches)
# already replaced.
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

_EMAIL = "EMAIL"
_IP = "IP"
_USER = "USER"


class Anonymizer:
    """Mask, verify, block and log tool output for external LLM clients.

    Deterministic by construction: with hashing on, the placeholder is derived
    from the value itself (MD5 or SHA-256, first six hex digits), so the same
    input always maps to the same placeholder and no cross-request state is
    required. The in-memory counters only feed the compliance report.
    """

    def __init__(self, config: AnonymizationConfig) -> None:
        self.config = config
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

    def _placeholder(self, kind: str, value: str) -> str:
        if self.config.use_hash:
            digest = hashlib.new(
                self.config.hash_algorithm, value.encode("utf-8")
            ).hexdigest()
            return f"[{kind}_{digest[:6]}]"
        return _NO_HASH_LABELS[kind]

    def _register(self, kind: str, value: str) -> str:
        """Record a masked value for the report and return its placeholder."""
        with self._lock:
            counts = self._counts[kind]
            if len(counts) < _MAX_TRACKED_VALUES:
                counts[value] += 1
        return self._placeholder(kind, value)

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

    def _mask_string_value(self, path: str, value: str) -> str:
        """Mask a single string leaf of the response, given its dotted path."""
        if not value:
            return value

        matched = self._field_for_path(path)
        if matched is not None:
            kind, field = matched
            with self._lock:
                self._field_hits[field] += 1
            return self._register(kind, value)

        # Unconfigured field: mask by value type. Whole-value matches first
        # (a field that holds nothing but an IP is an IP), then embedded
        # occurrences inside free text.
        stripped = value.strip()
        if _EMAIL_RE.fullmatch(stripped):
            return self._register(_EMAIL, value)
        if _IPV4_RE.fullmatch(stripped) or _IPV6_RE.fullmatch(stripped):
            return self._register(_IP, value)
        if _FQDN_RE.fullmatch(stripped) and "://" not in stripped:
            return self._register(HOST, value)
        return self.mask_text(value)

    def mask_json(self, obj: Any, path: str = "") -> Any:
        """Deep-walk a parsed response and mask personal data in place-free."""
        if isinstance(obj, dict):
            return {
                key: self.mask_json(value, f"{path}.{key}" if path else key)
                for key, value in obj.items()
            }
        if isinstance(obj, list):
            # List indices do not belong to the field path.
            return [self.mask_json(item, path) for item in obj]
        if isinstance(obj, str):
            return self._mask_string_value(path, obj)
        return obj

    def mask_response(self, response: Response) -> Response:
        """A clone of the response with the JSON body masked, or the original.

        The original is returned unchanged when anonymization is inactive or the
        body is not JSON — a non-JSON body gets its free-text pass in `finish`.
        """
        if not self.active:
            return response
        parsed = response.json()
        if not isinstance(parsed, (dict, list)):
            return response
        masked = self.mask_json(parsed)
        return Response(
            response.status_code,
            json.dumps(masked, indent=2, ensure_ascii=False),
            response.url,
        )

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

    def mask_text(self, text: str) -> str:
        """Mask personal data anywhere in rendered output.

        E-mails, then IP addresses, then usernames in their log context. The
        order matters: the username pass runs after the value-type passes so a
        source address can never be captured as a username.
        """
        if not text:
            return text
        text = _EMAIL_RE.sub(lambda m: self._register(_EMAIL, m.group(0)), text)
        text = _IPV6_RE.sub(lambda m: self._register(_IP, m.group(0)), text)
        text = _IPV4_RE.sub(lambda m: self._register(_IP, m.group(0)), text)
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
        return (
            match.group(0)[: start - base]
            + self._register(_USER, match.group("name"))
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
                f"  hash placeholders: {self.config.hash_algorithm} "
                f"(use_hash={self.config.use_hash})",
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
            f"placeholder hashing:  {self.config.hash_algorithm} "
            f"(use_hash={self.config.use_hash})",
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
                f"  (e.g. {self._placeholder(kind, example)})"
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
        try:
            with open(log_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if " RAW:" in line:
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
