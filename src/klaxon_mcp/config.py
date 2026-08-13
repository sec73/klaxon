# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Configuration. Environment only — nothing hardcoded, nothing in code.

The anonymization block is the one section that can also come from an optional
YAML file (KLAXON_CONFIG, default ./config.yaml). Precedence is always
environment > YAML > default, so the environment stays authoritative even when
a config file is present.
"""

from __future__ import annotations

import logging
import os
import re
import secrets
from dataclasses import dataclass
from typing import Any, Literal, get_args

from .constants import DEFAULT_TRACE_LEVEL
from .envutil import (
    LOOPBACK_HOSTS,
    ConfigError,
    _env_bool,
    _env_bool_strict,
    _env_float,
    _env_int,
    _env_list,
    _env_str,
    _is_loopback_url,
    _load_yaml_file,
    _section,
    _yaml_get,
)
from .field_kinds import DEFAULT_ANONYMIZATION_MASK_FIELDS
from .tokens import weak_salt

# Explicit re-export for mypy strict: these are the names other modules (and
# tests) import from klaxon_mcp.config.
__all__ = [
    "AnonymizationConfig",
    "Config",
    "ConfigError",
    "GdprConfig",
    "Transport",
    "TransportConfig",
    "quarantine_pattern_overlap",
]

logger = logging.getLogger("klaxon_mcp.config")

Transport = Literal["stdio", "http", "sse"]


def _anonymization_yaml(path: str) -> dict[str, Any] | None:
    """Read the `anonymization:` section of an optional YAML config file."""
    return _section(_load_yaml_file(path), "anonymization")


def _gdpr_yaml(path: str) -> dict[str, Any] | None:
    """Read the `gdpr_checker:` section of an optional YAML config file."""
    return _section(_load_yaml_file(path), "gdpr_checker")


def _resolve_salt(config_file: str) -> str:
    """The HMAC salt: environment first, then a persisted file, then a new one.

    `KLAXON_ANONYMIZATION_SALT` is authoritative when set. Otherwise a salt
    persisted next to the config file (`<config_file>.salt`) is reused, so tokens
    stay deterministic across restarts; when neither exists a random salt is
    generated and persisted (with a warning). The salt is never logged and is a
    secret — `.salt` files are gitignored. A configured salt shorter than 32 hex
    chars (16 bytes / 128 bits) is weak for the HMAC key and triggers a startup
    warning (see `weak_salt`).
    """
    env_salt = _env_str("KLAXON_ANONYMIZATION_SALT", None)
    if env_salt:
        if weak_salt(env_salt):
            logger.warning(
                "KLAXON_ANONYMIZATION_SALT is set but shorter than 32 hex chars "
                "(16 bytes / 128 bits). The salt is the HMAC key; a weak salt "
                "makes enumerable values (usernames, internal IPs) easy to "
                "re-identify by brute force. Generate one with "
                "`python -c \"import secrets; print(secrets.token_hex(32))\"` "
                "(256 bits) and rotate it as a secret."
            )
        return env_salt
    path = f"{config_file}.salt"
    try:
        with open(path, "r", encoding="ascii") as fh:
            existing = fh.read().strip()
        if existing:
            return existing
    except OSError:
        pass
    generated = secrets.token_hex(32)
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="ascii") as fh:
            fh.write(generated + "\n")
        os.chmod(path, 0o600)
    except OSError as exc:
        logger.warning(
            "KLAXON_ANONYMIZATION_SALT is not set and no salt could be persisted "
            "to %s (%s); a random per-process salt will be used, so tokens rotate "
            "on every restart. Set KLAXON_ANONYMIZATION_SALT to a stable secret.",
            path,
            exc,
        )
        return ""
    logger.warning(
        "KLAXON_ANONYMIZATION_SALT is not set. A random salt was generated and "
        "persisted to %s so tokens stay deterministic across restarts. That file "
        "is a secret — keep it out of backups and set KLAXON_ANONYMIZATION_SALT "
        "if you want the secret in the environment instead of on disk.",
        path,
    )
    return generated


# --------------------------------------------------------------------------- #
# Quarantine / masked_streams fail-closed guard
#
# The Option B quarantine stream (klaxon-quarantine-<tenant>-v5-*) holds RAW
# masking-failure documents. `masked_streams` is the LLM allowlist: the response
# layer passes those streams' values through unchanged, trusting them to be
# pre-masked. If a masked_streams pattern could ever match the quarantine
# namespace, an LLM query would read RAW data through Klaxon — refuse to start.
# Quarantine is NEVER generated into masked_streams (see build_config_fragment);
# this guard catches a hand-edit or env override that adds it back.
# --------------------------------------------------------------------------- #

# Representative quarantine index names across tenant shapes. A masked_streams
# pattern overlapping the quarantine namespace matches at least one of these
# (tenant-specific patterns AND broad patterns like `klaxon-*`).
_QUARANTINE_PROBE_NAMES = (
    "klaxon-quarantine-a-v5-000001",
    "klaxon-quarantine-customer-a-v5-000001",
    "klaxon-quarantine-customer-a-v5-raw",
    "klaxon-quarantine-z-v5-000001",
    "klaxon-quarantine-other-b-v5-000001",
)


def _index_pattern_regex(pattern: str) -> re.Pattern[str]:
    """Translate an index pattern glob (`*`/`?`) into an anchored regex."""
    out = ["^"]
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    out.append("$")
    return re.compile("".join(out))


def quarantine_pattern_overlap(pattern: str) -> bool:
    """Whether an index pattern could match the klaxon-quarantine-* namespace.

    Used to refuse startup when a `masked_streams` entry would let an LLM query
    read quarantine (raw) data through Klaxon. Also exported for tests.
    """
    rx = _index_pattern_regex(pattern)
    return any(rx.match(name) is not None for name in _QUARANTINE_PROBE_NAMES)


# The default anonymization mask list lives in field_kinds — the single home
# for field classification shared with the anonymizer and the GDPR checker.


@dataclass(frozen=True)
class AnonymizationConfig:
    """PII anonymization for non-local LLM clients.

    Environment-driven, with the optional YAML file as the second tier. The one
    field that matters for the security story is `enabled` (env
    KLAXON_ANONYMIZE_EXTERNAL_LLM): when false, no tool output is ever touched.
    When true, output is masked unless the LLM endpoint is provably local.

    `llm_base_url` is how the server distinguishes a local model from a cloud
    one. An endpoint on loopback (Ollama, vLLM on localhost) means the client
    model never leaves the machine, so data is left unchanged. An unknown
    endpoint is treated as external — the GDPR-safe default, because failing to
    mask is the expensive failure.
    """

    enabled: bool = False
    llm_base_url: str = ""
    use_hash: bool = True
    # HMAC secret for token derivation (KLAXON_ANONYMIZATION_SALT, or a salt
    # persisted next to the config file). Never logged; empty falls back to a
    # per-process random salt (see anonymization._process_salt).
    salt: str = ""
    mask_fields: tuple[str, ...] = DEFAULT_ANONYMIZATION_MASK_FIELDS
    # Mask the `key` values of aggregation buckets (terms / significant_terms /
    # significant_text / multi_terms / composite) in `search` responses when the
    # aggregation's source field is in `mask_fields`. ON by default (fail-closed:
    # a terms/composite on `related.user` or `related.hosts` returns raw values
    # otherwise — the same PII the `_source` pass masks). Set
    # KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS=false to restore the
    # pre-feature behaviour. Keys of non-field aggregations (date_histogram,
    # histogram, range, filters, metrics) are never touched. Aggregation keys
    # and `_source` values use the same deterministic tokens, so the two stay
    # aligned for one entity.
    mask_aggregation_keys: bool = True
    # Mask usernames that appear inside free-text fields (message, event.original,
    # ...) using known identities from the structured fields plus precise context
    # patterns (uid=..., "for user ...", "Accepted publickey for ..."). On by
    # default (the LLM-safe reading); false restores the pre-feature behaviour.
    mask_free_text_users: bool = True
    # Extra free-text fields, beyond the built-in free-text hint pattern
    # (message, *.log, raw, ...), that get the free-text username pass.
    mask_free_text_fields: tuple[str, ...] = ()
    # Data streams that are already masked at ingest (Option B, e.g.
    # klaxon-masked-<tenant>-v5*). The response layer passes already-tokenized
    # values through unchanged, so masking is idempotent for these streams.
    masked_streams: tuple[str, ...] = ()
    # Whitelist semantics for this server: only responses that mask cleanly go
    # out. true => a residual PII hit blocks the response entirely; false => it
    # is logged as a warning and the masked response is still returned.
    whitelist_enabled: bool = True
    log_path: str = "llm_prompts.log"
    log_raw: bool = False
    log_max_len: int = 20_000
    config_file: str = "config.yaml"

    @property
    def llm_is_local(self) -> bool:
        """Whether the configured LLM endpoint is on loopback."""
        return _is_loopback_url(self.llm_base_url)

    @property
    def active(self) -> bool:
        """The anonymization switch for the current LLM, all tiers applied.

        enabled=false: never active. enabled=true: active unless the LLM is
        provably local. An unknown endpoint is treated as external.
        """
        if not self.enabled:
            return False
        if not self.llm_base_url:
            return True
        return not self.llm_is_local

    @classmethod
    def from_env(cls) -> AnonymizationConfig:
        config_file = _env_str("KLAXON_CONFIG", "config.yaml") or "config.yaml"
        anon_yaml = _anonymization_yaml(config_file)

        enabled = _env_bool_strict(
            "KLAXON_ANONYMIZE_EXTERNAL_LLM", _yaml_get(anon_yaml, "enabled", False)
        )
        llm_base_url = _env_str(
            "KLAXON_LLM_BASE_URL", _yaml_get(anon_yaml, "llm_base_url", "")
        ) or ""

        salt = _resolve_salt(config_file)

        raw_free_text = _env_str("KLAXON_ANONYMIZATION_MASK_FREE_TEXT_FIELDS", None)
        if raw_free_text is None:
            yaml_ft = _yaml_get(anon_yaml, "mask_free_text_fields", None)
            if isinstance(yaml_ft, (list, tuple)):
                mask_free_text_fields = tuple(
                    str(f).strip() for f in yaml_ft if str(f).strip()
                )
            else:
                mask_free_text_fields = ()
        else:
            mask_free_text_fields = tuple(
                f.strip() for f in raw_free_text.split(",") if f.strip()
            )

        # Fail-closed drift guard: the environment override was the known
        # silent-bypass vector against the generated Option B config. If both the
        # env var and the YAML file define mask_fields and they differ, refuse to
        # start instead of silently overriding the file.
        raw_fields = _env_str("KLAXON_ANONYMIZATION_MASK_FIELDS", None)
        yaml_fields = _yaml_get(anon_yaml, "mask_fields", None)
        yaml_fields_tuple: tuple[str, ...] = ()
        if isinstance(yaml_fields, (list, tuple)):
            yaml_fields_tuple = tuple(
                str(f).strip() for f in yaml_fields if str(f).strip()
            )
        if raw_fields is not None:
            env_fields = tuple(
                f.strip() for f in raw_fields.split(",") if f.strip()
            )
            if yaml_fields_tuple and env_fields != yaml_fields_tuple:
                raise ConfigError(
                    "KLAXON_ANONYMIZATION_MASK_FIELDS is set and differs from "
                    "anonymization.mask_fields in the config file. The environment "
                    "is a drift vector against the generated masked-stream config: "
                    "align the two (edit tenants/<tenant>/fields.yaml and "
                    "regenerate), or unset the variable so the file wins. See "
                    "docs/option-b-masked-stream.md."
                )
            mask_fields = env_fields
        elif yaml_fields_tuple:
            mask_fields = yaml_fields_tuple
        else:
            mask_fields = DEFAULT_ANONYMIZATION_MASK_FIELDS

        raw_streams = _env_str("KLAXON_ANONYMIZATION_MASKED_STREAMS", None)
        if raw_streams is None:
            yaml_streams = _yaml_get(anon_yaml, "masked_streams", None)
            if isinstance(yaml_streams, (list, tuple)):
                masked_streams = tuple(
                    str(s).strip() for s in yaml_streams if str(s).strip()
                )
            else:
                masked_streams = ()
        else:
            masked_streams = tuple(
                s.strip() for s in raw_streams.split(",") if s.strip()
            )

        # Fail-closed: `masked_streams` is the LLM allowlist. If any pattern
        # could match the quarantine stream (raw masking-failure documents), an
        # LLM query would read RAW data through Klaxon — refuse to start/serve.
        # Quarantine is NEVER generated into masked_streams; this catches a
        # hand-edit or env override that adds it back.
        for stream in masked_streams:
            if quarantine_pattern_overlap(stream):
                raise ConfigError(
                    f"masked_streams pattern {stream!r} could match the "
                    "quarantine stream (klaxon-quarantine-<tenant>-v5-*), which "
                    "holds RAW masking-failure documents and must never reach an "
                    "LLM through Klaxon. Remove the pattern — quarantine is never "
                    "added to masked_streams (see docs/option-b-masked-stream.md)."
                )

        log_max_len = _env_int(
            "KLAXON_ANONYMIZATION_LOG_MAX_LEN",
            _yaml_get(anon_yaml, "log_max_len", 20_000),
        )
        if isinstance(log_max_len, bool) or not isinstance(log_max_len, int):
            log_max_len = 20_000
        if log_max_len < 0:
            raise ConfigError("KLAXON_ANONYMIZATION_LOG_MAX_LEN must be >= 0")

        log_path = _env_str(
            "KLAXON_ANONYMIZATION_LOG",
            _yaml_get(anon_yaml, "log_path", "llm_prompts.log"),
        ) or "llm_prompts.log"

        return cls(
            enabled=enabled,
            llm_base_url=llm_base_url,
            use_hash=_env_bool(
                "KLAXON_ANONYMIZATION_USE_HASH",
                _yaml_get(anon_yaml, "use_hash", True),
            ),
            salt=salt,
            mask_fields=mask_fields,
            mask_aggregation_keys=_env_bool_strict(
                "KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS",
                _yaml_get(anon_yaml, "mask_aggregation_keys", True),
            ),
            mask_free_text_users=_env_bool_strict(
                "KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS",
                _yaml_get(anon_yaml, "mask_free_text_users", True),
            ),
            mask_free_text_fields=mask_free_text_fields,
            masked_streams=masked_streams,
            whitelist_enabled=_env_bool_strict(
                "KLAXON_ANONYMIZATION_WHITELIST_ENABLED",
                _yaml_get(anon_yaml, "whitelist_enabled", True),
            ),
            log_path=log_path,
            log_raw=_env_bool_strict(
                "KLAXON_ANONYMIZATION_LOG_RAW",
                _yaml_get(anon_yaml, "log_raw", False),
            ),
            log_max_len=log_max_len,
            config_file=config_file,
        )


# The frozen default shared by every Config that does not say otherwise. Frozen
# means it is safe to share: nothing can mutate it.
_DEFAULT_ANONYMIZATION = AnonymizationConfig()


# Built-in GDPR checker custom rules. `user.effective.name` holds values like
# "root(uid=0)" that the generic user.name name-pattern misses; pinning it as a
# high-priority username makes the checker report it (and, once it is in
# mask_fields, as covered). Operator rules from the YAML file are merged on top.
DEFAULT_GDPR_CUSTOM_PATTERNS: tuple[dict[str, Any], ...] = (
    {"field": "user.effective.name", "type": "USERNAME", "priority": "high"},
)


@dataclass(frozen=True)
class GdprConfig:
    """Settings for the DSGVO plausibility checker (`gdpr_check` tool / CLI).

    Environment-driven like everything else, with the optional YAML file
    (KLAXON_CONFIG, `gdpr_checker:` block) as the second tier. Custom rules are
    YAML-only — a rule is structured data (field, type, priority, regex) that
    does not fit an environment variable.
    """

    log_path: str = "gdpr_check.log"
    report_path: str = "gdpr_compliance_report.json"
    # How many documents to sample for content-based classification.
    sample_size: int = 10
    # When true, `search` appends a DSGVO notice naming sensitive fields that
    # appear in the hits. Cheap: a name-pattern scan, no extra cluster calls.
    check_on_search: bool = False
    # `gdpr_checker.custom_patterns` — each: field (exact or glob), type,
    # priority (high|medium|low), optional regex validated against samples.
    # Built-in rules are always present; YAML rules are merged on top.
    custom_patterns: tuple[dict[str, Any], ...] = DEFAULT_GDPR_CUSTOM_PATTERNS
    config_file: str = "config.yaml"

    @classmethod
    def from_env(cls) -> GdprConfig:
        config_file = _env_str("KLAXON_CONFIG", "config.yaml") or "config.yaml"
        gdpr_yaml = _gdpr_yaml(config_file)

        sample_size = _env_int(
            "KLAXON_GDPR_SAMPLE_SIZE", _yaml_get(gdpr_yaml, "sample_size", 10)
        )
        if isinstance(sample_size, bool) or not isinstance(sample_size, int):
            sample_size = 10
        if sample_size < 0:
            raise ConfigError("KLAXON_GDPR_SAMPLE_SIZE must be >= 0")

        log_path = _env_str(
            "KLAXON_GDPR_CHECK_LOG",
            _yaml_get(gdpr_yaml, "log_path", "gdpr_check.log"),
        ) or "gdpr_check.log"
        report_path = _env_str(
            "KLAXON_GDPR_REPORT",
            _yaml_get(gdpr_yaml, "report_path", "gdpr_compliance_report.json"),
        ) or "gdpr_compliance_report.json"

        raw_patterns = _yaml_get(gdpr_yaml, "custom_patterns", None)
        custom: tuple[dict[str, Any], ...] = DEFAULT_GDPR_CUSTOM_PATTERNS
        if isinstance(raw_patterns, list):
            custom = DEFAULT_GDPR_CUSTOM_PATTERNS + tuple(
                p for p in raw_patterns if isinstance(p, dict)
            )

        return cls(
            log_path=log_path,
            report_path=report_path,
            sample_size=sample_size,
            check_on_search=_env_bool(
                "KLAXON_GDPR_CHECK_ON_SEARCH",
                _yaml_get(gdpr_yaml, "check_on_search", False),
            ),
            custom_patterns=custom,
            config_file=config_file,
        )


# The frozen default shared by every Config that does not say otherwise.
_DEFAULT_GDPR = GdprConfig()


@dataclass(frozen=True)
class TransportConfig:
    """How the server is served, as opposed to what it connects to.

    Kept separate from `Config` on purpose: `Config` is credentials for talking
    to Wazuh, this is the listening socket. Getting the two mixed up is how a
    SIEM ends up on a public port.
    """

    transport: Transport
    host: str
    port: int
    path: str
    auth_token: str
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    # Browser origins permitted to call the endpoint directly with XHR/fetch.
    # Empty means no CORS headers at all, which is what any client that is not a
    # browser wants — including Open WebUI, whose native MCP integration connects
    # from its backend rather than from the page (its documented
    # `host.docker.internal` guidance only makes sense server-side; the CORS
    # advice in its docs is about OpenAPI "Direct Tool Servers", a separate
    # browser-side feature). Distinct from `allowed_origins`, which only says
    # which Origin values are *not rejected* — that is a filter, this is a grant.
    cors_origins: tuple[str, ...]
    json_response: bool
    stateless: bool

    @property
    def is_networked(self) -> bool:
        """True when the server listens on anything other than loopback."""
        return self.transport != "stdio" and self.host not in LOOPBACK_HOSTS

    @property
    def is_unauthenticated_network_listener(self) -> bool:
        """The configuration that exposes Wazuh to anyone who can reach the port."""
        return self.is_networked and not self.auth_token

    @classmethod
    def from_env(cls) -> TransportConfig:
        transport = os.environ.get("WAZUH_MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in get_args(Transport):
            valid = ", ".join(get_args(Transport))
            raise ConfigError(
                f"WAZUH_MCP_TRANSPORT must be one of: {valid} (got {transport!r})"
            )

        path = os.environ.get("WAZUH_MCP_PATH", "/mcp").strip() or "/mcp"
        if not path.startswith("/"):
            path = "/" + path

        # An Origin header never carries a path, so a trailing slash here would
        # produce an entry that matches nothing — and the failure surfaces in the
        # browser console as a generic CORS error, a long way from this file.
        cors_origins = tuple(o.rstrip("/") for o in _env_list("WAZUH_MCP_CORS_ORIGINS"))
        if "*" in cors_origins:
            raise ConfigError(
                "WAZUH_MCP_CORS_ORIGINS=* is refused. Every tool here runs with "
                "the Wazuh credentials in this file, so a wildcard grant lets any "
                "page a browser loads read your SIEM from that browser's network "
                "position. List the origins that need it, comma-separated, e.g. "
                "WAZUH_MCP_CORS_ORIGINS=https://openwebui.example"
            )

        return cls(
            transport=transport,  # type: ignore[arg-type]  # checked above
            host=os.environ.get("WAZUH_MCP_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=_env_int("WAZUH_MCP_PORT", 8000),
            path=path,
            auth_token=os.environ.get("WAZUH_MCP_AUTH_TOKEN", "").strip(),
            allowed_hosts=_env_list("WAZUH_MCP_ALLOWED_HOSTS"),
            allowed_origins=_env_list("WAZUH_MCP_ALLOWED_ORIGINS"),
            cors_origins=cors_origins,
            json_response=_env_bool("WAZUH_MCP_JSON_RESPONSE", False),
            stateless=_env_bool("WAZUH_MCP_STATELESS", False),
        )


@dataclass(frozen=True)
class Config:
    """Runtime configuration, assembled from environment variables."""

    indexer_url: str
    indexer_user: str
    indexer_password: str

    manager_url: str
    manager_user: str
    manager_password: str

    # The engine's own HTTP server, which runs inside the manager container and
    # is neither the indexer nor the manager API. Empty disables `tester_sessions`.
    engine_url: str

    verify_ssl: bool
    timeout: float

    # Hard ceiling for an unfiltered schema listing. The engine schema has 2351
    # fields; an uncapped fields=* listing is unusable output.
    schema_field_limit: int

    # How many exists-aggregations to pack into one request when checking which
    # mapped fields actually carry data.
    schema_probe_batch: int

    # Ceiling for the `size` a search body may ask for. A Wazuh 5 event carries
    # roughly 40 fields, so an uncapped "size": 10000 returns more document than
    # any caller can hold. 0 or negative disables the cap.
    search_max_size: int

    # One of TRACE_LEVELS. Verified against a live 5.0 instance.
    logtest_default_trace_level: str
    logtest_default_space: str

    # PII anonymization for non-local LLM clients. Disabled by default; see
    # AnonymizationConfig for the precedence (env > YAML > default).
    anonymization: AnonymizationConfig = _DEFAULT_ANONYMIZATION

    # DSGVO plausibility checker settings; see GdprConfig.
    gdpr: GdprConfig = _DEFAULT_GDPR

    # Option B sync (`klaxon-mcp --sync-masked`). The reindex runs as an async
    # task (wait_for_completion=false) and is polled, so a proxy/LB closing a
    # long synchronous connection cannot abort a large window. `sync_reindex_timeout`
    # is the generous read/write timeout for the reindex POST and each task-poll
    # GET (the default short `timeout` would kill a long-running reindex);
    # `sync_task_timeout` is the overall deadline for the async task to complete.
    sync_reindex_timeout: float = 1800.0  # 30 min, KLAXON_SYNC_REINDEX_TIMEOUT
    sync_task_timeout: float = 3600.0  # 60 min, KLAXON_SYNC_TASK_TIMEOUT

    @classmethod
    def from_env(cls) -> Config:
        indexer_url = os.environ.get("WAZUH_INDEXER_URL", "").strip().rstrip("/")
        if not indexer_url:
            raise ConfigError(
                "WAZUH_INDEXER_URL is required (e.g. https://indexer.example:9200). "
                "See .env.example."
            )

        manager_url = os.environ.get("WAZUH_MANAGER_URL", "").strip().rstrip("/")
        engine_url = os.environ.get("WAZUH_ENGINE_URL", "").strip().rstrip("/")

        verify_ssl = _env_bool("WAZUH_VERIFY_SSL", True)
        if not verify_ssl:
            # The transport layer is loud about the listening socket; this is
            # the same statement about the outbound one. Every request carries
            # the credentials below, so an unverified connection hands them to
            # anyone in a position to answer for the indexer or the manager.
            logger.warning(
                "WAZUH_VERIFY_SSL=false disables TLS certificate verification for "
                "the indexer, manager and engine connections. The credentials in "
                "this configuration are sent on every request, so anyone able to "
                "intercept or impersonate those endpoints can take them and read "
                "the SIEM. Acceptable against a self-signed lab cluster; in "
                "production, trust the cluster CA on this host instead."
            )

        search_max_size = _env_int("WAZUH_SEARCH_MAX_SIZE", 100)
        if search_max_size <= 0:
            # Disabling it is a legitimate choice for a caller that pages its own
            # way through a result set, but it is not a state to discover from an
            # unusable response — say it once, at startup.
            logger.warning(
                "WAZUH_SEARCH_MAX_SIZE=%d disables the search result cap. A body "
                'asking for "size": 10000 will now return 10000 full documents.',
                search_max_size,
            )

        return cls(
            indexer_url=indexer_url,
            indexer_user=os.environ.get("WAZUH_INDEXER_USER", ""),
            indexer_password=os.environ.get("WAZUH_INDEXER_PASSWORD", ""),
            manager_url=manager_url,
            manager_user=os.environ.get("WAZUH_MANAGER_USER", ""),
            manager_password=os.environ.get("WAZUH_MANAGER_PASSWORD", ""),
            engine_url=engine_url,
            verify_ssl=verify_ssl,
            timeout=_env_float("WAZUH_TIMEOUT", 60.0),
            sync_reindex_timeout=_env_float("KLAXON_SYNC_REINDEX_TIMEOUT", 1800.0),
            sync_task_timeout=_env_float("KLAXON_SYNC_TASK_TIMEOUT", 3600.0),
            schema_field_limit=_env_int("WAZUH_SCHEMA_FIELD_LIMIT", 200),
            schema_probe_batch=_env_int("WAZUH_SCHEMA_PROBE_BATCH", 100),
            search_max_size=search_max_size,
            logtest_default_trace_level=os.environ.get(
                "WAZUH_LOGTEST_TRACE_LEVEL", DEFAULT_TRACE_LEVEL
            ),
            logtest_default_space=os.environ.get("WAZUH_LOGTEST_SPACE", "custom"),
            anonymization=AnonymizationConfig.from_env(),
            gdpr=GdprConfig.from_env(),
        )
