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
import urllib.parse
from dataclasses import dataclass
from typing import Any, Literal, get_args

from .constants import DEFAULT_TRACE_LEVEL

logger = logging.getLogger("klaxon_mcp.config")

Transport = Literal["stdio", "http", "sse"]

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or malformed."""


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _env_str(name: str, default: str | None) -> str | None:
    """Env value trimmed; an unset or empty variable falls back to `default`."""
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip()


def _env_list(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


def _is_loopback_url(url: str) -> bool:
    """Whether a URL (or bare host) points at the loopback interface."""
    if not url:
        return False
    candidate = url if "://" in url else f"//{url}"
    try:
        host = urllib.parse.urlsplit(candidate).hostname
    except ValueError:
        return False
    if not host:
        return False
    return host.strip().lower().rstrip(".") in LOOPBACK_HOSTS


def _yaml_get(cfg: dict[str, Any] | None, key: str, default: Any) -> Any:
    if not cfg:
        return default
    return cfg.get(key, default)


def _anonymization_yaml(path: str) -> dict[str, Any] | None:
    """Read the `anonymization:` section of an optional YAML config file.

    Returns None when the file is absent, unreadable or has no such section.
    The YAML dependency is optional at runtime: a missing pyyaml simply means
    the file is ignored and the environment remains the only source.
    """
    try:
        import yaml
    except ImportError:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return None
    if not isinstance(data, dict):
        return None
    section = data.get("anonymization")
    return section if isinstance(section, dict) else None


# Fields treated as personal data by default. The value under each is replaced
# wholesale; the placeholder family is derived from the field name (see
# anonymization._FIELD_KIND). Every entry is dotted, so a suffix match also
# covers the nested position, e.g. "user.name" -> "source.user.name".
DEFAULT_ANONYMIZATION_MASK_FIELDS: tuple[str, ...] = (
    "source.ip",
    "destination.ip",
    "client.ip",
    "server.ip",
    "related.ip",
    "source.domain",
    "destination.domain",
    "host.hostname",
    "host.name",
    "user.name",
    "user.id",
    "source.user.name",
    "destination.user.name",
    "wazuh.agent.name",
    "wazuh.agent.id",
    "agent.name",
    "agent.id",
)


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
    hash_algorithm: Literal["md5", "sha256"] = "md5"
    mask_fields: tuple[str, ...] = DEFAULT_ANONYMIZATION_MASK_FIELDS
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

        enabled = _env_bool(
            "KLAXON_ANONYMIZE_EXTERNAL_LLM", _yaml_get(anon_yaml, "enabled", False)
        )
        llm_base_url = _env_str(
            "KLAXON_LLM_BASE_URL", _yaml_get(anon_yaml, "llm_base_url", "")
        ) or ""

        hash_algorithm = _env_str(
            "KLAXON_ANONYMIZATION_HASH_ALGORITHM",
            _yaml_get(anon_yaml, "hash_algorithm", "md5"),
        )
        if hash_algorithm is None:
            hash_algorithm = "md5"
        hash_algorithm = hash_algorithm.strip().lower()
        if hash_algorithm not in {"md5", "sha256"}:
            raise ConfigError(
                "KLAXON_ANONYMIZATION_HASH_ALGORITHM must be 'md5' or 'sha256', "
                f"got {hash_algorithm!r}"
            )

        raw_fields = _env_str("KLAXON_ANONYMIZATION_MASK_FIELDS", None)
        if raw_fields is None:
            yaml_fields = _yaml_get(anon_yaml, "mask_fields", None)
            if isinstance(yaml_fields, (list, tuple)):
                mask_fields = tuple(
                    str(f).strip() for f in yaml_fields if str(f).strip()
                )
            else:
                mask_fields = DEFAULT_ANONYMIZATION_MASK_FIELDS
        else:
            mask_fields = tuple(
                f.strip() for f in raw_fields.split(",") if f.strip()
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
            hash_algorithm=hash_algorithm,  # type: ignore[arg-type]  # checked above
            mask_fields=mask_fields,
            whitelist_enabled=_env_bool(
                "KLAXON_ANONYMIZATION_WHITELIST_ENABLED",
                _yaml_get(anon_yaml, "whitelist_enabled", True),
            ),
            log_path=log_path,
            log_raw=_env_bool(
                "KLAXON_ANONYMIZATION_LOG_RAW",
                _yaml_get(anon_yaml, "log_raw", False),
            ),
            log_max_len=log_max_len,
            config_file=config_file,
        )


# The frozen default shared by every Config that does not say otherwise. Frozen
# means it is safe to share: nothing can mutate it.
_DEFAULT_ANONYMIZATION = AnonymizationConfig()


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
            schema_field_limit=_env_int("WAZUH_SCHEMA_FIELD_LIMIT", 200),
            schema_probe_batch=_env_int("WAZUH_SCHEMA_PROBE_BATCH", 100),
            search_max_size=search_max_size,
            logtest_default_trace_level=os.environ.get(
                "WAZUH_LOGTEST_TRACE_LEVEL", DEFAULT_TRACE_LEVEL
            ),
            logtest_default_space=os.environ.get("WAZUH_LOGTEST_SPACE", "custom"),
            anonymization=AnonymizationConfig.from_env(),
        )
