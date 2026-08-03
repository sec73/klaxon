# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Configuration. Environment only — nothing hardcoded, nothing in code."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Literal, get_args

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

        return cls(
            transport=transport,  # type: ignore[arg-type]  # checked above
            host=os.environ.get("WAZUH_MCP_HOST", "127.0.0.1").strip() or "127.0.0.1",
            port=_env_int("WAZUH_MCP_PORT", 8000),
            path=path,
            auth_token=os.environ.get("WAZUH_MCP_AUTH_TOKEN", "").strip(),
            allowed_hosts=_env_list("WAZUH_MCP_ALLOWED_HOSTS"),
            allowed_origins=_env_list("WAZUH_MCP_ALLOWED_ORIGINS"),
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
        )
