# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Environment + YAML configuration primitives.

Leaf helpers for the env-driven configuration layer: strict and non-strict
environment parsers, the loopback URL test, and the tolerant YAML loader.
`ConfigError` is the package-wide configuration exception, owned here so the
helpers that raise it do not import from `config` (which would cycle).
"""

from __future__ import annotations

import os
import urllib.parse
from typing import Any


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or malformed."""


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


# --------------------------------------------------------------------------- #
# Canonical KLAXON_* namespace (single source)
#
# Klaxon is configured by its own name (KLAXON_*), not by the system it talks
# to. Every env read goes through `_get_env`, which reads ONLY the canonical
# KLAXON_<NAME> name — the legacy WAZUH_* spellings were fully removed and must
# not reappear (the CI grep check in tests/test_envutil.py forbids them).
# --------------------------------------------------------------------------- #


def _get_env(name: str, default: str | None = None) -> str | None:
    """Read a Klaxon env var (`KLAXON_*`) verbatim.

    The single choke point for every environment read. An unset or empty
    variable returns `default`, so the standard missing-env error path applies
    upstream.
    """
    return os.environ.get(name, default)


def _env_bool(name: str, default: bool) -> bool:
    raw = _get_env(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _env_bool_strict(name: str, default: bool) -> bool:
    """Boolean env var that FAILS CLOSED on an unrecognised value.

    Used for the security-critical anonymization switches. `_env_bool` treats
    anything that is not a truthy word as False, so a typo like
    `KLAXON_ANONYMIZE_EXTERNAL_LLM=treu` would silently disable masking. For
    these flags an explicit but invalid value is a configuration error, not a
    preference: refuse to start rather than serve unmasked.
    """
    raw = _get_env(name)
    if raw is None or raw.strip() == "":
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(
        f"{name} must be a boolean (true/false/1/0/yes/no/on/off), got {raw!r}"
    )


def _env_int(name: str, default: int) -> int:
    raw = _get_env(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _env_str(name: str, default: str | None) -> str | None:
    """Env value trimmed; an unset or empty variable falls back to `default`."""
    raw = _get_env(name)
    if raw is None or raw == "":
        return default
    return raw.strip()


def _env_list(name: str) -> tuple[str, ...]:
    raw = _get_env(name) or ""
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _env_float(name: str, default: float) -> float:
    raw = _get_env(name)
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


def _load_yaml_file(path: str) -> dict[str, Any] | None:
    """Read a YAML file into a dict, tolerating absence and parse errors.

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
    return data if isinstance(data, dict) else None


def _section(data: dict[str, Any] | None, name: str) -> dict[str, Any] | None:
    section = data.get(name) if data else None
    return section if isinstance(section, dict) else None
