# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Live-test credential resolution (env + local dotenv).

Reads the `KLAXON_INDEXER_*` environment (optionally loading a gitignored
local `KEY=VALUE` file) into a `LiveIndexerConfig`. Nothing here ever prints a
password: the URL is sanitised via `safe_url` and the password is only ever
held in the config object. Reused by `klaxon masking test` (live_test.py) and
the integration/live pytest markers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# The credential env vars — the ONLY source of live-test credentials.
LIVE_ENV_URL = "KLAXON_INDEXER_URL"
LIVE_ENV_USER = "KLAXON_INDEXER_USER"
LIVE_ENV_PASSWORD = "KLAXON_INDEXER_PASSWORD"
LIVE_ENV_NAMES: tuple[str, ...] = (LIVE_ENV_URL, LIVE_ENV_USER, LIVE_ENV_PASSWORD)

# Optional, NON-credential TLS knob (default true = verify, the secure default;
# mirror of the WAZUH_VERIFY_SSL used by the main clients). Set false only for
# a self-signed lab cluster — the test warns. The skip gate depends ONLY on the
# three credential vars above.
LIVE_ENV_VERIFY_SSL = "KLAXON_INDEXER_VERIFY_SSL"

# Local dotenv candidates (both gitignored; never committed).
ENV_FILE_CANDIDATES: tuple[str, ...] = (".env.live", "tests/live/.env")

# Salt for the live run when neither `--salt` nor the env salt is set. Expected
# tokens are derived in-process with the SAME salt, so any value is deterministic;
# the env salt is preferred so the test mirrors what the operator deploys.
DEFAULT_TEST_SALT = "klaxon-masking-live-test-fixed"


@dataclass(frozen=True)
class LiveIndexerConfig:
    """Resolved indexer credentials (never serialised, never logged)."""

    url: str
    user: str
    password: str
    # TLS verification for the test connection; False only for self-signed labs.
    verify_ssl: bool = True


class LiveTestError(RuntimeError):
    """A hard failure while talking to the live indexer (never carries secrets)."""


# --------------------------------------------------------------------------- #
# Credential resolution (env / local .env) — no secrets are ever printed
# --------------------------------------------------------------------------- #


def load_dotenv_file(path: str | Path) -> None:
    """Parse a `KEY=VALUE` file into the environment WITHOUT overriding existing
    vars (env wins). Blank lines and `#` comments are ignored; an optional
    `export ` prefix and surrounding quotes are stripped. Values are never
    printed here or anywhere in this module."""
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def find_env_file(override: str | Path | None = None) -> Path | None:
    """The local credentials file to load, or None. Explicit `--env FILE` wins;
    otherwise the first existing gitignored candidate."""
    if override:
        p = Path(override)
        return p if p.is_file() else None
    for candidate in ENV_FILE_CANDIDATES:
        p = Path(candidate)
        if p.is_file():
            return p
    return None


def _env_bool(name: str, default: bool) -> bool:
    """Parse a boolean env var; unrecognised values fall back to `default`.

    NOTE: deliberately NOT the same contract as `envutil._env_bool` (which
    returns False for an unrecognised non-empty value). The live-test knob
    keeps its historical fail-safe: `KLAXON_INDEXER_VERIFY_SSL=bogus` must fall
    back to the secure default (verify), not to no-verify.
    """
    raw = os.environ.get(name, "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def _url_has_embedded_credentials(url: str) -> bool:
    parts = urlsplit(url)
    return parts.username is not None or parts.password is not None


def safe_url(url: str) -> str:
    """Strip any userinfo so a URL with embedded credentials is never logged."""
    parts = urlsplit(url)
    if parts.username is None and parts.password is None:
        return url
    host = parts.hostname or ""
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return f"{parts.scheme}://{host}{parts.path or ''}"


def resolve_live_config(
    env_file: str | Path | None = None,
) -> tuple[LiveIndexerConfig | None, tuple[str, ...]]:
    """Resolve the live-test credentials.

    Loads the local dotenv (if present), then reads the three `KLAXON_INDEXER_*`
    vars. Returns `(None, missing_names)` — never the password — when any of the
    three is unset, so callers can skip cleanly instead of failing the suite.
    """
    dotenv_path = find_env_file(env_file)
    if dotenv_path is not None:
        load_dotenv_file(dotenv_path)
    missing = tuple(
        name for name in LIVE_ENV_NAMES if not os.environ.get(name, "").strip()
    )
    if missing:
        return None, missing
    return (
        LiveIndexerConfig(
            url=os.environ[LIVE_ENV_URL].strip(),
            user=os.environ[LIVE_ENV_USER].strip(),
            password=os.environ[LIVE_ENV_PASSWORD],
            verify_ssl=_env_bool(LIVE_ENV_VERIFY_SSL, default=True),
        ),
        (),
    )


def live_salt(
    cfg: Any, explicit: str | None = None, salt_env_override: str | None = None
) -> str:
    """The salt the live run derives expected tokens with: `--salt`, else the
    env salt (`salt_env` from fields.yaml), else a fixed test salt. Never warns
    (a random salt warning only matters when one is baked into a deployable)."""
    if explicit:
        return explicit
    name = salt_env_override or cfg.salt_env
    env = os.environ.get(name, "").strip()
    return env or DEFAULT_TEST_SALT
