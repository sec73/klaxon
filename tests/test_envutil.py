# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The canonical-KLAXON_* env loader, and the grep guard.

`envutil._get_env` is the SINGLE source for every Klaxon env read, reading only
the canonical `KLAXON_*` name — the legacy `WAZUH_*` spellings were fully
removed. An unset variable returns the default so the standard missing-env
error path applies upstream. The config-level behaviour (the missing-env error)
is covered in `tests/test_config.py`; here we pin the loader itself and the CI
grep check that forbids any legacy/deprecated marker from reappearing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from klaxon_mcp import envutil


class TestGetEnv:
    def test_klaxon_read_directly(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KLAXON_VERIFY_SSL", "false")
        assert envutil._get_env("KLAXON_VERIFY_SSL") == "false"

    def test_unset_returns_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("KLAXON_TIMEOUT", raising=False)
        assert envutil._get_env("KLAXON_TIMEOUT") is None
        assert envutil._get_env("KLAXON_TIMEOUT", "60") == "60"

    def test_helpers_route_through_the_loader(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # _env_* go through _get_env, so the KLAXON_ value reaches them.
        monkeypatch.setenv("KLAXON_VERIFY_SSL", "false")
        assert envutil._env_bool("KLAXON_VERIFY_SSL", True) is False

    def test_non_klaxon_name_read_verbatim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("UNRELATED_VAR", "x")
        assert envutil._get_env("UNRELATED_VAR") == "x"
        assert envutil._get_env("UNRELATED_VAR", "default") == "x"


class TestNoLegacyDirectReads:
    """Grep-based CI guard: nothing in the source tree may contain the removed
    legacy/deprecated markers. The `WAZUH_*` env namespace, the deprecated
    generator flags and the word "deprecated" are gone from the code — if any
    of them reappears (a read, a comment, a fallback constant), the build
    fails. The lowercase `wazuh-*` product names in prose are fine; the
    forbidden patterns are the uppercase legacy env names and the flags.

    The generator-flag pattern is built from two string parts on purpose, so
    the literal flag spelling exists nowhere except the release note in
    CHANGELOG.md — the guard still detects it, but never self-matches."""

    # (label, compiled pattern) — none may occur anywhere in src/.
    FORBIDDEN: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("WAZUH_LEGACY", re.compile(r"WAZUH_LEGACY")),
        ("WAZUH_INDEXER", re.compile(r"WAZUH_INDEXER")),
        ("WAZUH_MCP", re.compile(r"WAZUH_MCP")),
        ("generator flag", re.compile(r"--generate-" + r"masking")),
        ("deprecated marker", re.compile(r"deprecat", re.IGNORECASE)),
    )

    def test_no_legacy_or_deprecated_markers_in_source(self) -> None:
        src_root = Path(__file__).resolve().parents[1] / "src" / "klaxon_mcp"
        offenders: list[str] = []
        for path in sorted(src_root.glob("*.py")):
            for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1
            ):
                for label, pattern in self.FORBIDDEN:
                    if pattern.search(line):
                        offenders.append(
                            f"{path.name}:{lineno} [{label}]: {line.strip()}"
                        )
        assert not offenders, (
            "legacy/deprecated markers must not appear in source: the WAZUH_* "
            "env namespace and the deprecated generator flags were fully "
            "removed (only KLAXON_* and `masking generate` remain):\n"
            + "\n".join(offenders)
        )

    def test_the_guard_itself_detects_each_forbidden_pattern(self) -> None:
        by_label = {label: pattern for label, pattern in self.FORBIDDEN}
        samples = {
            "WAZUH_LEGACY": "_WAZUH_LEGACY_PREFIX = 'WAZUH_'",
            "WAZUH_INDEXER": 'os.environ.get("WAZUH_INDEXER_URL")',
            "WAZUH_MCP": 'os.environ.get("WAZUH_MCP_AUTH_TOKEN")',
            "generator flag": "--generate-" + "masking",
            "deprecated marker": "DEPRECATED — use `masking generate`",
        }
        for label, sample in samples.items():
            assert by_label[label].search(sample), f"guard misses {label!r}"
        # Legitimate lowercase Wazuh-product prose is NOT flagged.
        assert not by_label["WAZUH_INDEXER"].search("wazuh-events-v5-* index")
        assert not by_label["WAZUH_MCP"].search("the wazuh manager API")
