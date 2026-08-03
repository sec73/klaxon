# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Config.from_env, and the defaults that are security decisions.

`verify_ssl` is the one that matters here. It governs the outbound half of the
server — the connections that carry the indexer and manager credentials on every
request — and a default is what most deployments will actually run with.
"""

from __future__ import annotations

import logging

import pytest

from klaxon_mcp.config import Config, ConfigError

WAZUH_VARS = (
    "WAZUH_INDEXER_URL",
    "WAZUH_INDEXER_USER",
    "WAZUH_INDEXER_PASSWORD",
    "WAZUH_MANAGER_URL",
    "WAZUH_MANAGER_USER",
    "WAZUH_MANAGER_PASSWORD",
    "WAZUH_ENGINE_URL",
    "WAZUH_VERIFY_SSL",
    "WAZUH_TIMEOUT",
    "WAZUH_SCHEMA_FIELD_LIMIT",
    "WAZUH_SCHEMA_PROBE_BATCH",
    "WAZUH_SEARCH_MAX_SIZE",
    "WAZUH_LOGTEST_TRACE_LEVEL",
    "WAZUH_LOGTEST_SPACE",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's own .env must not decide what the defaults look like."""
    for name in WAZUH_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example:9200")


class TestVerifySsl:
    def test_defaults_to_verifying(self) -> None:
        """Off by default would hand the credentials to any on-path attacker."""
        assert Config.from_env().verify_ssl is True

    @pytest.mark.parametrize("value", ["true", "1", "yes", "on", "TRUE"])
    def test_explicit_true_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("WAZUH_VERIFY_SSL", value)
        assert Config.from_env().verify_ssl is True

    def test_disabling_it_is_possible_but_never_silent(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A self-signed lab cluster is a real case; an unannounced one is not."""
        monkeypatch.setenv("WAZUH_VERIFY_SSL", "false")
        with caplog.at_level(logging.WARNING, logger="klaxon_mcp.config"):
            config = Config.from_env()

        assert config.verify_ssl is False
        assert "WAZUH_VERIFY_SSL=false" in caplog.text
        assert "credentials" in caplog.text

    def test_verifying_says_nothing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="klaxon_mcp.config"):
            Config.from_env()
        assert caplog.text == ""


class TestRequiredAndOptional:
    def test_indexer_url_is_required(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
        with pytest.raises(ConfigError, match="WAZUH_INDEXER_URL is required"):
            Config.from_env()

    def test_urls_lose_their_trailing_slash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example:9200/")
        assert Config.from_env().indexer_url == "https://indexer.example:9200"

    def test_manager_and_engine_are_optional(self) -> None:
        config = Config.from_env()
        assert config.manager_url == ""
        assert config.engine_url == ""

    def test_disabling_the_search_cap_warns(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("WAZUH_SEARCH_MAX_SIZE", "0")
        with caplog.at_level(logging.WARNING, logger="klaxon_mcp.config"):
            config = Config.from_env()
        assert config.search_max_size == 0
        assert "disables the search result cap" in caplog.text

    def test_a_non_numeric_integer_is_a_config_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WAZUH_SEARCH_MAX_SIZE", "lots")
        with pytest.raises(ConfigError, match="must be an integer"):
            Config.from_env()
