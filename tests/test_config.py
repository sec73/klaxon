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
from typing import Any

import pytest
import yaml

from klaxon_mcp import config
from klaxon_mcp.config import (
    DEFAULT_GDPR_CUSTOM_PATTERNS,
    AnonymizationConfig,
    Config,
    ConfigError,
    GdprConfig,
)

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

KLAXON_VARS = (
    "KLAXON_ANONYMIZE_EXTERNAL_LLM",
    "KLAXON_LLM_BASE_URL",
    "KLAXON_ANONYMIZATION_USE_HASH",
    "KLAXON_ANONYMIZATION_SALT",
    "KLAXON_ANONYMIZATION_MASK_FIELDS",
    "KLAXON_ANONYMIZATION_MASKED_STREAMS",
    "KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS",
    "KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS",
    "KLAXON_ANONYMIZATION_MASK_FREE_TEXT_FIELDS",
    "KLAXON_ANONYMIZATION_WHITELIST_ENABLED",
    "KLAXON_ANONYMIZATION_LOG",
    "KLAXON_ANONYMIZATION_LOG_RAW",
    "KLAXON_ANONYMIZATION_LOG_MAX_LEN",
    "KLAXON_GDPR_CHECK_LOG",
    "KLAXON_GDPR_REPORT",
    "KLAXON_GDPR_SAMPLE_SIZE",
    "KLAXON_GDPR_CHECK_ON_SEARCH",
    "KLAXON_GDPR_INDEX",
    "KLAXON_CONFIG",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """A developer's own .env must not decide what the defaults look like."""
    for name in (*WAZUH_VARS, *KLAXON_VARS):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example:9200")
    # Point the optional config file (and its auto-generated .salt) at tmp so
    # from_env() never writes salt files into the repo.
    monkeypatch.setenv("KLAXON_CONFIG", str(tmp_path / "config.yaml"))


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
        # Verify_ssl default says nothing (the salt auto-generation warning may
        # fire on a fresh config path, which is unrelated to TLS verification).
        assert "WAZUH_VERIFY_SSL" not in caplog.text


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


class TestAnonymizationDefaults:
    def test_anonymization_is_off_by_default(self) -> None:
        """The feature is opt-in: no env var, no masking, nothing touches output."""
        config = Config.from_env()
        assert config.anonymization.enabled is False
        assert config.anonymization.active is False

    def test_sensible_security_defaults(self) -> None:
        config = Config.from_env().anonymization
        # Keyed tokens, the strict whitelist and aggregation-key masking are the
        # safe (fail-closed) readings: without them a terms/composite on a masked
        # field returns raw bucket keys while `_source` is masked.
        assert config.use_hash is True
        assert config.whitelist_enabled is True
        assert config.log_raw is False
        assert config.log_path == "llm_prompts.log"
        assert config.mask_free_text_users is True
        assert config.mask_aggregation_keys is True


class TestAnonymizationEnv:
    def test_master_switch_turns_it_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZE_EXTERNAL_LLM", "true")
        assert Config.from_env().anonymization.enabled is True

    def test_external_endpoint_is_active(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZE_EXTERNAL_LLM", "true")
        monkeypatch.setenv("KLAXON_LLM_BASE_URL", "https://api.deepseek.com/v1")
        assert Config.from_env().anonymization.active is True

    def test_loopback_endpoint_means_local_model(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZE_EXTERNAL_LLM", "true")
        monkeypatch.setenv("KLAXON_LLM_BASE_URL", "http://localhost:11434")
        assert Config.from_env().anonymization.active is False

    def test_mask_fields_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "KLAXON_ANONYMIZATION_MASK_FIELDS", "source.ip,user.name, custom.field"
        )
        config = AnonymizationConfig.from_env()
        assert config.mask_fields == ("source.ip", "user.name", "custom.field")

    def test_mask_aggregation_keys_defaults_on(self) -> None:
        # Fail-closed: bucket keys must be masked unless explicitly turned off.
        assert Config.from_env().anonymization.mask_aggregation_keys is True

    def test_mask_aggregation_keys_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS", "true")
        assert AnonymizationConfig.from_env().mask_aggregation_keys is True

    def test_salt_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "super-secret")
        assert AnonymizationConfig.from_env().salt == "super-secret"

    def test_salt_is_persisted_and_reused(self, tmp_path: Any) -> None:
        first = AnonymizationConfig.from_env().salt
        second = AnonymizationConfig.from_env().salt
        assert first and first == second
        salt_file = tmp_path / "config.yaml.salt"
        assert salt_file.exists()
        assert salt_file.read_text(encoding="ascii").strip() == first

    def test_weak_salt_flags_short_env_salt(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A configured salt shorter than 32 hex chars (16 bytes / 128 bits)
        triggers a startup warning (the salt is the HMAC key)."""
        from klaxon_mcp.tokens import weak_salt

        assert weak_salt("super-secret")  # 12 chars
        assert not weak_salt("a1" * 16)  # 32 hex chars = 16 bytes
        assert not weak_salt("a1" * 32)  # 64 hex chars = 32 bytes (recommended)
        monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "super-secret")
        with caplog.at_level("WARNING", logger="klaxon_mcp.config"):
            assert AnonymizationConfig.from_env().salt == "super-secret"
        assert any("shorter than 32 hex chars" in r.message for r in caplog.records)

    def test_strong_salt_is_silent(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "a1" * 32)
        with caplog.at_level("WARNING", logger="klaxon_mcp.config"):
            assert AnonymizationConfig.from_env().salt == "a1" * 32
        assert not any("shorter than 32 hex chars" in r.message for r in caplog.records)

    def test_mask_free_text_users_defaults_on(self) -> None:
        assert Config.from_env().anonymization.mask_free_text_users is True

    def test_mask_free_text_users_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS", "false")
        assert AnonymizationConfig.from_env().mask_free_text_users is False

    def test_mask_free_text_fields_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "KLAXON_ANONYMIZATION_MASK_FREE_TEXT_FIELDS", "message, event.original"
        )
        assert AnonymizationConfig.from_env().mask_free_text_fields == (
            "message",
            "event.original",
        )

    def test_default_mask_fields_include_user_effective_name(self) -> None:
        assert "user.effective.name" in Config.from_env().anonymization.mask_fields

    def test_masked_streams_defaults_empty(self) -> None:
        assert Config.from_env().anonymization.masked_streams == ()

    def test_masked_streams_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "KLAXON_ANONYMIZATION_MASKED_STREAMS",
            "klaxon-masked-customer-a-v5-*,klaxon-masked-customer-b-v5-*",
        )
        assert AnonymizationConfig.from_env().masked_streams == (
            "klaxon-masked-customer-a-v5-*",
            "klaxon-masked-customer-b-v5-*",
        )

    def test_masked_streams_env_tolerates_whitespace(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            "KLAXON_ANONYMIZATION_MASKED_STREAMS", " klaxon-masked-a-v5-* "
        )
        assert AnonymizationConfig.from_env().masked_streams == (
            "klaxon-masked-a-v5-*",
        )


class TestQuarantineMaskedStreamsGuard:
    """A masked_streams pattern that could match the quarantine stream (RAW
    masking-failure docs) must refuse startup — the LLM allowlist must never
    overlap the quarantine namespace."""

    def test_quarantine_pattern_overlap_detects_quarantine(self) -> None:
        assert config.quarantine_pattern_overlap("klaxon-quarantine-*")
        assert config.quarantine_pattern_overlap("klaxon-quarantine-customer-a-v5-*")
        assert config.quarantine_pattern_overlap("klaxon-*")  # too broad
        assert config.quarantine_pattern_overlap("klaxon-quarantine-a-v5-*")

    def test_quarantine_pattern_overlap_allows_masked(self) -> None:
        assert not config.quarantine_pattern_overlap("klaxon-masked-customer-a-v5-*")
        assert not config.quarantine_pattern_overlap("wazuh-events-v5-*")
        assert not config.quarantine_pattern_overlap("klaxon-masked-*")

    @pytest.mark.parametrize("pattern", [
        "klaxon-quarantine-customer-a-v5-*",
        "klaxon-quarantine-*",
        "klaxon-*",
    ])
    def test_from_env_refuses_quarantine_in_masked_streams(
        self, monkeypatch: pytest.MonkeyPatch, pattern: str
    ) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZATION_MASKED_STREAMS", pattern)
        with pytest.raises(ConfigError, match="quarantine"):
            AnonymizationConfig.from_env()

    def test_from_env_allows_only_masked(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "KLAXON_ANONYMIZATION_MASKED_STREAMS",
            "klaxon-masked-customer-a-v5-*",
        )
        assert AnonymizationConfig.from_env().masked_streams == (
            "klaxon-masked-customer-a-v5-*",
        )

    def test_generated_config_fragment_never_adds_quarantine(self) -> None:
        """Quarantine is NEVER generated into masked_streams — the fragment
        lists only the masked stream, so the guard cannot trip on a fresh
        tenant's generated config."""
        from klaxon_mcp.tenants import build_config_fragment, load_tenant_config

        data = yaml.safe_load(build_config_fragment(load_tenant_config("customer-a")))
        streams = data["anonymization"]["masked_streams"]
        assert streams == ["klaxon-masked-customer-a-v5-*"]
        for stream in streams:
            assert not config.quarantine_pattern_overlap(stream)


class TestBooleanFailClosed:
    """M3: a typo in a security-critical switch must refuse to start, never
    silently disable masking (fail-closed, not fail-open)."""

    @pytest.mark.parametrize("var", [
        "KLAXON_ANONYMIZE_EXTERNAL_LLM",
        "KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS",
        "KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS",
        "KLAXON_ANONYMIZATION_WHITELIST_ENABLED",
        "KLAXON_ANONYMIZATION_LOG_RAW",
    ])
    def test_invalid_value_raises(self, monkeypatch: pytest.MonkeyPatch, var: str) -> None:
        monkeypatch.setenv(var, "treu")  # typo
        with pytest.raises(ConfigError, match="must be a boolean"):
            AnonymizationConfig.from_env()

    @pytest.mark.parametrize("raw,expected", [
        ("true", True),
        ("1", True),
        ("yes", True),
        ("on", True),
        ("false", False),
        ("0", False),
        ("no", False),
        ("off", False),
    ])
    def test_recognized_values_parse(
        self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
    ) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS", raw)
        assert AnonymizationConfig.from_env().mask_aggregation_keys is expected

    def test_lenient_bool_still_used_elsewhere(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Non-security flags keep the lenient parser (e.g. verify_ssl typo -> False).
        monkeypatch.setenv("WAZUH_VERIFY_SSL", "treu")
        assert Config.from_env().verify_ssl is False


class TestAnonymizationYaml:
    def test_yaml_enables_when_env_unset(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
    ) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "anonymization:\n  enabled: true\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        config = AnonymizationConfig.from_env()
        assert config.enabled is True

    def test_yaml_mask_free_text(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "anonymization:\n  mask_free_text_users: false\n"
            "  mask_free_text_fields:\n    - message\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        cfg = AnonymizationConfig.from_env()
        assert cfg.mask_free_text_users is False
        assert cfg.mask_free_text_fields == ("message",)

    def test_env_beats_yaml(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
    ) -> None:
        path = tmp_path / "config.yaml"
        path.write_text("anonymization:\n  enabled: true\n", encoding="utf-8")
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        monkeypatch.setenv("KLAXON_ANONYMIZE_EXTERNAL_LLM", "false")
        config = AnonymizationConfig.from_env()
        assert config.enabled is False

    def test_missing_yaml_is_ignored(self) -> None:
        config = AnonymizationConfig.from_env()
        assert config.enabled is False

    def test_yaml_mask_fields(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "anonymization:\n  mask_fields:\n    - source.ip\n    - user.name\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        config = AnonymizationConfig.from_env()
        assert config.mask_fields == ("source.ip", "user.name")

    def test_yaml_mask_aggregation_keys(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "anonymization:\n  mask_aggregation_keys: true\n", encoding="utf-8"
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        assert AnonymizationConfig.from_env().mask_aggregation_keys is True

    def test_env_beats_yaml_mask_aggregation_keys(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "anonymization:\n  mask_aggregation_keys: true\n", encoding="utf-8"
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        monkeypatch.setenv("KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS", "false")
        assert AnonymizationConfig.from_env().mask_aggregation_keys is False

    def test_yaml_masked_streams(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "anonymization:\n  masked_streams:\n    - klaxon-masked-customer-a-v5-*\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        assert AnonymizationConfig.from_env().masked_streams == (
            "klaxon-masked-customer-a-v5-*",
        )

    def test_env_beats_yaml_masked_streams(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "anonymization:\n  masked_streams:\n    - klaxon-masked-a-v5-*\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        monkeypatch.setenv(
            "KLAXON_ANONYMIZATION_MASKED_STREAMS", "klaxon-masked-b-v5-*"
        )
        assert AnonymizationConfig.from_env().masked_streams == (
            "klaxon-masked-b-v5-*",
        )

    def test_env_and_yaml_mask_fields_conflict_is_fail_closed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        """Both env and YAML set mask_fields differently -> refuse to start."""
        path = tmp_path / "config.yaml"
        path.write_text(
            "anonymization:\n  mask_fields:\n    - source.ip\n    - user.name\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        monkeypatch.setenv(
            "KLAXON_ANONYMIZATION_MASK_FIELDS", "source.ip,user.name,user.id"
        )
        with pytest.raises(ConfigError, match="mask_fields"):
            AnonymizationConfig.from_env()

    def test_env_and_yaml_mask_fields_agreement_is_allowed(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
    ) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "anonymization:\n  mask_fields:\n    - source.ip\n    - user.name\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        monkeypatch.setenv(
            "KLAXON_ANONYMIZATION_MASK_FIELDS", "source.ip, user.name"
        )
        cfg = AnonymizationConfig.from_env()
        assert cfg.mask_fields == ("source.ip", "user.name")


class TestGdprConfig:
    def test_defaults(self) -> None:
        gdpr = Config.from_env().gdpr
        assert gdpr.sample_size == 10
        assert gdpr.log_path == "gdpr_check.log"
        assert gdpr.report_path == "gdpr_compliance_report.json"
        assert gdpr.check_on_search is False
        assert gdpr.custom_patterns == (
            {"field": "user.effective.name", "type": "USERNAME", "priority": "high"},
        )

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KLAXON_GDPR_SAMPLE_SIZE", "25")
        monkeypatch.setenv("KLAXON_GDPR_CHECK_ON_SEARCH", "true")
        monkeypatch.setenv("KLAXON_GDPR_CHECK_LOG", "/tmp/gdpr.log")
        gdpr = GdprConfig.from_env()
        assert gdpr.sample_size == 25
        assert gdpr.check_on_search is True
        assert gdpr.log_path == "/tmp/gdpr.log"

    def test_yaml_custom_patterns(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
        path = tmp_path / "config.yaml"
        path.write_text(
            "gdpr_checker:\n"
            "  sample_size: 5\n"
            "  custom_patterns:\n"
            "    - field: custom.user_id\n"
            "      type: USER_ID\n"
            "      priority: high\n"
            "      regex: '^[A-Z0-9]{8}$'\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("KLAXON_CONFIG", str(path))
        gdpr = GdprConfig.from_env()
        assert gdpr.sample_size == 5
        # Built-in rules are always present; the YAML rules are merged on top.
        assert gdpr.custom_patterns == DEFAULT_GDPR_CUSTOM_PATTERNS + (
            {"field": "custom.user_id", "type": "USER_ID",
             "priority": "high", "regex": "^[A-Z0-9]{8}$"},
        )

    def test_invalid_sample_size_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("KLAXON_GDPR_SAMPLE_SIZE", "-1")
        with pytest.raises(ConfigError, match="must be >= 0"):
            GdprConfig.from_env()
