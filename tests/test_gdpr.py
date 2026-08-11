# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The DSGVO plausibility checker: heuristics, suggestions, config updates.

The guarantee this module exists for: an operator can find the personal data
they did not know they were collecting. The tests pin the three classification
layers (custom rules > field-name patterns > sampled values), the priority
scale, and the side effects (config.yaml merge, audit log, compliance report).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from klaxon_mcp import server
from klaxon_mcp.anonymization import Anonymizer
from klaxon_mcp.clients import Response
from klaxon_mcp.config import (
    DEFAULT_GDPR_CUSTOM_PATTERNS,
    AnonymizationConfig,
    Config,
    GdprConfig,
)
from klaxon_mcp.fields import FieldInfo
from klaxon_mcp.gdpr import (
    AGENT_ID,
    DOMAIN,
    EMAIL,
    FREETEXT,
    HOSTNAME,
    IP_ADDRESS,
    USERNAME,
    SensitiveField,
    analyze,
    classify_field,
    env_hint,
    render_json,
    run_check,
    sample_values,
    scan_hits,
    update_mask_fields,
)


def classify(
    field: str,
    types: list[str] | None = None,
    sampled: list[str] | None = None,
    custom: tuple[dict[str, Any], ...] = (),
    already: set[str] | None = None,
) -> SensitiveField | None:
    return classify_field(
        field,
        types or [],
        sampled or [],
        custom,
        already or set(),
    )


# --------------------------------------------------------------------------- #
# Field-name patterns
# --------------------------------------------------------------------------- #


class TestNamePatterns:
    @pytest.mark.parametrize(
        "field,kind,priority",
        [
            ("source.ip", IP_ADDRESS, "high"),
            ("destination.ip", IP_ADDRESS, "high"),
            ("client.ip", IP_ADDRESS, "high"),
            ("user.name", USERNAME, "high"),
            ("source.user.name", USERNAME, "high"),
            ("username", USERNAME, "high"),
            ("user.email", EMAIL, "high"),
            ("host.hostname", HOSTNAME, "medium"),
            ("wazuh.agent.name", HOSTNAME, "medium"),
            ("wazuh.agent.id", AGENT_ID, "medium"),
            ("source.domain", DOMAIN, "medium"),
        ],
    )
    def test_recognised_by_name(self, field: str, kind: str, priority: str) -> None:
        found = classify(field)
        assert found is not None
        assert found.kind == kind
        assert found.priority == priority
        assert found.suggested_mask

    @pytest.mark.parametrize(
        "field", ["event.action", "@timestamp", "network.protocol", "message"]
    )
    def test_generic_fields_are_not_sensitive(self, field: str) -> None:
        assert classify(field) is None


# --------------------------------------------------------------------------- #
# Sampled values
# --------------------------------------------------------------------------- #


class TestContentBased:
    def test_custom_field_with_ip_values(self) -> None:
        found = classify("custom.peer", sampled=["192.168.1.100"])
        assert found is not None
        assert found.kind == IP_ADDRESS
        assert found.priority == "high"
        assert "sampled value" in found.evidence

    def test_custom_field_with_email_values(self) -> None:
        found = classify("custom.contact", sampled=["user@example.com"])
        assert found is not None
        assert found.kind == EMAIL

    def test_custom_field_with_hostname_values(self) -> None:
        found = classify("custom.node", sampled=["web-server-01.example.com"])
        assert found is not None
        assert found.kind == HOSTNAME
        assert found.priority == "medium"

    def test_free_text_embedding_personal_data(self) -> None:
        found = classify(
            "event.original",
            types=["keyword"],
            sampled=["Failed login for admin from 192.168.1.100"],
        )
        assert found is not None
        assert found.kind == FREETEXT
        assert found.priority == "medium"

    def test_free_text_without_pii_is_not_sensitive(self) -> None:
        assert classify("event.original", sampled=["all systems nominal"]) is None

    def test_name_pattern_beats_content_for_known_fields(self) -> None:
        found = classify("source.ip", sampled=["not-an-ip"])
        assert found is not None
        assert found.kind == IP_ADDRESS  # by name, not by the odd sample


# --------------------------------------------------------------------------- #
# Custom rules
# --------------------------------------------------------------------------- #

CUSTOM = (
    {"field": "custom.user_id", "type": "USER_ID", "priority": "high"},
    {"field": "internal.*", "type": "USERNAME", "priority": "medium"},
    {
        "field": "token",
        "type": "USER_ID",
        "priority": "high",
        "regex": "^[A-Z0-9]{8}$",
    },
)


class TestCustomRules:
    def test_exact_custom_field(self) -> None:
        found = classify("custom.user_id", custom=CUSTOM)
        assert found is not None
        assert found.kind == "USER_ID"
        assert found.priority == "high"
        assert found.evidence == "custom rule"

    def test_glob_custom_field(self) -> None:
        found = classify("internal.employee_no", custom=CUSTOM)
        assert found is not None
        assert found.kind == USERNAME
        assert found.priority == "medium"

    def test_regex_rule_matches_content(self) -> None:
        found = classify("token", sampled=["ABCD1234"], custom=CUSTOM)
        assert found is not None
        assert found.kind == "USER_ID"

    def test_regex_rule_skips_non_matching_content(self) -> None:
        assert classify("token", sampled=["abc"], custom=CUSTOM) is None

    def test_custom_rule_overrides_name_pattern(self) -> None:
        override = ({"field": "source.ip", "type": "USERNAME", "priority": "high"},)
        found = classify("source.ip", custom=override)
        assert found is not None
        assert found.kind == USERNAME


class TestAlreadyConfigured:
    def test_covered_fields_are_marked(self) -> None:
        found = classify("source.ip", already={"source.ip"})
        assert found is not None
        assert found.already_configured is True

    def test_analysis_excludes_nothing_but_flags_coverage(self) -> None:
        fields = [
            FieldInfo(name="source.ip"),
            FieldInfo(name="event.action"),
            FieldInfo(name="user.name"),
        ]
        found = analyze(fields, {}, (), {"source.ip"})
        names = [f.field for f in found]
        assert "source.ip" in names  # still reported, flagged as covered
        assert found[0].already_configured is True

    def test_user_effective_name_covered_by_default_rule(self) -> None:
        """The built-in custom rule pins user.effective.name as a username."""
        found = classify(
            "user.effective.name",
            custom=DEFAULT_GDPR_CUSTOM_PATTERNS,
            already={"user.effective.name"},
        )
        assert found is not None
        assert found.kind == USERNAME
        assert found.priority == "high"
        assert found.evidence == "custom rule"
        assert found.already_configured is True


class TestAnalyze:
    def test_sorted_by_priority_then_name(self) -> None:
        fields = [
            FieldInfo(name="host.hostname"),   # medium
            FieldInfo(name="source.ip"),       # high
            FieldInfo(name="user.email"),      # high
        ]
        found = analyze(fields, {}, (), set())
        assert [f.field for f in found] == ["source.ip", "user.email", "host.hostname"]


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


class TestRendering:
    def test_json_shape(self) -> None:
        result = run_check_result_with(
            [
                SensitiveField("source.ip", IP_ADDRESS, "high", "field-name pattern", "[IP_ADDRESS]"),
            ]
        )
        payload = json.loads(render_json(result))
        assert payload["sensitive_fields"][0]["field"] == "source.ip"
        assert payload["sensitive_fields"][0]["type"] == IP_ADDRESS
        assert payload["action_required"] is True
        assert payload["fields_to_add"] == ["source.ip"]

    def test_env_hint(self) -> None:
        assert env_hint(["source.ip", "user.name"]) == (
            'KLAXON_ANONYMIZATION_MASK_FIELDS="source.ip,user.name"'
        )
        assert env_hint([]) == ""


def run_check_result_with(sensitive: list[SensitiveField]) -> Any:
    from klaxon_mcp.gdpr import CheckResult

    return CheckResult(
        index="wazuh-events-v5-*",
        mapped_total=2,
        sensitive=sensitive,
        sampled_fields=0,
        sample_size=10,
    )


# --------------------------------------------------------------------------- #
# The cheap hit scan (KLAXON_GDPR_CHECK_ON_SEARCH)
# --------------------------------------------------------------------------- #


class TestScanHits:
    def test_finds_sensitive_fields_in_hits(self) -> None:
        parsed = {
            "hits": {
                "hits": [
                    {
                        "_source": {
                            "source": {"ip": "1.2.3.4"},
                            "user": {"name": "admin"},
                            "event": {"action": "login"},
                        }
                    }
                ]
            }
        }
        assert scan_hits(parsed, ()) == ["source.ip", "user.name"]

    def test_custom_patterns_are_honoured(self) -> None:
        parsed = {"hits": {"hits": [{"_source": {"custom.user_id": "x"}}]}}
        assert scan_hits(parsed, ()) == []
        rules = ({"field": "custom.*", "type": "USER_ID", "priority": "high"},)
        assert scan_hits(parsed, rules) == ["custom.user_id"]


# --------------------------------------------------------------------------- #
# Sampling
# --------------------------------------------------------------------------- #


class StubIndexer:
    def __init__(self, caps: dict[str, Any], docs: list[dict[str, Any]]) -> None:
        self.caps = caps
        self.docs = docs
        self.search_calls = 0

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Response:
        if path.endswith("/_field_caps"):
            return Response(
                200, json.dumps({"fields": self.caps}), f"https://indexer.example{path}"
            )
        return Response(404, "{}", f"https://indexer.example{path}")

    async def post(
        self, path: str, *, body: Any = None, params: dict[str, Any] | None = None
    ) -> Response:
        self.search_calls += 1
        if path.endswith("/_search"):
            hits = [{"_source": doc} for doc in self.docs]
            return Response(
                200,
                json.dumps({"hits": {"hits": hits}}),
                f"https://indexer.example{path}",
            )
        return Response(404, "{}", f"https://indexer.example{path}")


class TestSampleValues:
    async def test_flattens_nested_and_dotted_keys(self) -> None:
        client = StubIndexer(
            {}, [{"source": {"ip": "1.2.3.4"}, "custom.peer": "5.6.7.8", "count": 3}]
        )
        values, sampled = await sample_values(
            client, "wazuh-events-v5-*", [FieldInfo(name="x")], size=10
        )
        assert sampled == 1
        assert values["source.ip"] == ["1.2.3.4"]
        assert values["custom.peer"] == ["5.6.7.8"]
        assert values["count"] == ["3"]

    async def test_values_are_capped(self) -> None:
        client = StubIndexer(
            {},
            [{"many": str(i)} for i in range(20)],
        )
        values, _ = await sample_values(
            client, "wazuh-events-v5-*", [FieldInfo(name="x")], size=20
        )
        assert len(values["many"]) == 5

    async def test_zero_size_disables_sampling(self) -> None:
        client = StubIndexer({}, [{"source": {"ip": "1.2.3.4"}}])
        values, sampled = await sample_values(
            client, "wazuh-events-v5-*", [FieldInfo(name="x")], size=0
        )
        assert values == {}
        assert sampled == 0
        assert client.search_calls == 0


# --------------------------------------------------------------------------- #
# config.yaml update
# --------------------------------------------------------------------------- #


class TestUpdateMaskFields:
    def test_merges_into_existing_file(
        self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("KLAXON_ANONYMIZATION_MASK_FIELDS", raising=False)
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "anonymization:\n  enabled: true\n  mask_fields:\n    - source.ip\n",
            encoding="utf-8",
        )
        changed, merged, warning = update_mask_fields(str(cfg), ["user.name", "source.ip"])
        assert changed is True
        assert merged == ["source.ip", "user.name"]
        assert warning is None
        content = cfg.read_text(encoding="utf-8")
        assert "user.name" in content
        assert "enabled: true" in content  # unrelated keys survive

    def test_creates_file_when_absent(self, tmp_path: Any) -> None:
        cfg = tmp_path / "config.yaml"
        changed, merged, _ = update_mask_fields(str(cfg), ["user.name"])
        assert changed is True
        assert merged == ["user.name"]
        assert cfg.exists()

    def test_no_new_fields_is_no_change(self, tmp_path: Any) -> None:
        cfg = tmp_path / "config.yaml"
        cfg.write_text("anonymization:\n  mask_fields:\n    - user.name\n", encoding="utf-8")
        changed, _, _ = update_mask_fields(str(cfg), ["user.name"])
        assert changed is False

    def test_env_override_warns(self, tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("KLAXON_ANONYMIZATION_MASK_FIELDS", "source.ip")
        cfg = tmp_path / "config.yaml"
        changed, _, warning = update_mask_fields(str(cfg), ["user.name"])
        assert changed is True
        assert warning is not None
        assert "overrides" in warning


# --------------------------------------------------------------------------- #
# run_check orchestration + the gdpr_check MCP tool
# --------------------------------------------------------------------------- #

CAPS = {
    "source.ip": {"keyword": {}},
    "user.name": {"keyword": {}},
    "event.action": {"keyword": {}},
    "host.hostname": {"keyword": {}},
    "custom.peer": {"keyword": {}},
}


def docs() -> list[dict[str, Any]]:
    return [
        {
            "source": {"ip": "10.0.0.1"},
            "user": {"name": "admin"},
            "event": {"action": "login"},
            "host": {"hostname": "web-01"},
            "custom": {"peer": "192.168.1.100"},
        }
    ]


class TestRunCheck:
    async def test_full_pipeline(self) -> None:
        client = StubIndexer(CAPS, docs())
        result = await run_check(
            client, "wazuh-events-v5-*", None, 10, (), set()
        )
        assert result.mapped_total == 5
        kinds = {f.field: f.kind for f in result.sensitive}
        assert kinds["source.ip"] == IP_ADDRESS
        assert kinds["user.name"] == USERNAME
        assert kinds["host.hostname"] == HOSTNAME
        assert kinds["custom.peer"] == IP_ADDRESS  # content-based
        assert "event.action" not in kinds
        assert set(result.new_fields) == set(kinds)
        # Priority order: high before medium, never interleaved.
        rank = {"high": 0, "medium": 1, "low": 2}
        ordered = [rank[f.priority] for f in result.sensitive]
        assert ordered == sorted(ordered)

    async def test_exclude_filters_fields(self) -> None:
        client = StubIndexer(CAPS, docs())
        result = await run_check(
            client, "wazuh-events-v5-*", None, 10, (), set(), {"source.ip"}
        )
        assert "source.ip" not in {f.field for f in result.sensitive}

    async def test_caps_failure_is_reported_not_raised(self) -> None:
        client = StubIndexer({}, docs())

        async def failing(path: str, *, params: dict[str, Any] | None = None) -> Response:
            return Response(400, json.dumps({"error": {"type": "bad"}}), path)

        client.get = failing  # type: ignore[method-assign]
        result = await run_check(client, "wazuh-events-v5-*", None, 10, (), set())
        assert result.caps_failed is not None
        assert result.sensitive == []


@pytest.fixture
def gdpr_env(tmp_path: Any) -> Iterator[tuple[StubIndexer, Any]]:
    """Install a stub indexer + a config whose side-effect files live in tmp."""
    previous_indexer = server._indexer
    previous_config = server._config
    previous_anon = server._anonymizer

    server._config = Config(
        indexer_url="https://indexer.example:9200",
        indexer_user="",
        indexer_password="",
        manager_url="",
        manager_user="",
        manager_password="",
        engine_url="",
        verify_ssl=False,
        timeout=60.0,
        schema_field_limit=200,
        schema_probe_batch=100,
        search_max_size=100,
        logtest_default_trace_level="ASSET_ONLY",
        logtest_default_space="custom",
        anonymization=AnonymizationConfig(enabled=False, mask_fields=()),
        gdpr=GdprConfig(
            config_file=str(tmp_path / "config.yaml"),
            log_path=str(tmp_path / "gdpr_check.log"),
            report_path=str(tmp_path / "gdpr_compliance_report.json"),
            sample_size=10,
        ),
    )
    client = StubIndexer(CAPS, docs())
    server._indexer = client  # type: ignore[assignment]
    server._anonymizer = Anonymizer(AnonymizationConfig(enabled=False, mask_fields=()))
    try:
        yield client, tmp_path
    finally:
        server._indexer = previous_indexer
        server._config = previous_config
        server._anonymizer = previous_anon


class TestGdprCheckTool:
    async def test_dry_run_shows_suggestions(
        self, gdpr_env: tuple[StubIndexer, Any]
    ) -> None:
        from klaxon_mcp.server import gdpr_check

        out = await gdpr_check(index="wazuh-events-v5-*")
        assert "DSGVO PLAUSIBILITY CHECK" in out
        assert "source.ip" in out
        assert "user.name" in out
        assert "custom.peer" in out
        assert "dry run" in out
        assert "IP_ADDRESS" in out

    async def test_apply_merges_into_config(
        self, gdpr_env: tuple[StubIndexer, Any]
    ) -> None:
        from klaxon_mcp.server import gdpr_check

        client, tmp = gdpr_env
        out = await gdpr_check(index="wazuh-events-v5-*", apply=True)
        assert "config.yaml updated" in out
        cfg = tmp / "config.yaml"
        assert cfg.exists()
        content = cfg.read_text(encoding="utf-8")
        for field in ("source.ip", "user.name", "host.hostname", "custom.peer"):
            assert field in content
        report = tmp / "gdpr_compliance_report.json"
        payload = json.loads(report.read_text(encoding="utf-8"))
        assert payload["anonymization_updated"] is True
        assert set(payload["fields_added"]) == {
            "source.ip", "user.name", "host.hostname", "custom.peer",
        }
        log = tmp / "gdpr_check.log"
        assert "DSGVO-Prüfer" in log.read_text(encoding="utf-8")

    async def test_json_output(
        self, gdpr_env: tuple[StubIndexer, Any]
    ) -> None:
        from klaxon_mcp.server import gdpr_check

        out = await gdpr_check(index="wazuh-events-v5-*", as_json=True)
        payload = json.loads(out)
        assert payload["action_required"] is True
        assert {f["field"] for f in payload["sensitive_fields"]} == {
            "source.ip", "user.name", "host.hostname", "custom.peer",
        }

    async def test_json_output_runs_through_masking_guard(
        self, gdpr_env: tuple[StubIndexer, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """M2: the as_json report must pass through the masking guard. A raw IP
        that ever lands in the JSON is masked, never returned to the client."""
        from dataclasses import replace

        from klaxon_mcp import gdpr as gdpr_module
        from klaxon_mcp.server import gdpr_check

        _, tmp = gdpr_env
        active = AnonymizationConfig(
            enabled=True,
            salt="test-salt",
            mask_fields=("source.ip",),
            log_path=str(tmp / "llm.log"),
        )
        server._anonymizer = Anonymizer(active)  # type: ignore[assignment]
        server._config = replace(server._config, anonymization=active)  # type: ignore[arg-type]
        monkeypatch.setattr(
            gdpr_module,
            "render_json",
            lambda result: (
                '{"sensitive_fields": [{"field": "source.ip", "evidence": '
                '"sampled value is an IP address at 10.0.0.1"}]}'
            ),
        )
        out = await gdpr_check(index="wazuh-events-v5-*", as_json=True)
        assert "10.0.0.1" not in out
        assert "[IP_" in out

    async def test_exclude_skips_fields(
        self, gdpr_env: tuple[StubIndexer, Any]
    ) -> None:
        from klaxon_mcp.server import gdpr_check

        out = await gdpr_check(index="wazuh-events-v5-*", exclude=["user.name"])
        assert "user.name" not in out
        assert "source.ip" in out


class TestGdprCli:
    def test_cli_json_dry_run(
        self,
        gdpr_env: tuple[StubIndexer, Any],
        monkeypatch: pytest.MonkeyPatch,
        capsys: Any,
    ) -> None:
        from klaxon_mcp.__main__ import gdpr_cli_main

        _, tmp = gdpr_env
        monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example:9200")
        monkeypatch.setenv("KLAXON_GDPR_REPORT", str(tmp / "report.json"))
        monkeypatch.setenv("KLAXON_GDPR_CHECK_LOG", str(tmp / "gdpr.log"))
        rc = gdpr_cli_main(["--index", "wazuh-events-v5-*", "--dry-run", "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["action_required"] is True
        # dry run must not write a compliance report claiming an update
        report = json.loads((tmp / "report.json").read_text(encoding="utf-8"))
        assert report["anonymization_updated"] is False
