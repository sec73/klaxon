# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The klaxon_posture_check contract: facts + gaps, never a verdict.

The tool returns one `check: status — fact` line per item with source
attribution, statuses OK / WARN / unknown only, and — because it is itself
callable from chat — MUST never emit the salt, PII, raw values, tokens,
hostnames, usernames, IPs or sampled values. These tests pin the nine checks,
the statuses, the no-salt/no-PII contract and the explicit "unknown" handling
for an unreachable indexer.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

from klaxon_mcp import posture, server
from klaxon_mcp.clients import Response, TransportError
from klaxon_mcp.config import AnonymizationConfig, Config
from klaxon_mcp.masked_stream import fields_yaml_sha256
from klaxon_mcp.tenants import load_tenant_config

TEST_SALT = "0123456789abcdef0123456789abcdef"
# Exactly 64 hex chars = 256 bits (the recommended length).
SECRET_SALT = (
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef"
)


def anon(**kw: Any) -> AnonymizationConfig:
    defaults: dict[str, Any] = {
        "enabled": True,
        "llm_base_url": "",
        "salt": TEST_SALT,
        "mask_fields": ("user.name", "source.ip"),
        "mask_aggregation_keys": True,
        "mask_free_text_users": True,
        "masked_streams": ("klaxon-masked-customer-a-v5*",),
        "whitelist_enabled": True,
    }
    defaults.update(kw)
    return AnonymizationConfig(**defaults)


def cfg_for(a: AnonymizationConfig) -> Config:
    return Config(
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
        anonymization=a,
    )


class FakeIndexer:
    """A stub indexer: configurable data streams, roles, pipeline, backlog count."""

    def __init__(
        self,
        *,
        masked_streams: bool = True,
        quarantine_streams: bool = False,
        roles: dict[str, Any] | None = None,
        pipeline: dict[str, Any] | None = None,
        count: int = 0,
        reachable: bool = True,
        pii_in_roles: bool = False,
    ) -> None:
        self.masked_streams = masked_streams
        self.quarantine_streams = quarantine_streams
        self.roles = roles
        self.pipeline = pipeline
        self.count = count
        self.reachable = reachable
        self.pii_in_roles = pii_in_roles

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Response:
        if not self.reachable:
            raise TransportError(f"GET {path} failed at transport level: boom")
        if path.startswith("/_data_stream/"):
            pattern = path.split("/_data_stream/", 1)[1]
            streams = []
            if self.masked_streams and pattern.startswith("klaxon-masked-"):
                streams.append({"name": "klaxon-masked-customer-a-v5"})
            if self.quarantine_streams and pattern.startswith("klaxon-quarantine-"):
                streams.append({"name": "klaxon-quarantine-customer-a-v5"})
            return Response(
                200, json.dumps({"data_streams": streams}), f"https://indexer.example{path}"
            )
        if path.startswith("/_ingest/pipeline/"):
            name = path.rsplit("/", 1)[1]
            if self.pipeline is None:
                return Response(404, "{}", f"https://indexer.example{path}")
            return Response(
                200, json.dumps({name: self.pipeline}), f"https://indexer.example{path}"
            )
        if path == "/_plugins/_security/api/roles":
            if self.roles is None:
                return Response(404, "{}", f"https://indexer.example{path}")
            if self.pii_in_roles:
                # PII smuggled into role bodies must never surface in the tool
                # output — the tool only reads role NAMES + index patterns.
                bodies = {
                    r: {"description": "owner marco@example.com / marco"}
                    for r in self.roles
                }
            else:
                bodies = {r: {} for r in self.roles}
            return Response(
                200, json.dumps({"roles": bodies}), f"https://indexer.example{path}"
            )
        raise AssertionError(f"unexpected GET {path}")

    async def post(
        self, path: str, *, body: Any | None = None, params: dict[str, Any] | None = None
    ) -> Response:
        if not self.reachable:
            raise TransportError(f"POST {path} failed at transport level: boom")
        if path.endswith("/_count"):
            return Response(
                200, json.dumps({"count": self.count}), f"https://indexer.example{path}"
            )
        raise AssertionError(f"unexpected POST {path}")


ALL_ROLES = [
    "klaxon_llm_report_customer-a",
    "klaxon_ops_customer-a",
    "klaxon_sync_customer-a",
]


def matching_pipeline(cfg: Any) -> dict[str, Any]:
    """A deployed pipeline that passes the drift checks for this tenant."""
    meta = {
        "sha256": fields_yaml_sha256(cfg),
        "fields": list(cfg.all_masked_fields),
        "free_text_fields": list(cfg.free_text_fields),
    }
    return {
        "description": "\nklaxon-provenance: " + json.dumps(meta),
        "processors": [
            {
                "script": {
                    "source": "def noop() { return 1; } noop();",
                    "on_failure": [
                        {
                            "script": {
                                "source": (
                                    "original_index; masking_error; _index; "
                                    "quarantine;"
                                )
                            }
                        }
                    ],
                }
            }
        ],
    }


async def run_posture(
    fake: FakeIndexer,
    *,
    a: AnonymizationConfig | None = None,
    cfg: Any | None = None,
    hours: int = 24,
) -> list[str]:
    a = a or anon()
    config = cfg_for(a)
    tenant = cfg or load_tenant_config("customer-a")
    return await posture.posture_check(fake, config, a, tenant, hours=hours)


def find(lines: list[str], check: str) -> str:
    return next(line for line in lines if line.startswith(f"{check}:"))


class TestPostureChecks:
    async def test_all_nine_checks_present(self) -> None:
        tenant = load_tenant_config("customer-a")
        # Align the effective config with the tenant's fields.yaml so the
        # pipeline-drift check passes (response layer == pipeline field list).
        a = anon(
            mask_fields=tenant.all_masked_fields,
            mask_free_text_fields=tenant.free_text_fields,
            salt=SECRET_SALT,
        )
        fake = FakeIndexer(roles=set(ALL_ROLES), pipeline=matching_pipeline(tenant))
        lines = await run_posture(fake, a=a, cfg=tenant)
        names = {line.split(":", 1)[0] for line in lines}
        assert names == {
            "masking",
            "response_gate",
            "mode",
            "pipeline_drift",
            "salt_strength",
            "quarantine_backlog",
            "rbac",
            "retention",
            "startup_fail_closed",
        }
        # In the safe state everything is OK (mode OK because the masked stream
        # exists in this stub).
        assert find(lines, "masking").startswith("masking: OK")
        assert find(lines, "response_gate").startswith("response_gate: OK")
        assert find(lines, "mode").startswith("mode: OK")
        assert find(lines, "pipeline_drift").startswith("pipeline_drift: OK")
        assert find(lines, "salt_strength").startswith("salt_strength: OK")
        assert find(lines, "quarantine_backlog").startswith("quarantine_backlog: OK")
        assert find(lines, "rbac").startswith("rbac: OK")
        assert find(lines, "retention").startswith("retention: OK")
        assert find(lines, "startup_fail_closed").startswith("startup_fail_closed: OK")

    async def test_masking_off_warns(self) -> None:
        lines = await run_posture(FakeIndexer(), a=anon(enabled=False))
        assert find(lines, "masking").startswith("masking: WARN")
        assert "anonymization feature is disabled" in find(lines, "masking")

    async def test_empty_mask_fields_warns(self) -> None:
        lines = await run_posture(FakeIndexer(), a=anon(mask_fields=()))
        assert find(lines, "masking").startswith("masking: WARN")

    async def test_external_llm_with_gate_off_warns(self) -> None:
        lines = await run_posture(
            FakeIndexer(),
            a=anon(llm_base_url="https://api.deepseek.com", whitelist_enabled=False),
        )
        assert find(lines, "response_gate").startswith("response_gate: WARN")
        assert "response gate is inactive" in find(lines, "response_gate")

    async def test_external_llm_with_gate_on_ok(self) -> None:
        lines = await run_posture(
            FakeIndexer(),
            a=anon(llm_base_url="https://api.deepseek.com", whitelist_enabled=True),
        )
        assert find(lines, "response_gate").startswith("response_gate: OK")

    async def test_loopback_ok(self) -> None:
        lines = await run_posture(
            FakeIndexer(), a=anon(llm_base_url="http://127.0.0.1:11434")
        )
        assert find(lines, "response_gate").startswith("response_gate: OK")
        assert "loopback" in find(lines, "response_gate")

    async def test_mode_warns_when_masked_stream_absent(self) -> None:
        lines = await run_posture(FakeIndexer(masked_streams=False))
        assert find(lines, "mode").startswith("mode: WARN")
        assert "not present" in find(lines, "mode")
        assert "planned, not implemented" in find(lines, "mode")

    async def test_mode_warns_when_config_does_not_cover_deployed_stream(
        self,
    ) -> None:
        """The divergence guard: the data stream is named
        klaxon-masked-customer-a-v5, so a masked_streams config of ...-v5-* would
        make every Klaxon query match nothing — the mode check must WARN."""
        a = anon(masked_streams=("klaxon-masked-customer-a-v5-*",))
        lines = await run_posture(FakeIndexer(masked_streams=True), a=a)
        line = find(lines, "mode")
        assert line.startswith("mode: WARN")
        assert "NOT covered by the masked_streams config" in line
        assert "klaxon-masked-customer-a-v5-*" in line

    async def test_pipeline_not_deployed_warns(self) -> None:
        lines = await run_posture(FakeIndexer(pipeline=None))
        assert find(lines, "pipeline_drift").startswith("pipeline_drift: WARN")
        assert "not deployed" in find(lines, "pipeline_drift")

    async def test_pipeline_drift_warns_on_fingerprint_mismatch(self) -> None:
        fake = FakeIndexer(pipeline={"description": "wrong provenance", "processors": []})
        lines = await run_posture(fake)
        assert find(lines, "pipeline_drift").startswith("pipeline_drift: WARN")

    async def test_salt_weak_warns(self) -> None:
        lines = await run_posture(FakeIndexer(), a=anon(salt="short"))
        assert find(lines, "salt_strength").startswith("salt_strength: WARN")
        assert "~20 bits" in find(lines, "salt_strength")

    async def test_salt_empty_warns(self) -> None:
        lines = await run_posture(FakeIndexer(), a=anon(salt=""))
        assert find(lines, "salt_strength").startswith("salt_strength: WARN")

    async def test_salt_mid_length_warns(self) -> None:
        lines = await run_posture(FakeIndexer(), a=anon(salt="0123456789abcdef"))
        assert find(lines, "salt_strength").startswith("salt_strength: WARN")

    async def test_salt_ok(self) -> None:
        lines = await run_posture(FakeIndexer(), a=anon(salt=SECRET_SALT))
        assert find(lines, "salt_strength").startswith("salt_strength: OK")

    async def test_quarantine_backlog_ok_zero(self) -> None:
        lines = await run_posture(FakeIndexer(count=0))
        assert find(lines, "quarantine_backlog").startswith("quarantine_backlog: OK")

    async def test_quarantine_backlog_warns_on_count(self) -> None:
        lines = await run_posture(FakeIndexer(count=340))
        line = find(lines, "quarantine_backlog")
        assert line.startswith("quarantine_backlog: WARN")
        assert "340 doc(s) since" in line
        assert "investigate" in line

    async def test_rbac_all_present_ok(self) -> None:
        lines = await run_posture(FakeIndexer(roles=set(ALL_ROLES)))
        line = find(lines, "rbac")
        assert line.startswith("rbac: OK")
        for role in ALL_ROLES:
            assert f"{role} present" in line
        assert "klaxon-masked-customer-a-v5*" in line  # grants reported

    async def test_rbac_missing_warns(self) -> None:
        lines = await run_posture(FakeIndexer(roles={"klaxon_llm_report_customer-a"}))
        line = find(lines, "rbac")
        assert line.startswith("rbac: WARN")
        assert "klaxon_ops_customer-a missing" in line

    async def test_retention_reports_days(self) -> None:
        lines = await run_posture(FakeIndexer())
        assert "retention: OK — masked 30d / quarantine 90d" in find(lines, "retention")

    async def test_startup_fail_closed_ok(self) -> None:
        lines = await run_posture(FakeIndexer())
        assert find(lines, "startup_fail_closed").startswith("startup_fail_closed: OK")

    async def test_startup_fail_closed_warns_on_quarantine_overlap(self) -> None:
        lines = await run_posture(
            FakeIndexer(),
            a=anon(masked_streams=("klaxon-quarantine-customer-a-v5-*",)),
        )
        assert find(lines, "startup_fail_closed").startswith("startup_fail_closed: WARN")


class TestNoSaltNoPiiContract:
    async def test_salt_never_appears(self) -> None:
        # A distinctive salt: no prefix, no substring, no hash-of-it in output.
        lines = await run_posture(FakeIndexer(), a=anon(salt=SECRET_SALT))
        joined = "\n".join(lines)
        assert SECRET_SALT not in joined
        assert SECRET_SALT[:8] not in joined

    async def test_no_pii_surfaces(self) -> None:
        # Role bodies carry PII and the backlog is non-zero; none of it may
        # reach the output — only role names, index patterns, counts, statuses.
        fake = FakeIndexer(
            roles=set(ALL_ROLES), count=7, pii_in_roles=True
        )
        lines = await run_posture(fake)
        joined = "\n".join(lines)
        assert "marco" not in joined
        assert "marco@example.com" not in joined
        assert "[USER_" not in joined
        assert "[IP_" not in joined

    async def test_output_has_no_verdict(self) -> None:
        lines = await run_posture(FakeIndexer(roles=set(ALL_ROLES)))
        joined = "\n".join(lines).lower()
        for word in ("conform", "dsgvo-conform", "compliant", "safe", "pass"):
            assert word not in joined


class TestUnreachableIndexer:
    async def test_unreachable_reports_unknown(self) -> None:
        lines = await run_posture(FakeIndexer(reachable=False))
        joined = "\n".join(lines)
        # Every indexer-dependent check says "unknown — indexer not reachable".
        for check in ("mode", "pipeline_drift", "quarantine_backlog", "rbac"):
            assert find(lines, check).startswith(f"{check}: unknown")
        assert "indexer not reachable" in joined
        # Config-only checks still run.
        assert find(lines, "masking").startswith("masking:")
        assert find(lines, "salt_strength").startswith("salt_strength:")


# --------------------------------------------------------------------------- #
# End to end through the MCP tool
# --------------------------------------------------------------------------- #


@pytest.fixture
def run_tool() -> Iterator[Any]:
    previous_indexer = server._indexer
    previous_config = server._config
    previous_anon = server._anonymizer

    def install(fake: FakeIndexer, a: AnonymizationConfig | None = None) -> None:
        a = a or anon(mask_fields=load_tenant_config("customer-a").all_masked_fields)
        server._config = cfg_for(a)
        server._anonymizer = None  # type: ignore[assignment]
        server._indexer = fake  # type: ignore[assignment]

    install(FakeIndexer(roles=set(ALL_ROLES)))
    try:
        yield install
    finally:
        server._indexer = previous_indexer
        server._config = previous_config
        server._anonymizer = previous_anon


class TestPostureTool:
    async def test_tool_returns_all_checks(self, run_tool: Any) -> None:
        out = await server.klaxon_posture_check()
        for check in (
            "masking:",
            "response_gate:",
            "mode:",
            "pipeline_drift:",
            "salt_strength:",
            "quarantine_backlog:",
            "rbac:",
            "retention:",
            "startup_fail_closed:",
        ):
            assert check in out

    async def test_tool_honours_hours_param(self, run_tool: Any) -> None:
        out = await server.klaxon_posture_check(hours=12)
        assert "in the last 12h" in out

    async def test_tool_never_leaks_salt(self, run_tool: Any) -> None:
        out = await server.klaxon_posture_check()
        assert SECRET_SALT not in out
        assert "0123456789abcdef0123456789abcdef" not in out
