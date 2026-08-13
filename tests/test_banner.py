# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Automatic safety banner in the diagnostics layer.

`[UNMASKED MODE]` and/or `[RAW STREAM QUERY]` are prepended to every search
response whenever masking is off, the LLM is external with the response gate
inactive, or the query targeted a raw Wazuh stream. These tests pin the three
conditions and the end-to-end `search` behaviour (banner first, before the
existing diagnostics).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest

from klaxon_mcp import server
from klaxon_mcp.clients import Response
from klaxon_mcp.config import AnonymizationConfig, Config
from klaxon_mcp.constants import FINDINGS_PATTERN
from klaxon_mcp.diagnostics import safety_banner
from klaxon_mcp.server import search

TEST_SALT = "0123456789abcdef0123456789abcdef"


def make_config(
    *,
    enabled: bool = True,
    llm_base_url: str = "",
    whitelist_enabled: bool = True,
    mask_fields: tuple[str, ...] = ("user.name", "source.ip"),
    masked_streams: tuple[str, ...] = ("klaxon-masked-customer-a-v5-*",),
) -> Config:
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
        anonymization=AnonymizationConfig(
            enabled=enabled,
            llm_base_url=llm_base_url,
            whitelist_enabled=whitelist_enabled,
            mask_fields=mask_fields,
            masked_streams=masked_streams,
            salt=TEST_SALT,
            log_path="/tmp/klaxon-test-banner.log",
        ),
    )


def cfg(**kw: Any) -> AnonymizationConfig:
    return make_config(**kw).anonymization


def tags(lines: list[str]) -> set[str]:
    return {line.split("]")[0].lstrip("[") for line in lines if line.startswith("[")}


class TestSafetyBanner:
    def test_no_banner_in_safe_state_loopback(self) -> None:
        # Masking on + masked stream + loopback LLM: nothing to warn about.
        lines = safety_banner(
            cfg(llm_base_url="http://127.0.0.1:11434"), "klaxon-masked-customer-a-v5-*"
        )
        assert lines == []

    def test_no_banner_in_safe_state_external_with_gate(self) -> None:
        # Masking on + masked stream + external LLM but the response gate is
        # active: no banner.
        lines = safety_banner(
            cfg(llm_base_url="https://api.deepseek.com"),
            "klaxon-masked-customer-a-v5-*",
        )
        assert lines == []

    def test_masking_feature_off_emits_unmasked(self) -> None:
        lines = safety_banner(cfg(enabled=False), "klaxon-masked-customer-a-v5-*")
        assert "UNMASKED MODE" in tags(lines)
        assert any("Anonymization is disabled" in line for line in lines)

    def test_empty_mask_fields_emits_unmasked(self) -> None:
        lines = safety_banner(cfg(mask_fields=()), "klaxon-masked-customer-a-v5-*")
        assert "UNMASKED MODE" in tags(lines)

    def test_external_llm_gate_off_emits_unmasked(self) -> None:
        lines = safety_banner(
            cfg(llm_base_url="https://api.deepseek.com", whitelist_enabled=False),
            "klaxon-masked-customer-a-v5-*",
        )
        assert "UNMASKED MODE" in tags(lines)
        assert any("response gate is inactive" in line for line in lines)

    def test_external_llm_gate_on_has_no_gate_line(self) -> None:
        lines = safety_banner(
            cfg(llm_base_url="https://api.deepseek.com"),
            "klaxon-masked-customer-a-v5-*",
        )
        assert not any("response gate is inactive" in line for line in lines)

    def test_raw_events_emits_raw_stream_banner(self) -> None:
        lines = safety_banner(cfg(), "wazuh-events-v5-*")
        assert "RAW STREAM QUERY" in tags(lines)
        assert any("wazuh-events-v5-*" in line for line in lines)

    def test_raw_findings_emits_raw_stream_banner(self) -> None:
        lines = safety_banner(cfg(), FINDINGS_PATTERN)
        assert "RAW STREAM QUERY" in tags(lines)

    def test_raw_sub_pattern_emits_raw_stream_banner(self) -> None:
        lines = safety_banner(cfg(), "wazuh-events-v5-network-activity*")
        assert "RAW STREAM QUERY" in tags(lines)

    def test_masked_index_has_no_raw_stream_banner(self) -> None:
        lines = safety_banner(cfg(), "klaxon-masked-customer-a-v5-*")
        assert "RAW STREAM QUERY" not in tags(lines)

    def test_banner_never_contains_salt_or_tokens(self) -> None:
        # Only the condition + reason + index pattern; no salt, no raw values,
        # no token shapes.
        for index in ("wazuh-events-v5-*", "klaxon-masked-customer-a-v5-*"):
            for line in safety_banner(
                cfg(enabled=False, whitelist_enabled=False), index
            ):
                assert TEST_SALT not in line
                assert "[USER_" not in line and "[IP_" not in line


# --------------------------------------------------------------------------- #
# End to end through the `search` tool (banner first, before other diagnostics)
# --------------------------------------------------------------------------- #

PAYLOAD: dict[str, Any] = {
    "took": 3,
    "timed_out": False,
    "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
}


class RecordingIndexer:
    async def post(self, path: str, body: Any = None) -> Response:
        return Response(200, json.dumps(PAYLOAD), f"https://indexer.example{path}")


@pytest.fixture
def run_search() -> Iterator[Any]:
    """Install a stub indexer, a fresh config and a freshly built anonymizer."""
    previous_indexer = server._indexer
    previous_config = server._config
    previous_anon = server._anonymizer

    def install(**kw: Any) -> None:
        server._config = make_config(**kw)
        server._anonymizer = None  # type: ignore[assignment]
        server._indexer = RecordingIndexer()  # type: ignore[assignment]

    install()
    try:
        yield install
    finally:
        server._indexer = previous_indexer
        server._config = previous_config
        server._anonymizer = previous_anon


async def run(index: str, body: dict[str, Any]) -> str:
    return await search(index=index, body=json.dumps(body))


def first_notice(out: str) -> str:
    for line in out.splitlines():
        if line.startswith("- ["):
            return line.lstrip("- ")
    return ""


class TestSearchBanner:
    async def test_banner_is_first_diagnostics_line(self, run_search: Any) -> None:
        # Masking off + raw events query: both banners, before [ZERO HITS].
        run_search(enabled=False)
        out = await run("wazuh-events-v5-*", {"query": {"match_all": {}}})
        first = first_notice(out)
        assert first.startswith(("[UNMASKED MODE]", "[RAW STREAM QUERY]"))
        assert "[ZERO HITS]" in out
        assert out.index("[UNMASKED MODE]") < out.index("[ZERO HITS]")

    async def test_raw_query_banner_on_zero_hits(self, run_search: Any) -> None:
        run_search()
        out = await run("wazuh-events-v5-*", {"query": {"match_all": {}}})
        assert "[RAW STREAM QUERY]" in out
        assert "[ZERO HITS]" in out
        assert out.index("[RAW STREAM QUERY]") < out.index("[ZERO HITS]")

    async def test_safe_state_no_banner(self, run_search: Any) -> None:
        run_search(llm_base_url="http://127.0.0.1:11434")
        out = await run("klaxon-masked-customer-a-v5-*", {"query": {"match_all": {}}})
        assert "[UNMASKED MODE]" not in out
        assert "[RAW STREAM QUERY]" not in out

    async def test_external_gate_off_banner_on_masked_index(self, run_search: Any) -> None:
        run_search(llm_base_url="https://api.deepseek.com", whitelist_enabled=False)
        out = await run("klaxon-masked-customer-a-v5-*", {"query": {"match_all": {}}})
        assert "[UNMASKED MODE]" in out
        assert "[RAW STREAM QUERY]" not in out
