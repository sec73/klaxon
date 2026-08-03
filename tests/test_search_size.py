# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The size cap: bounded output, but never a quietly shortened one.

Capping is the only place where this server sends something other than what the
caller wrote. A caller that asks for 500 documents, receives 100 and is not told
would be reading a partial result as a complete one — the exact failure the
diagnostics layer exists to prevent. So every test here checks the pair: what
went out on the wire, and what the caller was told about it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from klaxon_mcp import server
from klaxon_mcp.clients import Response
from klaxon_mcp.config import Config, ConfigError
from klaxon_mcp.server import _cap_size, search

EMPTY_RESULT: dict[str, Any] = {
    "hits": {"total": {"value": 4200, "relation": "eq"}, "hits": []}
}


def config_with(search_max_size: int) -> Config:
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
        search_max_size=search_max_size,
        logtest_default_trace_level="ASSET_ONLY",
        logtest_default_space="custom",
    )


class RecordingIndexer:
    """Captures the body actually sent, which is what the cap has to change."""

    def __init__(self) -> None:
        self.sent: Any = None

    async def post(self, path: str, body: Any = None) -> Response:
        self.sent = body
        return Response(200, json.dumps(EMPTY_RESULT), f"https://indexer.example{path}")


@pytest.fixture
def indexer() -> Iterator[RecordingIndexer]:
    """Install a stub indexer; the limit is set per test via `limit`."""
    client = RecordingIndexer()
    previous = server._indexer
    server._indexer = client  # type: ignore[assignment]
    try:
        yield client
    finally:
        server._indexer = previous


@pytest.fixture
def limit() -> Iterator[Any]:
    """Install a config with a given search_max_size, defaulting to 100."""
    previous = server._config

    def install(value: int) -> None:
        server._config = config_with(value)

    install(100)
    try:
        yield install
    finally:
        server._config = previous


async def run(body: dict[str, Any]) -> str:
    return await search(index="wazuh-events-v5-*", body=json.dumps(body))


class TestCapApplied:
    async def test_oversized_request_is_lowered_on_the_wire(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        """The cap has to bite before the query goes out, not after it returns."""
        await run({"size": 10_000, "query": {"match_all": {}}})
        assert indexer.sent["size"] == 100
        # Everything else in the body survives untouched.
        assert indexer.sent["query"] == {"match_all": {}}

    async def test_the_caller_is_told_both_numbers(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        """A shortened result the caller never hears about is the bug we avoid."""
        out = await run({"size": 500})
        assert "[SIZE CAPPED]" in out
        assert "500" in out
        assert "100" in out
        assert "WAZUH_SEARCH_MAX_SIZE" in out

    async def test_notice_survives_an_error_response(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        """search_notices returns early on a non-2xx; the cap notice must not be lost."""

        async def failing(path: str, body: Any = None) -> Response:
            indexer.sent = body
            return Response(400, json.dumps({"error": {"type": "parsing_exception"}}), path)

        indexer.post = failing  # type: ignore[method-assign]
        out = await run({"size": 500})
        assert "[SIZE CAPPED]" in out
        assert "HTTP 400" in out

    async def test_exactly_at_the_limit_is_not_capped(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        out = await run({"size": 100})
        assert indexer.sent["size"] == 100
        assert "[SIZE CAPPED]" not in out


class TestCapNotApplied:
    async def test_size_below_limit_passes_through(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        out = await run({"size": 25, "query": {"match_all": {}}})
        assert indexer.sent["size"] == 25
        assert "[SIZE CAPPED]" not in out

    async def test_size_zero_is_untouched(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        """size: 0 is the normal shape of an aggregation-only query."""
        out = await run({"size": 0, "aggs": {"a": {"terms": {"field": "event.action"}}}})
        assert indexer.sent["size"] == 0
        assert "[SIZE CAPPED]" not in out

    async def test_absent_size_stays_absent(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        """Injecting a size would change the meaning of a body that had none."""
        out = await run({"query": {"match_all": {}}})
        assert "size" not in indexer.sent
        assert "[SIZE CAPPED]" not in out

    async def test_limit_zero_disables_the_cap(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        limit(0)
        out = await run({"size": 10_000})
        assert indexer.sent["size"] == 10_000
        assert "[SIZE CAPPED]" not in out

    async def test_negative_limit_disables_the_cap(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        limit(-1)
        out = await run({"size": 10_000})
        assert indexer.sent["size"] == 10_000
        assert "[SIZE CAPPED]" not in out


class TestBodyHandling:
    async def test_invalid_json_still_raises_the_existing_error(
        self, indexer: RecordingIndexer, limit: Any
    ) -> None:
        """The cap must not run before, or in place of, the body parse."""
        with pytest.raises(ToolError) as exc:
            await search(index="wazuh-events-v5-*", body="{not json")
        assert "body is not valid JSON" in str(exc.value)
        assert indexer.sent is None

    def test_non_dict_body_is_left_alone(self) -> None:
        """A JSON array parses fine but has no `size` to cap."""
        assert _cap_size([1, 2, 3], 100) is None

    def test_non_integer_size_is_left_to_the_indexer(self) -> None:
        body: dict[str, Any] = {"size": "500"}
        assert _cap_size(body, 100) is None
        assert body["size"] == "500"

    def test_boolean_size_is_not_rewritten_to_a_number(self) -> None:
        """bool is an int subclass; "size": true is malformed, not oversized."""
        body: dict[str, Any] = {"size": True}
        assert _cap_size(body, 100) is None
        assert body["size"] is True


class TestConfiguration:
    def test_default_is_one_hundred(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example:9200")
        monkeypatch.delenv("WAZUH_SEARCH_MAX_SIZE", raising=False)
        assert Config.from_env().search_max_size == 100

    def test_disabling_the_cap_warns_at_startup(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Running without the cap is a choice, not a state to discover later."""
        monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example:9200")
        monkeypatch.setenv("WAZUH_SEARCH_MAX_SIZE", "0")
        with caplog.at_level("WARNING", logger="klaxon_mcp.config"):
            assert Config.from_env().search_max_size == 0
        assert "WAZUH_SEARCH_MAX_SIZE" in caplog.text

    def test_valid_value_is_silent(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example:9200")
        monkeypatch.setenv("WAZUH_SEARCH_MAX_SIZE", "250")
        with caplog.at_level("WARNING", logger="klaxon_mcp.config"):
            assert Config.from_env().search_max_size == 250
        assert caplog.text == ""

    def test_non_integer_value_is_a_config_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WAZUH_INDEXER_URL", "https://indexer.example:9200")
        monkeypatch.setenv("WAZUH_SEARCH_MAX_SIZE", "many")
        with pytest.raises(ConfigError) as exc:
            Config.from_env()
        assert "WAZUH_SEARCH_MAX_SIZE" in str(exc.value)
