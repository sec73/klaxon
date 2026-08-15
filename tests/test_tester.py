# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""tester_sessions: which engine environments exist, and which of them work.

`logtest` reports a missing environment as HTTP 200 with the failure nested in
message.normalization. Without this tool the next question — "then which
environments *do* exist?" — has no answer short of reading engine source. The
cases here are the ones where the table is served successfully and still does
not mean what it appears to: an empty list, a DISABLED session, an ERROR status.

Route and payload shapes are from v5.0.0-beta4:
api/tester/include/api/tester/handlers.hpp:37-42 and proto/src/tester.proto:23-32.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from klaxon_mcp import server
from klaxon_mcp.clients import EngineClient, Response, TransportError
from klaxon_mcp.config import Config
from klaxon_mcp.constants import TESTER_TABLE_GET
from klaxon_mcp.diagnostics import session_state, tester_notices
from klaxon_mcp.server import tester_sessions


def config_with(engine_url: str) -> Config:
    return Config(
        indexer_url="https://indexer.example:9200",
        indexer_user="",
        indexer_password="",
        manager_url="",
        manager_user="",
        manager_password="",
        engine_url=engine_url,
        verify_ssl=False,
        timeout=60.0,
        schema_field_limit=200,
        schema_probe_batch=100,
        search_max_size=100,
        logtest_default_trace_level="ASSET_ONLY",
        logtest_default_space="custom",
    )


def session(
    name: str,
    *,
    namespace: str = "wazuh",
    status: Any = "ENABLED",
    lifetime: int = 0,
    last_use: int = 1_760_000_000,
    description: str | None = None,
) -> dict[str, Any]:
    """A Session as tester.proto:23-32 defines it."""
    entry: dict[str, Any] = {
        "name": name,
        "namespaceId": namespace,
        "lifetime": lifetime,
        "entry_status": status,
        "last_use": last_use,
    }
    if description is not None:
        entry["description"] = description
    return entry


def tags(text: str) -> set[str]:
    return {
        line.split("]")[0].lstrip("- [")
        for line in text.splitlines()
        if line.startswith("- [")
    }


class StubEngine:
    """Stands in for the engine's HTTP server; records what was requested."""

    def __init__(self, payload: Any, status: int = 200) -> None:
        self.payload = payload
        self.status = status
        self.calls: list[str] = []

    async def post(self, path: str, *, body: Any | None = None) -> Response:
        self.calls.append(path)
        text = self.payload if isinstance(self.payload, str) else json.dumps(self.payload)
        return Response(self.status, text, f"https://engine.example{path}")


@pytest.fixture
def engine() -> Iterator[Any]:
    """Install a stub engine client and a config that has KLAXON_ENGINE_URL set."""
    previous_client = server._engine
    previous_config = server._config
    server._config = config_with("https://manager.example:5000")

    def install(payload: Any, status: int = 200) -> StubEngine:
        stub = StubEngine(payload, status)
        server._engine = stub  # type: ignore[assignment]
        return stub

    try:
        yield install
    finally:
        server._engine = previous_client
        server._config = previous_config


TABLE = {
    "status": "OK",
    "sessions": [
        session("standard", lifetime=0, description="shipped ruleset"),
        session("custom", lifetime=3600),
    ],
}


class TestSuccessfulListing:
    async def test_sessions_are_tabulated(self, engine: Any) -> None:
        stub = engine(TABLE)
        out = await tester_sessions()

        assert stub.calls == [TESTER_TABLE_GET]
        assert "NAME" in out and "NAMESPACE" in out and "STATUS" in out
        assert "LIFETIME" in out and "LAST_USE" in out
        assert "standard" in out
        assert "custom" in out
        assert "wazuh" in out
        assert "3600" in out
        assert "sessions: 2" in out

    async def test_raw_response_is_still_returned_verbatim(self, engine: Any) -> None:
        """The table is an addition to the payload, never a replacement for it."""
        engine(TABLE)
        out = await tester_sessions()
        raw = out.split("=== RAW RESPONSE ===")[1]
        body = raw.split("\n", 1)[1].split("\nrequest: POST")[0]
        assert json.loads(body) == TABLE

    async def test_healthy_table_produces_no_notices(self, engine: Any) -> None:
        engine(TABLE)
        out = await tester_sessions()
        assert "DIAGNOSTICS" not in out

    async def test_descriptions_are_shown(self, engine: Any) -> None:
        engine(TABLE)
        out = await tester_sessions()
        assert "shipped ruleset" in out

    async def test_numeric_entry_status_is_named(self, engine: Any) -> None:
        """A build serialising the enum as an int must not print a bare '2'."""
        engine({"status": "OK", "sessions": [session("custom", status=2)]})
        out = await tester_sessions()
        assert "ENABLED" in out

    async def test_missing_fields_render_as_placeholders(self, engine: Any) -> None:
        engine({"status": "OK", "sessions": [{"name": "custom"}]})
        out = await tester_sessions()
        assert "custom" in out
        assert "-" in out


class TestDisabledSession:
    async def test_disabled_session_is_flagged(self, engine: Any) -> None:
        """An existing but inactive session explains a logtest failure just as well."""
        engine({"status": "OK", "sessions": [session("custom", status="DISABLED")]})
        out = await tester_sessions()
        assert "SESSION DISABLED" in tags(out)
        assert "'custom'" in out
        assert "DISABLED" in out

    async def test_numeric_disabled_is_flagged_too(self, engine: Any) -> None:
        """tester.proto:8-13 — DISABLED is 1."""
        engine({"status": "OK", "sessions": [session("custom", status=1)]})
        assert "SESSION DISABLED" in tags(await tester_sessions())

    async def test_enabled_sessions_are_not_flagged(self, engine: Any) -> None:
        engine(TABLE)
        assert "SESSION DISABLED" not in tags(await tester_sessions())

    def test_notice_names_the_namespace(self) -> None:
        notices = tester_notices(
            {"status": "OK", "sessions": [session("custom", namespace="acme", status="DISABLED")]}
        )
        joined = " ".join(notices)
        assert "'acme'" in joined
        assert "space='custom'" in joined


class TestEmptyTable:
    async def test_empty_list_is_reported_as_such(self, engine: Any) -> None:
        """No sessions is a successful answer with consequences, not a failure."""
        engine({"status": "OK", "sessions": []})
        out = await tester_sessions()
        assert "NO TESTER SESSIONS" in tags(out)
        assert "environment does not exist" in out
        assert "sessions: 0" in out
        assert "(no sessions)" in out

    async def test_absent_sessions_field_is_treated_as_empty(self, engine: Any) -> None:
        engine({"status": "OK"})
        assert "NO TESTER SESSIONS" in tags(await tester_sessions())


class TestErrorStatus:
    async def test_error_field_is_passed_through(self, engine: Any) -> None:
        engine({"status": "ERROR", "error": "Tester is not initialized"})
        out = await tester_sessions()
        assert "TESTER ERROR" in tags(out)
        assert "Tester is not initialized" in out
        assert "'ERROR'" in out

    async def test_error_suppresses_the_empty_list_notice(self, engine: Any) -> None:
        """An errored table is unknown, not known to be empty."""
        engine({"status": "ERROR", "error": "boom", "sessions": []})
        found = tags(await tester_sessions())
        assert "TESTER ERROR" in found
        assert "NO TESTER SESSIONS" not in found

    async def test_error_without_status_field_is_still_surfaced(
        self, engine: Any
    ) -> None:
        engine({"error": "Tester is not initialized"})
        assert "TESTER ERROR" in tags(await tester_sessions())

    async def test_non_json_body_does_not_crash(self, engine: Any) -> None:
        engine("<html>proxy error</html>")
        out = await tester_sessions()
        assert "NON-JSON RESPONSE" in tags(out)
        assert "<html>proxy error</html>" in out


class TestHttpFailures:
    async def test_401_names_the_missing_auth_scheme(self, engine: Any) -> None:
        engine({"error": "unauthorized"}, status=401)
        out = await tester_sessions()
        assert "HTTP 401" in tags(out)
        assert "no credentials" in out

    async def test_403_is_handled_like_401(self, engine: Any) -> None:
        engine({"error": "forbidden"}, status=403)
        assert "HTTP 403" in tags(await tester_sessions())

    async def test_404_suggests_the_wrong_host(self, engine: Any) -> None:
        """Pointing KLAXON_ENGINE_URL at the indexer is the likely cause."""
        engine({"error": "not found"}, status=404)
        out = await tester_sessions()
        assert "HTTP 404" in tags(out)
        assert "manager container" in out

    async def test_other_errors_are_passed_through(self, engine: Any) -> None:
        engine({"error": "boom"}, status=500)
        out = await tester_sessions()
        assert "HTTP 500" in tags(out)
        assert "boom" in out


class TestMissingConfiguration:
    async def test_absent_engine_url_is_a_clear_message(self) -> None:
        """No URL must name the variable, not fail somewhere in httpx."""
        previous_client, previous_config = server._engine, server._config
        server._engine = None
        server._config = config_with("")
        try:
            with pytest.raises(ToolError) as exc:
                await tester_sessions()
        finally:
            server._engine, server._config = previous_client, previous_config

        message = str(exc.value)
        assert "KLAXON_ENGINE_URL" in message
        assert "tester_sessions" in message
        # The most likely misconfiguration is pointing it at one of the other two.
        assert "KLAXON_INDEXER_URL" in message
        assert "KLAXON_MANAGER_URL" in message

    async def test_client_refuses_before_opening_a_connection(self) -> None:
        with pytest.raises(TransportError) as exc:
            await EngineClient(config_with("")).post(TESTER_TABLE_GET)
        assert "KLAXON_ENGINE_URL" in str(exc.value)


class TestReadOnly:
    async def test_only_list_is_accepted(self, engine: Any) -> None:
        """The mutating routes stay unexposed; the refusal has to say why."""
        stub = engine(TABLE)
        with pytest.raises(ToolError) as exc:
            await tester_sessions(action="create")
        message = str(exc.value)
        assert "read-only" in message
        assert "session/post" in message
        assert stub.calls == []

    async def test_action_is_normalised(self, engine: Any) -> None:
        engine(TABLE)
        assert "sessions: 2" in await tester_sessions(action="  LIST ")


class TestStateNormalisation:
    def test_known_names_pass_through(self) -> None:
        assert session_state({"entry_status": "enabled"}) == "ENABLED"

    def test_numeric_states_follow_the_proto(self) -> None:
        assert session_state({"entry_status": 0}) == "STATE_UNKNOWN"
        assert session_state({"entry_status": 1}) == "DISABLED"
        assert session_state({"entry_status": 2}) == "ENABLED"

    def test_unknown_number_is_reported_rather_than_guessed(self) -> None:
        assert session_state({"entry_status": 7}) == "UNKNOWN(7)"

    def test_missing_status_is_a_placeholder(self) -> None:
        assert session_state({}) == "?"
