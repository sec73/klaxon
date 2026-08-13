# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The manager JWT handshake under concurrency.

Tool calls do not arrive one at a time — the MCP SDK spawns a task per JSON-RPC
request, so several `manager` calls can be inside ManagerClient.get() at once.
The cache is a mutable field read and written across `await` points, which makes
these the tests that matter for it: not "does a token get fetched" but "how many
times", because the manager API counts logins per source address and blocks the
caller that makes too many.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from klaxon_mcp.clients import IndexerClient, ManagerClient, TransportError
from klaxon_mcp.config import Config

MANAGER_URL = "https://manager.example:55000"


def make_config() -> Config:
    return Config(
        indexer_url="https://indexer.example:9200",
        indexer_user="admin",
        indexer_password="secret",
        manager_url=MANAGER_URL,
        manager_user="wazuh",
        manager_password="secret",
        engine_url="",
        verify_ssl=True,
        timeout=5.0,
        schema_field_limit=200,
        schema_probe_batch=100,
        search_max_size=100,
        logtest_default_trace_level="ASSET_ONLY",
        logtest_default_space="custom",
    )


class FakeManagerAPI:
    """A manager API that counts logins and can reject a named token.

    `reject` is the token value that answers 401 — the shape of an expired JWT.
    Every handshake hands out a new one, so the test can tell a refresh that
    reused a concurrent request's token from one that logged in again.
    """

    def __init__(self, reject: str | None = None, latency: float = 0.01) -> None:
        self.logins = 0
        self.reject = reject
        self.latency = latency
        self.bearers: list[str | None] = []

    def _response(self, status: int, text: str, path: str) -> httpx.Response:
        return httpx.Response(
            status, text=text, request=httpx.Request("GET", MANAGER_URL + path)
        )

    async def post(self, path: str, *, auth: Any = None) -> httpx.Response:
        await asyncio.sleep(self.latency)
        self.logins += 1
        token = f"token-{self.logins}"
        return self._response(200, '{"data": {"token": "%s"}}' % token, path)

    async def get(
        self, path: str, *, params: Any = None, headers: Any = None
    ) -> httpx.Response:
        bearer = (headers or {}).get("Authorization", "").removeprefix("Bearer ")
        self.bearers.append(bearer)
        await asyncio.sleep(self.latency)
        if self.reject is not None and bearer == self.reject:
            return self._response(401, '{"title": "Unauthorized"}', path)
        return self._response(200, '{"data": {"affected_items": []}}', path)


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> tuple[ManagerClient, FakeManagerAPI]:
    api = FakeManagerAPI()
    manager = ManagerClient(make_config())
    monkeypatch.setattr(manager, "_ensure", lambda: api)
    return manager, api


class TestConcurrentAuthentication:
    async def test_a_cold_cache_produces_one_login_not_one_per_call(
        self, client: tuple[ManagerClient, FakeManagerAPI]
    ) -> None:
        """The finding: eight concurrent calls used to mean eight logins.

        The manager API's brute-force protection (max_login_attempts, 5 per
        block_time by default) treats that as an attack on itself and blocks the
        source address — a server that DoSes its own credentials on startup.
        """
        manager, api = client
        responses = await asyncio.gather(*(manager.get("/agents") for _ in range(8)))

        assert api.logins == 1
        assert all(r.status_code == 200 for r in responses)
        assert set(api.bearers) == {"token-1"}

    async def test_concurrent_401s_refresh_once_between_them(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An expired token is refreshed once, not once per request holding it."""
        api = FakeManagerAPI()
        manager = ManagerClient(make_config())
        monkeypatch.setattr(manager, "_ensure", lambda: api)

        # Prime the cache, then expire that token server-side.
        await manager.get("/agents")
        assert api.logins == 1
        api.reject = "token-1"

        responses = await asyncio.gather(*(manager.get("/agents") for _ in range(6)))

        assert api.logins == 2, "one refresh for all six concurrent 401s"
        assert all(r.status_code == 200 for r in responses)

    async def test_a_refresh_does_not_discard_a_newer_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The lost update: clearing the cache would throw away a valid token.

        A request that hits a 401 hands the rejected token to _authenticate
        rather than blanking `_token`, so it cannot invalidate a fresher one a
        concurrent request has already stored.
        """
        api = FakeManagerAPI()
        manager = ManagerClient(make_config())
        monkeypatch.setattr(manager, "_ensure", lambda: api)

        await manager.get("/agents")
        api.reject = "token-1"
        await manager.get("/agents")  # refreshes to token-2
        assert api.logins == 2

        # A late arrival still carrying token-1 must not send everyone back to
        # the login endpoint.
        assert await manager._authenticate(stale="token-1") == "token-2"
        assert api.logins == 2

    async def test_serialised_calls_reuse_the_cached_token(
        self, client: tuple[ManagerClient, FakeManagerAPI]
    ) -> None:
        manager, api = client
        for _ in range(4):
            await manager.get("/agents")
        assert api.logins == 1


class TestAuthenticationFailures:
    async def test_a_non_200_handshake_raises_and_caches_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        api = FakeManagerAPI()

        async def refuse(path: str, *, auth: Any = None) -> httpx.Response:
            api.logins += 1
            return httpx.Response(
                403,
                text='{"title": "Forbidden"}',
                request=httpx.Request("POST", MANAGER_URL + path),
            )

        monkeypatch.setattr(api, "post", refuse)
        manager = ManagerClient(make_config())
        monkeypatch.setattr(manager, "_ensure", lambda: api)

        with pytest.raises(TransportError, match="HTTP 403"):
            await manager.get("/agents")
        assert manager._token is None

    async def test_the_lock_is_released_when_the_handshake_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failed login must not wedge every later call on the lock."""
        api = FakeManagerAPI()
        calls = {"n": 0}

        async def fail_once(path: str, *, auth: Any = None) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                raise httpx.ConnectError("connection refused")
            return await FakeManagerAPI.post(api, path, auth=auth)

        monkeypatch.setattr(api, "post", fail_once)
        manager = ManagerClient(make_config())
        monkeypatch.setattr(manager, "_ensure", lambda: api)

        with pytest.raises(TransportError):
            await manager.get("/agents")

        response = await asyncio.wait_for(manager.get("/agents"), timeout=2)
        assert response.status_code == 200


class TestIndexerClientPerRequestTimeout:
    """IndexerClient.request forwards a per-request `timeout` to httpx (None
    keeps the client-wide default). The long-running `_reindex` needs a much
    more generous timeout than the short reads the default is sized for."""

    async def test_timeout_is_forwarded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, Any] = {}

        class FakeHttp:
            async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
                seen["timeout"] = kwargs.get("timeout")
                return httpx.Response(
                    200, text="{}", request=httpx.Request(method, url)
                )

        client = IndexerClient(make_config())
        monkeypatch.setattr(client, "_ensure", lambda: FakeHttp())

        await client.get("/_tasks/node:1", timeout=123.0)
        assert seen["timeout"] == 123.0

        # No timeout -> the httpx client default applies (None forwarded).
        await client.post("/_reindex", body={"source": {}})
        assert seen["timeout"] is None

    async def test_transport_error_still_raised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class Boom:
            async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
                raise httpx.ReadTimeout("read timed out")

        client = IndexerClient(make_config())
        monkeypatch.setattr(client, "_ensure", lambda: Boom())
        with pytest.raises(TransportError, match="failed at transport level"):
            await client.post("/_reindex", body={}, timeout=1800.0)
