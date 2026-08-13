# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""HTTP clients for the Wazuh indexer and the Wazuh manager API.

Neither client interprets response bodies. They return (status_code, text) and
let the tool layer decide what to say about it. Non-2xx responses are values,
not exceptions — a 404 from /rules is information the caller needs.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from .config import Config
from .constants import MANAGER_AUTH_PATH


class TransportError(RuntimeError):
    """Raised when the request never produced an HTTP response at all."""


class Response:
    """A minimal HTTP response value object."""

    __slots__ = ("status_code", "text", "url")

    def __init__(self, status_code: int, text: str, url: str) -> None:
        self.status_code = status_code
        self.text = text
        self.url = url

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        """Parse the body as JSON, or return None when it is not JSON."""
        try:
            return json.loads(self.text)
        except (ValueError, TypeError):
            return None

    def pretty(self) -> str:
        """Re-serialise the body with indentation when it is JSON, else raw."""
        parsed = self.json()
        if parsed is None:
            return self.text
        return json.dumps(parsed, indent=2, ensure_ascii=False)


class IndexerClient:
    """Basic-auth client for the Wazuh indexer (OpenSearch)."""

    def __init__(self, config: Config) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None

    def _ensure(self) -> httpx.AsyncClient:
        if self._client is None:
            auth: tuple[str, str] | None = None
            if self._config.indexer_user:
                auth = (self._config.indexer_user, self._config.indexer_password)
            self._client = httpx.AsyncClient(
                base_url=self._config.indexer_url,
                auth=auth,
                verify=self._config.verify_ssl,
                timeout=self._config.timeout,
                headers={"Content-Type": "application/json"},
            )
        return self._client

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: Any | None = None,
        timeout: float | None = None,
    ) -> Response:
        """Send a request; raise TransportError only when no HTTP response came.

        `timeout` overrides the client-wide timeout for THIS request (httpx
        per-request override; None uses the client default). The long-running
        `_reindex` needs a much more generous timeout than the short reads the
        default is sized for.
        """
        client = self._ensure()
        try:
            resp = await client.request(
                method,
                path,
                params=params,
                content=json.dumps(body) if body is not None else None,
                timeout=timeout,
            )
        except httpx.HTTPError as exc:
            raise TransportError(
                f"{method} {self._config.indexer_url}{path} failed at transport level: {exc}"
            ) from exc
        return Response(resp.status_code, resp.text, str(resp.url))

    async def get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Response:
        return await self.request("GET", path, params=params, timeout=timeout)

    async def post(
        self,
        path: str,
        *,
        body: Any | None = None,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> Response:
        return await self.request("POST", path, params=params, body=body, timeout=timeout)

    async def put(
        self, path: str, *, body: Any | None = None, params: dict[str, Any] | None = None
    ) -> Response:
        return await self.request("PUT", path, params=params, body=body)

    async def delete(self, path: str, *, params: dict[str, Any] | None = None) -> Response:
        return await self.request("DELETE", path, params=params)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class EngineClient:
    """Client for the engine's internal HTTP API.

    A third base URL because the engine's own HTTP server is a third endpoint:
    it runs inside the manager container and answers neither on the indexer port
    nor on the manager API port. Pointing WAZUH_ENGINE_URL at either of those
    yields a 404 from the wrong server, not a tester response.

    No credentials are sent. Whether that server expects any could not be
    verified against the beta, and inventing a scheme would mean guessing at a
    handshake — so the request goes out bare and a 401/403 is reported as what
    it is rather than retried blindly.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None

    def _ensure(self) -> httpx.AsyncClient:
        if self._client is None:
            if not self._config.engine_url:
                raise TransportError(
                    "WAZUH_ENGINE_URL is not configured; the 'tester_sessions' tool "
                    "is unavailable. The engine's internal API runs inside the "
                    "manager container on its own port — it is neither "
                    "WAZUH_INDEXER_URL nor WAZUH_MANAGER_URL."
                )
            self._client = httpx.AsyncClient(
                base_url=self._config.engine_url,
                verify=self._config.verify_ssl,
                timeout=self._config.timeout,
                headers={"Content-Type": "application/json"},
            )
        return self._client

    async def post(self, path: str, *, body: Any | None = None) -> Response:
        client = self._ensure()
        try:
            resp = await client.post(
                path, content=json.dumps(body if body is not None else {})
            )
        except httpx.HTTPError as exc:
            raise TransportError(
                f"POST {self._config.engine_url}{path} failed at transport level: {exc}"
            ) from exc
        return Response(resp.status_code, resp.text, str(resp.url))

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class ManagerClient:
    """JWT client for the Wazuh manager API.

    Obtains a token via basic auth against /security/user/authenticate, caches
    it, and on a 401 refreshes once before giving up. Deliberately thin: this
    surface breaks at GA (path move /var/ossec -> /var/wazuh-manager, cluster by
    default, agent id 000 removed).

    The handshake is serialised by a lock. Tool calls run concurrently — the MCP
    SDK spawns a task per JSON-RPC request — so without one, N calls arriving on
    a cold cache each perform their own login. That is not merely wasteful: the
    manager API counts logins per source address (max_login_attempts /
    block_time in api.yaml, 5 per 300s by default), so a burst of concurrent
    tool calls can get this server's own IP blocked for minutes.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._auth_lock = asyncio.Lock()

    def _ensure(self) -> httpx.AsyncClient:
        if self._client is None:
            if not self._config.manager_url:
                raise TransportError(
                    "WAZUH_MANAGER_URL is not configured; the 'manager' tool is unavailable"
                )
            self._client = httpx.AsyncClient(
                base_url=self._config.manager_url,
                verify=self._config.verify_ssl,
                timeout=self._config.timeout,
            )
        return self._client

    async def _authenticate(self, *, stale: str | None = None) -> str:
        """Obtain a JWT, at most one handshake at a time.

        `stale` is the token the caller just saw rejected, or None when it had
        none at all. Under the lock the cache is re-read: if it now holds
        something other than `stale`, another request already refreshed it and
        this call returns that token instead of logging in again. Concurrent
        401s therefore produce one handshake, not one each.
        """
        async with self._auth_lock:
            cached = self._token
            if cached is not None and cached != stale:
                return cached
            return await self._login()

    async def _login(self) -> str:
        """The handshake itself. Called only with `_auth_lock` held."""
        client = self._ensure()
        try:
            resp = await client.post(
                MANAGER_AUTH_PATH,
                auth=(self._config.manager_user, self._config.manager_password),
            )
        except httpx.HTTPError as exc:
            raise TransportError(
                f"manager authentication failed at transport level: {exc}"
            ) from exc

        if resp.status_code != 200:
            raise TransportError(
                f"manager authentication returned HTTP {resp.status_code}: {resp.text}"
            )

        try:
            payload = resp.json()
            token = payload["data"]["token"]
        except (ValueError, KeyError, TypeError) as exc:
            raise TransportError(
                "manager authentication response did not contain data.token: "
                f"{resp.text[:400]}"
            ) from exc

        if not isinstance(token, str) or not token:
            raise TransportError("manager authentication returned an empty token")

        self._token = token
        return token

    async def get(self, path: str, *, params: dict[str, Any] | None = None) -> Response:
        """GET a manager path, refreshing the JWT once on 401."""
        client = self._ensure()
        token = self._token or await self._authenticate()

        async def _issue(bearer: str) -> httpx.Response:
            try:
                return await client.get(
                    path,
                    params=params,
                    headers={"Authorization": f"Bearer {bearer}"},
                )
            except httpx.HTTPError as exc:
                raise TransportError(
                    f"GET {self._config.manager_url}{path} failed at transport level: {exc}"
                ) from exc

        resp = await _issue(token)
        if resp.status_code == 401:
            # Token expired or revoked. Refresh exactly once — handing the
            # rejected token to _authenticate rather than clearing the cache
            # here, because clearing it would also discard a *newer* token that
            # a concurrent request had already fetched, and send this one back
            # for a login it does not need.
            resp = await _issue(await self._authenticate(stale=token))

        return Response(resp.status_code, resp.text, str(resp.url))

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._token = None
