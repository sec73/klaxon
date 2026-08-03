# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Serving the MCP server over stdio or HTTP.

Running this over a network is a materially different security proposition from
running it over stdio. On stdio the process is spawned by the MCP client and
inherits its trust boundary. On HTTP it is a listening socket holding Wazuh
credentials: anyone who can reach the port can query the whole SIEM, because the
tools themselves have no notion of a caller identity.

So the networked path here is deliberately noisy about the two things that
actually protect it — a bearer token and DNS rebinding protection — and refuses
to bind a non-loopback interface unauthenticated unless that is stated
explicitly.
"""

from __future__ import annotations

import hmac
import json
import logging
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from mcp.server.transport_security import TransportSecuritySettings

from .config import TransportConfig

logger = logging.getLogger("klaxon_mcp.transport")

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

HEALTH_PATH = "/healthz"


class BearerAuthMiddleware:
    """Require `Authorization: Bearer <token>` on every request.

    The SDK's own auth path (`token_verifier`) cannot be used without a full
    OAuth `AuthSettings` block — the server raises "Cannot specify
    auth_server_provider or token_verifier without auth settings". For a
    single-operator deployment behind a reverse proxy, a shared secret is the
    proportionate control, so it is implemented here as plain ASGI middleware.

    This is not OAuth and does not pretend to be. It is one static credential;
    rotate it by restarting with a new value.

    The comparison runs on raw bytes. Decoding the header to `str` first is the
    obvious version and it is wrong: `hmac.compare_digest` refuses a `str`
    holding non-ASCII, so a header of `Authorization: \\xff` raised TypeError
    where a 401 belonged — an unhandled 500 that any unauthenticated caller
    could trigger at will, on the one code path that is reachable before
    authentication.
    """

    def __init__(self, app: ASGIApp, token: str) -> None:
        self._app = app
        # Precomputed so the per-request path is a comparison and nothing else.
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        # Unauthenticated liveness probe. Returns no Wazuh data of any kind.
        if scope.get("path") == HEALTH_PATH:
            await _respond_json(send, 200, {"status": "ok"})
            return

        offered = [
            value
            for name, value in scope.get("headers", [])
            if name.lower() == b"authorization"
        ]

        # Exactly one header, or none. A request carrying two is rejected rather
        # than resolved: taking one of them — the earlier dict comprehension
        # silently kept the last — lets this server authenticate against a
        # different value than the reverse proxy in front of it read, which is
        # the setup for a header-smuggling bypass.
        presented = offered[0] if len(offered) == 1 else b""

        # Constant-time comparison: a length-sensitive == would leak the token
        # prefix to anyone able to time the response.
        if not hmac.compare_digest(presented, self._expected):
            client = scope.get("client")
            logger.warning(
                "rejected unauthenticated request to %s from %s%s",
                scope.get("path"),
                client[0] if client else "unknown",
                f" ({len(offered)} Authorization headers)" if len(offered) > 1 else "",
            )
            await _respond_json(
                send,
                401,
                {"error": "unauthorized", "detail": "valid bearer token required"},
                extra_headers=[(b"www-authenticate", b'Bearer realm="klaxon-mcp"')],
            )
            return

        await self._app(scope, receive, send)


async def _respond_json(
    send: Send,
    status: int,
    payload: dict[str, str],
    *,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    body = json.dumps(payload).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    headers.extend(extra_headers or [])
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def build_transport_security(cfg: TransportConfig) -> TransportSecuritySettings:
    """Configure DNS rebinding protection.

    The SDK defaults this to *disabled* when no settings object is passed, so it
    is always constructed explicitly here rather than left to the default.
    """
    if cfg.allowed_hosts or cfg.allowed_origins:
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(cfg.allowed_hosts),
            allowed_origins=list(cfg.allowed_origins),
        )

    if not cfg.is_networked:
        # Loopback bind: lock the Host header to loopback names.
        return TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*"],
            allowed_origins=[
                "http://127.0.0.1:*",
                "http://localhost:*",
                "http://[::1]:*",
            ],
        )

    # Bound to a real interface with no allowlist. Enabling protection with an
    # empty allowlist would reject every request, so it stays off — and says so.
    logger.warning(
        "DNS rebinding protection is DISABLED: listening on %s with no "
        "WAZUH_MCP_ALLOWED_HOSTS. Set it to the hostname clients use, "
        "e.g. WAZUH_MCP_ALLOWED_HOSTS=klaxon-mcp.example:8000",
        cfg.host,
    )
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


def preflight(cfg: TransportConfig) -> None:
    """Warn about configurations that expose Wazuh, before the socket opens."""
    if cfg.transport == "stdio":
        return

    if cfg.is_unauthenticated_network_listener:
        logger.warning(
            "SERVING WITHOUT AUTHENTICATION on %s:%s. Every tool in this server "
            "reaches your Wazuh indexer with the configured credentials, so "
            "anyone who can open a TCP connection to this port can read the SIEM. "
            "Set WAZUH_MCP_AUTH_TOKEN, or bind 127.0.0.1 and front it with a "
            "reverse proxy that terminates TLS and authenticates.",
            cfg.host,
            cfg.port,
        )
    elif cfg.auth_token:
        logger.info("bearer authentication enabled")

    if cfg.transport == "sse":
        logger.warning(
            "The 'sse' transport is the legacy MCP HTTP transport. Prefer "
            "'http' (streamable HTTP) unless a client requires SSE."
        )


def serve(mcp: Any, cfg: TransportConfig) -> None:
    """Run the server on the configured transport. Blocks until shutdown."""
    preflight(cfg)

    if cfg.transport == "stdio":
        mcp.run()
        return

    import uvicorn

    security = build_transport_security(cfg)

    if cfg.transport == "sse":
        app: ASGIApp = mcp.sse_app(transport_security=security, host=cfg.host)
    else:
        app = mcp.streamable_http_app(
            streamable_http_path=cfg.path,
            json_response=cfg.json_response,
            stateless_http=cfg.stateless,
            transport_security=security,
            host=cfg.host,
        )

    if cfg.auth_token:
        app = BearerAuthMiddleware(app, cfg.auth_token)

    endpoint = cfg.path if cfg.transport == "http" else "/sse"
    logger.info("serving MCP over %s at %s:%s%s", cfg.transport, cfg.host, cfg.port, endpoint)

    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="info")
