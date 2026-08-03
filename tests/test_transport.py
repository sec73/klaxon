# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Serving over a network: bearer auth and DNS rebinding protection."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from klaxon_mcp.config import TransportConfig
from klaxon_mcp.transport import (
    BearerAuthMiddleware,
    build_transport_security,
    preflight,
)


def cfg(**over: Any) -> TransportConfig:
    base: dict[str, Any] = {
        "transport": "http",
        "host": "127.0.0.1",
        "port": 8000,
        "path": "/mcp",
        "auth_token": "",
        "allowed_hosts": (),
        "allowed_origins": (),
        "json_response": False,
        "stateless": False,
    }
    base.update(over)
    return TransportConfig(**base)


class Recorder:
    """Collects ASGI messages sent by the middleware."""

    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def __call__(self, message: dict[str, Any]) -> None:
        self.messages.append(message)

    @property
    def status(self) -> int | None:
        for m in self.messages:
            if m["type"] == "http.response.start":
                return int(m["status"])
        return None

    @property
    def body(self) -> Any:
        for m in self.messages:
            if m["type"] == "http.response.body":
                return json.loads(m["body"])
        return None

    @property
    def headers(self) -> dict[bytes, bytes]:
        for m in self.messages:
            if m["type"] == "http.response.start":
                return dict(m["headers"])
        return {}


class SpyApp:
    def __init__(self) -> None:
        self.called = False

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        self.called = True


async def noop_receive() -> dict[str, Any]:  # pragma: no cover
    return {"type": "http.request"}


def http_scope(auth: str | None = None, path: str = "/mcp") -> dict[str, Any]:
    headers: list[tuple[bytes, bytes]] = []
    if auth is not None:
        headers.append((b"authorization", auth.encode()))
    return {"type": "http", "path": path, "headers": headers, "client": ("10.0.0.5", 51234)}


def raw_scope(*headers: tuple[bytes, bytes], path: str = "/mcp") -> dict[str, Any]:
    """A scope built from raw header bytes, for what `str` cannot express.

    ASGI carries headers as bytes, and a client is free to send any of them. The
    str-based helper above cannot represent a header that is not valid UTF-8, or
    a request that sends the same header twice — both of which reach this
    middleware before any authentication has happened.
    """
    return {
        "type": "http",
        "path": path,
        "headers": list(headers),
        "client": ("10.0.0.5", 51234),
    }


class TestBearerAuth:
    async def test_correct_token_passes_through(self) -> None:
        app = SpyApp()
        mw = BearerAuthMiddleware(app, "s3cret")
        rec = Recorder()
        await mw(http_scope("Bearer s3cret"), noop_receive, rec)
        assert app.called
        assert rec.messages == []

    @pytest.mark.parametrize(
        "header",
        [
            None,
            "",
            "Bearer wrong",
            "Bearer",
            "Bearer s3cre",  # prefix of the real token
            "Bearer s3cret ",  # trailing space
            "bearer s3cret",  # scheme is case-sensitive here
            "Basic czNjcmV0",
            "s3cret",  # bare token without the scheme
        ],
    )
    async def test_bad_credentials_are_rejected(self, header: str | None) -> None:
        app = SpyApp()
        mw = BearerAuthMiddleware(app, "s3cret")
        rec = Recorder()
        await mw(http_scope(header), noop_receive, rec)

        assert not app.called, "request reached the MCP app despite bad credentials"
        assert rec.status == 401
        assert rec.body == {
            "error": "unauthorized",
            "detail": "valid bearer token required",
        }
        assert rec.headers[b"www-authenticate"] == b'Bearer realm="klaxon-mcp"'

    async def test_health_probe_needs_no_token(self) -> None:
        app = SpyApp()
        mw = BearerAuthMiddleware(app, "s3cret")
        rec = Recorder()
        await mw(http_scope(None, path="/healthz"), noop_receive, rec)
        assert rec.status == 200
        assert rec.body == {"status": "ok"}
        assert not app.called, "health probe must not reach the MCP app"

    async def test_non_http_scopes_pass_through(self) -> None:
        app = SpyApp()
        mw = BearerAuthMiddleware(app, "s3cret")
        await mw({"type": "lifespan"}, noop_receive, Recorder())
        assert app.called

    async def test_header_name_case_is_ignored(self) -> None:
        """ASGI does not promise lowercased names; HTTP/1.1 field names are
        case-insensitive."""
        app = SpyApp()
        mw = BearerAuthMiddleware(app, "s3cret")
        await mw(
            raw_scope((b"Authorization", b"Bearer s3cret")), noop_receive, Recorder()
        )
        assert app.called


class TestMalformedAuthorizationHeader:
    """Header shapes that must produce a 401 rather than an exception.

    This is the pre-authentication code path: every one of these is reachable by
    anyone who can open a socket, so an unhandled error here is a denial of
    service that costs one request to trigger.
    """

    @pytest.mark.parametrize(
        "value",
        [
            b"\xff",  # not valid UTF-8 in any position
            b"Bearer \xff\xfe",  # non-ASCII payload after a valid scheme
            b"Bearer s3cret\xff",  # the real token with one byte appended
            b"\x00" * 8,
            bytes(range(128, 256)),
        ],
    )
    async def test_non_ascii_bytes_are_rejected_not_raised(self, value: bytes) -> None:
        """hmac.compare_digest refuses a str with non-ASCII, so the header used
        to be decoded into a TypeError and a 500."""
        app = SpyApp()
        mw = BearerAuthMiddleware(app, "s3cret")
        rec = Recorder()

        await mw(raw_scope((b"authorization", value)), noop_receive, rec)

        assert not app.called
        assert rec.status == 401

    async def test_duplicate_headers_are_rejected_rather_than_resolved(self) -> None:
        """Two Authorization headers, one of them valid, is not authentication.

        Picking either one means this server can disagree with a proxy in front
        of it about which credential the request carried.
        """
        app = SpyApp()
        mw = BearerAuthMiddleware(app, "s3cret")
        rec = Recorder()

        await mw(
            raw_scope(
                (b"authorization", b"Bearer wrong"),
                (b"authorization", b"Bearer s3cret"),
            ),
            noop_receive,
            rec,
        )

        assert not app.called, "a smuggled second header authenticated the request"
        assert rec.status == 401

    async def test_duplicate_valid_headers_are_rejected_too(self) -> None:
        app = SpyApp()
        mw = BearerAuthMiddleware(app, "s3cret")
        rec = Recorder()
        await mw(
            raw_scope(
                (b"authorization", b"Bearer s3cret"),
                (b"authorization", b"Bearer s3cret"),
            ),
            noop_receive,
            rec,
        )
        assert not app.called
        assert rec.status == 401

    async def test_the_duplicate_is_named_in_the_log(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A 401 for a token that is present and correct needs an explanation
        somewhere, or it is an unsolvable support call."""
        mw = BearerAuthMiddleware(SpyApp(), "s3cret")
        with caplog.at_level(logging.WARNING, logger="klaxon_mcp.transport"):
            await mw(
                raw_scope(
                    (b"authorization", b"Bearer s3cret"),
                    (b"authorization", b"Bearer s3cret"),
                ),
                noop_receive,
                Recorder(),
            )
        assert "2 Authorization headers" in caplog.text

    async def test_a_non_utf8_token_still_authenticates(self) -> None:
        """The token comes from the environment and is not required to be hex."""
        token = "sécret"
        app = SpyApp()
        mw = BearerAuthMiddleware(app, token)
        await mw(
            raw_scope((b"authorization", f"Bearer {token}".encode())),
            noop_receive,
            Recorder(),
        )
        assert app.called


class TestTransportSecurity:
    def test_loopback_gets_rebinding_protection_by_default(self) -> None:
        """The SDK leaves this off when unset, so it must be set explicitly."""
        settings = build_transport_security(cfg(host="127.0.0.1"))
        assert settings.enable_dns_rebinding_protection
        assert "127.0.0.1:*" in settings.allowed_hosts

    def test_explicit_allowlist_is_honoured(self) -> None:
        settings = build_transport_security(
            cfg(host="0.0.0.0", allowed_hosts=("klaxon-mcp.example:8000",))
        )
        assert settings.enable_dns_rebinding_protection
        assert settings.allowed_hosts == ["klaxon-mcp.example:8000"]

    def test_public_bind_without_allowlist_disables_protection_and_warns(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Enabling protection with an empty allowlist would reject everything."""
        with caplog.at_level("WARNING"):
            settings = build_transport_security(cfg(host="0.0.0.0"))
        assert not settings.enable_dns_rebinding_protection
        assert "DNS rebinding protection is DISABLED" in caplog.text


class TestNetworkExposure:
    @pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
    def test_loopback_is_not_networked(self, host: str) -> None:
        assert not cfg(host=host).is_networked

    def test_public_bind_is_networked(self) -> None:
        assert cfg(host="0.0.0.0").is_networked

    def test_stdio_is_never_networked(self) -> None:
        assert not cfg(transport="stdio", host="0.0.0.0").is_networked

    def test_unauthenticated_public_bind_is_flagged(self) -> None:
        assert cfg(host="0.0.0.0", auth_token="").is_unauthenticated_network_listener
        assert not cfg(host="0.0.0.0", auth_token="t").is_unauthenticated_network_listener
        assert not cfg(host="127.0.0.1").is_unauthenticated_network_listener

    def test_preflight_warns_loudly_about_open_siem(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            preflight(cfg(host="0.0.0.0", auth_token=""))
        assert "SERVING WITHOUT AUTHENTICATION" in caplog.text
        assert "read the SIEM" in caplog.text

    def test_preflight_is_silent_for_stdio(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level("WARNING"):
            preflight(cfg(transport="stdio"))
        assert caplog.text == ""


class TestTransportConfigFromEnv:
    def test_defaults_to_stdio_loopback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in list(os_environ_keys()):
            monkeypatch.delenv(key, raising=False)
        c = TransportConfig.from_env()
        assert c.transport == "stdio"
        assert c.host == "127.0.0.1"
        assert c.port == 8000
        assert c.path == "/mcp"
        assert c.auth_token == ""

    def test_rejects_unknown_transport(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WAZUH_MCP_TRANSPORT", "websocket")
        with pytest.raises(Exception, match="WAZUH_MCP_TRANSPORT must be one of"):
            TransportConfig.from_env()

    def test_parses_allowlists_and_normalises_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WAZUH_MCP_TRANSPORT", "http")
        monkeypatch.setenv("WAZUH_MCP_PATH", "wazuh")
        monkeypatch.setenv("WAZUH_MCP_ALLOWED_HOSTS", "a.example:8000, b.example:8000")
        c = TransportConfig.from_env()
        assert c.path == "/wazuh"
        assert c.allowed_hosts == ("a.example:8000", "b.example:8000")


def os_environ_keys() -> list[str]:
    return [
        "WAZUH_MCP_TRANSPORT",
        "WAZUH_MCP_HOST",
        "WAZUH_MCP_PORT",
        "WAZUH_MCP_PATH",
        "WAZUH_MCP_AUTH_TOKEN",
        "WAZUH_MCP_ALLOWED_HOSTS",
        "WAZUH_MCP_ALLOWED_ORIGINS",
    ]
