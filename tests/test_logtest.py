# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""logtest: enum guards and phase failures hidden inside an HTTP 200.

The values here were read off a live 5.0 instance, not guessed — the plugin
answers an invalid trace level with "Only support: NONE, ASSET_ONLY, ALL" and an
invalid space with "Logtest is only supported for the 'test', 'custom' and
'standard' spaces."
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from klaxon_mcp import server
from klaxon_mcp.clients import Response
from klaxon_mcp.config import Config
from klaxon_mcp.constants import DEFAULT_TRACE_LEVEL, LOGTEST_SPACES, TRACE_LEVELS
from klaxon_mcp.server import _logtest_notices, logtest


def resp(payload: object, status: int = 200) -> Response:
    return Response(status, json.dumps(payload), "https://x/logtest")


def tags(notices: list[str]) -> set[str]:
    return {n.split("]")[0].lstrip("[") for n in notices if n.startswith("[")}


class TestVerifiedConstants:
    def test_trace_levels(self) -> None:
        assert TRACE_LEVELS == ("NONE", "ASSET_ONLY", "ALL")

    def test_default_reveals_the_decoder_chain(self) -> None:
        assert DEFAULT_TRACE_LEVEL == "ASSET_ONLY"

    def test_spaces(self) -> None:
        assert LOGTEST_SPACES == ("test", "custom", "standard")


def config_with(trace_level: str, space: str) -> Config:
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
        logtest_default_trace_level=trace_level,
        logtest_default_space=space,
    )


def installed(config: Config) -> Iterator[None]:
    previous = server._config
    server._config = config
    try:
        yield
    finally:
        server._config = previous


@pytest.fixture
def bad_defaults() -> Iterator[None]:
    """Install a config whose logtest defaults came from a mistyped environment."""
    yield from installed(config_with(trace_level="1", space="produciton"))


@pytest.fixture
def good_defaults() -> Iterator[None]:
    """Valid defaults, so only the argument under test can be at fault."""
    yield from installed(config_with(trace_level="ASSET_ONLY", space="custom"))


class TestEnumGuardsNameTheirSource:
    """An invalid default comes from the environment, not from the call.

    Reporting the argument would send the caller looking in the wrong place —
    and `trace_level` is `None` in that case, so the old message read
    "got None", which points at nothing at all.
    """

    async def test_bad_env_trace_level_names_the_variable(
        self, bad_defaults: None
    ) -> None:
        with pytest.raises(ToolError) as exc:
            await logtest(event="x", location="/var/log/x")
        assert "WAZUH_LOGTEST_TRACE_LEVEL" in str(exc.value)
        assert "'1'" in str(exc.value)

    async def test_bad_argument_trace_level_names_the_argument(
        self, good_defaults: None
    ) -> None:
        with pytest.raises(ToolError) as exc:
            await logtest(event="x", location="/var/log/x", trace_level="VERBOSE")
        message = str(exc.value)
        assert "trace_level must be one of" in message
        assert "WAZUH_LOGTEST_TRACE_LEVEL" not in message
        assert "'VERBOSE'" in message

    async def test_bad_env_space_names_the_variable(self, bad_defaults: None) -> None:
        with pytest.raises(ToolError) as exc:
            await logtest(event="x", location="/var/log/x", trace_level="ALL")
        assert "WAZUH_LOGTEST_SPACE" in str(exc.value)
        assert "'produciton'" in str(exc.value)

    async def test_bad_argument_space_names_the_argument(
        self, good_defaults: None
    ) -> None:
        with pytest.raises(ToolError) as exc:
            await logtest(event="x", location="/var/log/x", space="production")
        message = str(exc.value)
        assert "space must be one of" in message
        assert "WAZUH_LOGTEST_SPACE" not in message


class TestLogtestNotices:
    def test_normalization_error_inside_http_200_is_surfaced(self) -> None:
        """The plugin reports failure with status 200; that must not read as success."""
        notices = _logtest_notices(
            resp(
                {
                    "message": {
                        "normalization": {
                            "status": "error",
                            "error": {
                                "message": "Invalid trace level: 1. Only support: "
                                "NONE, ASSET_ONLY, ALL",
                                "code": "PARSE_ERROR",
                            },
                        }
                    },
                    "status": 200,
                }
            )
        )
        assert "LOGTEST NORMALIZATION FAILED" in tags(notices)
        assert "No decoder chain was produced" in " ".join(notices)

    def test_missing_environment_gets_a_targeted_hint(self) -> None:
        notices = _logtest_notices(
            resp(
                {
                    "message": {
                        "normalization": {
                            "status": "error",
                            "error": {
                                "message": "The 'custom' environment does not exist.",
                                "code": "PARSE_ERROR",
                            },
                        }
                    }
                }
            )
        )
        assert "HINT" in tags(notices)
        joined = " ".join(notices)
        assert "not provisioned" in joined
        # 'standard' holds only the shipped ruleset, so it is the wrong fallback
        # for a chain that depends on custom decoders.
        assert "space='test'" in joined
        assert "space='standard'" not in joined
        assert "tester_sessions" in joined

    def test_skipped_detection_phase_is_reported(self) -> None:
        notices = _logtest_notices(
            resp(
                {
                    "message": {
                        "detection": {
                            "status": "skipped",
                            "reason": "'integration' field not provided",
                        }
                    }
                }
            )
        )
        assert "LOGTEST DETECTION SKIPPED" in tags(notices)
        assert "`integration`" in " ".join(notices)

    def test_successful_normalization_produces_no_noise(self) -> None:
        notices = _logtest_notices(
            resp(
                {
                    "message": {
                        "normalization": {
                            "output": {"@timestamp": "2026-07-31T09:28:24.774Z"},
                            "asset_traces": [
                                {"asset": "decoder/syslog/0", "success": True}
                            ],
                        }
                    }
                }
            )
        )
        assert notices == []

    def test_non_dict_payloads_are_tolerated(self) -> None:
        assert _logtest_notices(resp({"message": "Missing [space] field."})) == []
        assert _logtest_notices(Response(200, "not json", "u")) == []
