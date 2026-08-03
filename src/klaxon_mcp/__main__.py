# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Console entry point.

Defaults to stdio, which is what an MCP client spawning this process expects.
The HTTP transports exist for running the server on a different host from the
client — see the "Remote deployment" section of the README before using them.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import replace

from .config import ConfigError, TransportConfig
from .transport import serve


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="klaxon-mcp",
        description="Klaxon MCP — MCP server for Wazuh 5.x.",
        epilog=(
            "Every flag has an environment equivalent (WAZUH_MCP_TRANSPORT, "
            "WAZUH_MCP_HOST, WAZUH_MCP_PORT, WAZUH_MCP_PATH, "
            "WAZUH_MCP_AUTH_TOKEN, WAZUH_MCP_ALLOWED_HOSTS). Flags win."
        ),
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "sse"],
        help="stdio (default) spawns under an MCP client; http serves streamable HTTP.",
    )
    parser.add_argument("--host", help="Bind address for http/sse. Default 127.0.0.1.")
    parser.add_argument("--port", type=int, help="Bind port for http/sse. Default 8000.")
    parser.add_argument("--path", help="HTTP endpoint path. Default /mcp.")
    parser.add_argument(
        "--allowed-host",
        action="append",
        dest="allowed_hosts",
        metavar="HOST",
        help="Permitted Host header value; repeatable. Enables DNS rebinding protection.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Default INFO.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # Logs go to stderr: on stdio, stdout carries the JSON-RPC stream and any
    # stray byte written there corrupts the session.
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        cfg = TransportConfig.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    overrides: dict[str, object] = {}
    if args.transport is not None:
        overrides["transport"] = args.transport
    if args.host is not None:
        overrides["host"] = args.host
    if args.port is not None:
        overrides["port"] = args.port
    if args.path is not None:
        overrides["path"] = args.path if args.path.startswith("/") else f"/{args.path}"
    if args.allowed_hosts:
        overrides["allowed_hosts"] = tuple(args.allowed_hosts)
    if overrides:
        cfg = replace(cfg, **overrides)  # type: ignore[arg-type]

    # Imported here so that --help works without the Wazuh environment set.
    from .server import mcp

    try:
        serve(mcp, cfg)
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
