# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

FROM python:3.12-slim

# Two ways to run this image:
#   stdio (default) — docker run --rm -i --env-file .env klaxon-mcp
#   http            — docker run --rm -p 8000:8000 --env-file .env klaxon-mcp \
#                       --transport http --host 0.0.0.0
# stdio needs -i and no published port; http needs a published port and no -i.

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# pyproject.toml and README.md are both build inputs (readme = "README.md").
# Note: editing anything under src/ invalidates the install layer below — the
# dependency set is small enough that splitting it into its own layer would cost
# more in duplication drift than it saves in build time.
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 klaxon-mcp

USER klaxon-mcp

# Only relevant for the http/sse transports; ignored on stdio.
EXPOSE 8000

# No credentials are baked in; supply them at run time via --env-file.
# Defaults to stdio; append --transport http to serve over the network.
ENTRYPOINT ["klaxon-mcp"]
