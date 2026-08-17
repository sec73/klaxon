# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

# ---------------------------------------------------------------------------
# builder — Python 3.13 + Build-Toolchain
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base AS builder

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Wolfi  Python 3.13 + Build-Dependencies
RUN apk add --no-cache \
        python-3.13 \
        py3.13-pip \
        python-3.13-dev \
        build-base \
    && ln -sf /usr/bin/python3.13 /usr/bin/python3

WORKDIR /build

COPY pyproject.toml README.md ./
COPY src/ ./src/


RUN python3 -m pip wheel --no-cache-dir --wheel-dir /wheels .

# ---------------------------------------------------------------------------
# final 
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base AS final

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1


RUN apk add --no-cache \
        python-3.13 \
        py3.13-pip \
    && ln -sf /usr/bin/python3.13 /usr/bin/python3

WORKDIR /app

# The Option B single source of truth (tenants/<tenant>/fields.yaml) — needed
# at runtime by `klaxon_posture_check` / verify-config to load the tenant
# config (`find_repo_root()` locates the `tenants/` directory under /app).
# Without it the posture/GDPR verification chain aborts with "missing masking
# source of truth: /app/tenants/<tenant>/fields.yaml".
COPY tenants/ ./tenants/


COPY --from=builder /wheels /wheels
RUN python3 -m pip install --no-cache-dir --no-index /wheels/*.whl \
    && rm -rf /wheels


RUN apk add --no-cache shadow \
    && useradd --create-home --uid 10001 --system klaxon-mcp \
    && chown -R klaxon-mcp:klaxon-mcp /app

USER klaxon-mcp


EXPOSE 8000


ENTRYPOINT ["klaxon-mcp"]