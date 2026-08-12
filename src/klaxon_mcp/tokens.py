# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Deterministic token derivation for the masked stream (Option B).

The single source of truth for the pipeline token scheme: SHA-256 over
`family:value:salt`, first 16 hex chars, displayed as `[FAMILY_<16 hex>]`,
idempotent on already-tokenised values. `derive_token` is the canonical entry
point the generator self-test compares the Painless script against
(`masking.painless_token_reference` is an independent transcription used as a
canary).

The response layer (`anonymization._token`) deliberately uses a DIFFERENT
scheme (HMAC) on a different layer; this module is the stream/ingest side.

A leaf: imports nothing from the package, imported widely.
"""

from __future__ import annotations

import hashlib
import re

# A value already in this shape is a token: never re-mask it (idempotent).
TOKEN_RE = re.compile(r"^\[(?:IP|USER|HOST|AGENT)_[0-9a-f]{16}\]$")


def token_hex(family: str, value: str, salt: str) -> str:
    """16 hex chars of SHA-256 over `family:value:salt` (the pipeline scheme)."""
    if not value:
        return value
    if TOKEN_RE.fullmatch(value):
        return value  # already a token: idempotent, never re-mask
    digest = hashlib.sha256(f"{family}:{value}:{salt}".encode("utf-8")).hexdigest()
    return digest[:16]


def token(family: str, value: str, salt: str) -> str:
    """The display token `[FAMILY_<16 hex>]` used by the masked stream."""
    if not value:
        return value
    if TOKEN_RE.fullmatch(value):
        return value
    return f"[{family}_{token_hex(family, value, salt)}]"


def derive_token(value: str, family: str, salt: str) -> str:
    """The single token-derivation entry point: `derive_token(value, family, salt)`.

    `token()` is the implementation (SHA-256 over `family:value:salt`, first 16
    hex chars, displayed as `[FAMILY_<16 hex>]`, idempotent on existing tokens).
    `derive_token` is the name the token-schema self-test and the docs use for
    the pipeline scheme, so the Painless script and the Python side are compared
    against one canonical function.
    """
    return token(family, value, salt)
