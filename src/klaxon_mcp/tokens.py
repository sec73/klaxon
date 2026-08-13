# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Deterministic token derivation for the masked stream (Option B).

The single source of truth for the pipeline token scheme: a KEYED HMAC-SHA256
(key = salt, message = `<family>:<value>`), first 16 hex chars, displayed as
`[FAMILY_<16 hex>]`, idempotent on already-tokenised values. `derive_token` is
the canonical entry point the generator self-test compares the Painless script
against (`masking.painless_token_reference` is an independent transcription used
as a canary).

The generated Painless implements the SAME construction in pure Painless: the
restricted ingest allowlist has no `javax.crypto.Mac` (verified against
OpenSearch 3.6.0), and `String.sha256()` can only hash UTF-8 text (not raw
digest bytes), so HMAC-SHA256 is reimplemented over an `int[]` byte sequence —
byte-identical to Python's `hmac` and proven by the generator self-test and the
live `_simulate` (Stage C of `klaxon masking test`).

The response layer (`anonymization._token`) uses the SAME keyed-HMAC
construction, so both layers now produce the same token for the same
value + family + salt (previously the stream side used a concatenation hash).

A leaf: imports nothing from the package, imported widely.
"""

from __future__ import annotations

import hashlib
import hmac
import re

# A value already in this shape is a token: never re-mask it (idempotent).
TOKEN_RE = re.compile(r"^\[(?:IP|USER|HOST|AGENT)_[0-9a-f]{16}\]$")

# Minimum recommended salt length: 32 hex chars = 16 bytes = 128 bits. The
# recommended salt is `secrets.token_hex(32)` (64 hex chars = 32 bytes = 256
# bits). Anything shorter is worth a startup warning (see `weak_salt`).
MIN_SALT_HEX = 32


def weak_salt(salt: str) -> bool:
    """True when a configured salt is shorter than 32 hex chars (16 bytes).

    The salt is the HMAC key; its entropy is the only thing between an
    attacker and re-identifying enumerable values by brute force. The salt is
    never logged — this only decides whether a warning is printed.
    """
    return len((salt or "").strip()) < MIN_SALT_HEX


def token_hex(family: str, value: str, salt: str) -> str:
    """16 hex chars of HMAC-SHA256(key=salt, msg=`family:value`) (stream scheme).

    A keyed MAC (NOT a concatenation hash): the salt is the HMAC key and the
    field family is the context, so the same value in different families yields
    different tokens and the construction resists length-extension-style misuse.
    """
    if not value:
        return value
    if TOKEN_RE.fullmatch(value):
        return value  # already a token: idempotent, never re-mask
    digest = hmac.new(
        salt.encode(), f"{family}:{value}".encode(), hashlib.sha256
    ).hexdigest()
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

    `token()` is the implementation (HMAC-SHA256 keyed by the salt over
    `family:value`, first 16 hex chars, displayed as `[FAMILY_<16 hex>]`,
    idempotent on existing tokens). `derive_token` is the name the token-schema
    self-test and the docs use for the pipeline scheme, so the Painless script
    and the Python side are compared against one canonical function.
    """
    return token(family, value, salt)
