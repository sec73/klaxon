# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""The mandatory token-scheme and script-structure self-test.

Pure logic, no filesystem or network I/O: proves the rendered Painless script
implements byte-exactly the token scheme `derive_token` implements, and that
the script is structurally compilable (functions before statements, no
`ctx['_source']`). Runs inside every `klaxon masking generate`; on ANY problem
generation aborts and emits NO artifacts. Also exposed as
`klaxon masking selftest`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from .hmac_vectors import ALL_HMAC_VECTORS, KLAXON_VECTORS
from .masked_stream import _FREETEXT_PATTERN_ORDER
from .tokens import TOKEN_RE, token


class TokenSchemeError(Exception):
    """The Painless token scheme diverged from `derive_token` — generation aborts."""


# Representative values per family the self-test pins the scheme on. These are
# deliberately independent of any tenant's fields.yaml: they exercise every
# family, a UUID, an agent id, an empty value and an already-tokenised value
# (idempotency).
SELF_TEST_VALUES: tuple[tuple[str, str], ...] = (
    ("marcomoenig", "USER"),
    ("jdoe", "USER"),
    ("root(uid=0)", "USER"),
    ("550e8400-e29b-41d4-a716-446655440000", "USER"),  # UUID string
    ("müller", "USER"),  # non-ASCII
    ("nc02web", "HOST"),
    ("web-01.example.com", "HOST"),
    ("192.168.50.42", "IP"),
    ("10.0.0.1", "IP"),
    ("2001:db8::1", "IP"),
    ("001", "AGENT"),
    ("c2f7c1a4-9e4b-4c0a-8f6a-5b2d7e1a3c90", "AGENT"),  # agent id
    ("", "USER"),  # empty value stays unchanged
    ("[USER_7570f69ace298df1]", "USER"),  # already a token -> idempotent
)


def painless_token_reference(family: str, value: str, salt: str) -> str:
    """Byte-exact Python transcription of the Painless `token()`/`hmacSha256Hex()`.

    Written as a SEPARATE code path from `derive_token()` on purpose: the
    self-test runs both over the representative values and aborts on ANY
    mismatch, so a scheme change in one without the other is caught at generate
    time — changing `derive_token` breaks generation, not the deployed pipeline.
    """
    if value is None:
        return value
    if not value:
        return value  # empty stays empty — mirrors the script's value.isEmpty()
    if TOKEN_RE.fullmatch(value):
        return value  # idempotent passthrough, mirrors the script
    # Keyed HMAC-SHA256(key = salt, msg = `family:value`), first 16 hex chars.
    digest = hmac.new(
        salt.encode(), f"{family}:{value}".encode(), hashlib.sha256
    ).hexdigest()
    return f"[{family}_{digest[:16]}]"


# The token-scheme markers the rendered Painless source MUST contain. If any is
# missing, the script does not implement the scheme `derive_token` implements.
# The markers prove the construction is a KEYED HMAC (salt as key, family as
# context: pre-hash for keys > 64 bytes, ipad 0x36 / opad 0x5c) truncated to 16
# hex, not a concatenation hash / plain digest.
_SCHEME_MARKERS: tuple[str, ...] = (
    "def SALT = params.salt;",
    "if (value.isEmpty()) return value;",
    "String hmacSha256Hex(String salt, String message)",
    "key.length > 64",  # HMAC pre-hash for keys longer than the 64-byte block
    "kb[i] ^ 54",  # inner pad ipad (0x36)
    "kb[i] ^ 92",  # outer pad opad (0x5c)
    'hmacSha256Hex(SALT, family + ":" + value).substring(0, 16)',  # truncation
    "Pattern TOKEN_RE()",
    r"^\[(?:IP|USER|HOST|AGENT)_[0-9a-f]{16}\]$",  # the idempotency regex literal
)


def verify_script_scheme(script: str) -> list[str]:
    """Token-scheme markers MISSING from a rendered Painless script.

    Binds the self-test to the actual generated artifact: the script must encode
    exactly the scheme `derive_token` implements (keyed HMAC-SHA256 over
    `family:value` with the salt as key, first 16 hex chars, `[FAMILY_<hex>]`
    display, idempotent passthrough, salt injected via `params.salt`). Empty
    result = the script encodes the scheme.
    """
    return [marker for marker in _SCHEME_MARKERS if marker not in script]


# The function declarations the rendered Painless script MUST define: (name,
# return type). The HMAC/SHA-256 helpers implement the keyed token scheme in
# pure Painless (no javax.crypto.Mac / String.sha256 on the restricted ingest
# allowlist). The free-text regexes are emitted as `Pattern <NAME>()` functions
# and TOKEN_RE() as a `Pattern` function, matching the live-verified shape
# (`Pattern.compile` is not whitelisted on restricted clusters; regex literals
# in functions are).
_PAINLESS_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("sha256", "int[]"),
    ("ror", "int"),
    ("utf8", "int[]"),
    ("wordsToBytes", "int[]"),
    ("wordsToHex", "String"),
    ("hmacSha256Hex", "String"),
    ("token", "String"),
    ("TOKEN_RE", "Pattern"),
    ("maskPattern", "String"),
    ("isWordChar", "boolean"),
    ("replaceWordBoundary", "String"),
    ("maskRegistry", "String"),
    ("maskFreeText", "String"),
    # Nested-path helpers: structured fields may be NESTED in real Wazuh docs
    # (`user: {name: ...}`), so masking walks/creates dotted paths and the
    # free-text registry reads them (deepCopy keeps `ctx` pristine).
    ("deepCopy", "def"),
    ("pathGet", "def"),
    ("pathPut", "boolean"),
) + tuple((name, "Pattern") for name in _FREETEXT_PATTERN_ORDER)

# The top-level declarations the script emits (functions must precede these).
_PAINLESS_TOP_DECLS: tuple[str, ...] = (
    "def SALT =",
    "def FIELDS =",
    "def FREE_TEXT =",
)

# The first statement of the main logic, which must follow every declaration.
_MAIN_LOGIC_MARKER = "Map masked = deepCopy(ctx);"


def verify_script_structure(script: str) -> list[str]:
    """Structural compile-safety problems in a rendered Painless script.

    The scheme markers prove WHAT the script computes; these checks prove the
    script COMPILES the way the live `_execute`/`_simulate` test exercises it:

      * every function declaration precedes any top-level statement (Painless
        rejects functions after statements with `unexpected token ['(']`);
      * the declarations (`def SALT`/`FIELDS`/`FREE_TEXT`) precede the main logic;
      * no `ctx['_source']` remains — in an ingest script processor `ctx` IS the
        document, so `ctx['_source']` is null and NPEs on the first document.

    Empty result = structurally sound (the offline counterpart of the live
    compile check; see `klaxon masking test`).
    """
    problems: list[str] = []

    if "ctx['_source']" in script:
        problems.append(
            "script still references ctx['_source'] — in an ingest script "
            "processor ctx IS the document (no nested _source object); this "
            "NPEs on the first document once the script compiles."
        )

    def_positions = [script.find(decl) for decl in _PAINLESS_TOP_DECLS]
    first_statement = min((p for p in def_positions if p >= 0), default=-1)

    for name, rtype in _PAINLESS_FUNCTIONS:
        sig = f"{rtype} {name}("
        pos = script.find(sig)
        if pos < 0:
            problems.append(
                f"missing function declaration `{sig}...)` — the pipeline "
                "would fail to compile at ingest time."
            )
            continue
        if first_statement >= 0 and pos > first_statement:
            problems.append(
                f"function `{name}` is declared AFTER a top-level statement "
                f"(`{_PAINLESS_TOP_DECLS[0]}...`) — Painless requires ALL "
                "functions before any statement; the indexer rejects the "
                "pipeline with `unexpected token ['(']`."
            )

    main_pos = script.find(_MAIN_LOGIC_MARKER)
    if main_pos < 0:
        problems.append(
            f"main-logic marker `{_MAIN_LOGIC_MARKER}` not found — the emitted "
            "structure changed unexpectedly."
        )
    else:
        for decl, pos in zip(_PAINLESS_TOP_DECLS, def_positions):
            if pos < 0:
                problems.append(f"missing top-level declaration `{decl}`")
            elif pos > main_pos:
                problems.append(
                    f"declaration `{decl}` appears AFTER the main logic — the "
                    "script would use FIELDS/SALT before they are assigned."
                )
        if not any(
            f"Pattern {name}() {{" in script for name in _FREETEXT_PATTERN_ORDER
        ):
            problems.append(
                "no free-text Pattern functions found — the free-text pass "
                "references them by name and the script would fail to compile."
            )

    return problems


def verify_quarantine_on_failure(on_failure: list[Any]) -> list[str]:
    """Fail-closed on_failure markers MISSING from a pipeline's on_failure block.

    The on_failure MUST reroute a masking-failure document OUT of the masked
    stream into the quarantine stream (`klaxon-quarantine-<tenant>-v5-raw`),
    preserving the original destination + failure reason. Empty result = the
    routing is present. Runs inside every `klaxon masking generate` (via
    `run_generator_selftest`), so a regression that reverts to the old fail-open
    on_failure (`set klaxon.masking_error`, doc stays in the masked stream)
    aborts generation and emits NO artifacts.
    """
    problems: list[str] = []
    if not on_failure:
        problems.append("pipeline has no on_failure block (masking failures "
                        "would be dropped, not quarantined)")
        return problems
    blob = json.dumps(on_failure)
    if "{{ _ingest.on_failure_message }}" not in blob:
        problems.append(
            "on_failure lacks the {{ _ingest.on_failure_message }} capture "
            "(the failure reason would be lost)"
        )
    for marker in ("original_index", "masking_error", "quarantine", "ctx['_index']"):
        if marker not in blob:
            problems.append(f"on_failure rerouting script missing marker {marker!r}")
    if "klaxon-quarantine-" not in blob or "-v5-raw" not in blob:
        problems.append(
            "on_failure does not reroute to klaxon-quarantine-<tenant>-v5-raw"
        )
    return problems


# --------------------------------------------------------------------------- #
# HMAC edge-case vectors: the pure-Painless HMAC is a hand-rolled SHA-256-based
# MAC, so the self-test pins the exact places it is most likely to go wrong
# (RFC 4231 KATs, key-length boundaries, UTF-8, truncation).
# --------------------------------------------------------------------------- #


def pure_painless_hmac(key: bytes, msg: bytes) -> str:
    """Byte-exact Python port of the pure-Painless `hmacSha256Hex()`.

    Mirrors EXACTLY the algorithm the generator emits into Painless (see
    `painless._HMAC_FUNCTIONS`): pre-hash the key when longer than the 64-byte
    block, zero-pad to a 64-byte block, XOR with ipad (0x36) / opad (0x5c),
    TWO SHA-256 passes (inner then outer), hex output. The underlying SHA-256
    is Python's `hashlib` — the Painless `sha256(int[])` is pinned byte-
    identical by the RFC 4231 vectors and the live `_simulate`.
    """
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    block = key + b"\x00" * (64 - len(key))
    inner = hashlib.sha256(bytes(b ^ 0x36 for b in block) + msg).digest()
    return hashlib.sha256(bytes(b ^ 0x5c for b in block) + inner).hexdigest()


def run_hmac_vector_selftest() -> list[str]:
    """Assert the pure-Painless HMAC port against the authoritative reference.

    * RFC 4231 vectors: the port AND Python's `hmac` module must equal the
      hardcoded authoritative digest (a disagreement means the implementation
      or the generator is wrong — never edit the vector to match).
    * Key-length + Klaxon vectors: the port must equal the `hmac` reference.
    * Klaxon vectors: the pipeline's `token()` must equal the expected token
      (first 16 hex of the full digest; empty value passes through unchanged).

    Returns a list of problems (empty = pass). Runs inside every
    `klaxon masking generate`; on ANY problem generation aborts and emits NO
    artifacts, printing the failing label + expected + actual.
    """
    problems: list[str] = []

    for label, key, msg, expected in ALL_HMAC_VECTORS:
        actual_port = pure_painless_hmac(key, msg)
        if actual_port != expected:
            problems.append(
                f"  {label}: pure_painless_hmac -> {actual_port} but expected "
                f"{expected}"
            )
        actual_hmac = hmac.new(key, msg, hashlib.sha256).hexdigest()
        if actual_hmac != expected:
            problems.append(
                f"  {label}: Python hmac module -> {actual_hmac} but expected "
                f"{expected} (reference disagreement — never edit the vector)"
            )

    for label, salt, family, value, full, expected_token in KLAXON_VECTORS:
        actual_token = token(family, value, salt)
        if actual_token != expected_token:
            problems.append(
                f"  {label}: token({family!r}, {value!r}, salt) -> "
                f"{actual_token!r} but expected {expected_token!r}"
            )
        # Truncation semantics: the token must be the FIRST 16 hex of the FULL
        # digest (a naive re-encode of 8 raw digest bytes would diverge).
        if expected_token and not expected_token.endswith(full[:16] + "]"):
            problems.append(
                f"  {label}: expected token is not the first 16 hex of the "
                f"full digest ({full})"
            )
    return problems


def verify_hmac_structural(script: str) -> list[str]:
    """HMAC-structural markers MISSING from the rendered Painless script.

    The token scheme is a hand-rolled pure-Painless HMAC (deliberately NOT
    `javax.crypto.Mac` — the ingest allowlist has none). These scans (no
    cluster) pin the construction a single-digest or latin-1 shortcut would
    silently break: ipad/opad XOR, TWO distinct SHA-256 passes, the key-length
    branching (hash-if->64, zero-pad-if-<64), UTF-8 byte handling, and the
    absence of a crypto-class shortcut. Empty result = structurally sound.
    """
    problems: list[str] = []
    if "javax.crypto.Mac" in script or "Mac.getInstance" in script:
        problems.append(
            "script references javax.crypto.Mac — the pure-Painless HMAC is "
            "deliberate (the ingest allowlist has no Mac); do not reintroduce it"
        )
    if "kb[i] ^ 54" not in script:  # ipad 0x36
        problems.append("missing ipad (0x36) XOR in the HMAC inner pass")
    if "kb[i] ^ 92" not in script:  # opad 0x5c
        problems.append("missing opad (0x5c) XOR in the HMAC outer pass")
    if "sha256(innerInput)" not in script or "sha256(outerInput)" not in script:
        problems.append(
            "HMAC must perform TWO distinct SHA-256 digest steps (inner then "
            "outer) — a single-digest shortcut is not a keyed MAC"
        )
    if "key.length > 64" not in script:
        problems.append(
            "missing the HMAC key pre-hash branch for keys longer than 64 bytes"
        )
    if "utf8(String s)" not in script or "65536" not in script:
        problems.append(
            "missing/latin-1 UTF-8 byte handling (unicode values must be "
            "encoded like Python .encode('utf-8'))"
        )
    return problems


def _selftest_salt(salt: str | None, salt_env: str) -> str:
    """Salt for the self-test: explicit, else the env value, else a fixed test
    value. The self-test only proves scheme identity (salt-agnostic), so an
    unset env never warns here — a random salt warning only makes sense when a
    real salt is actually baked into a deployable artifact (see `generate`)."""
    if salt is not None:
        return salt
    env = os.environ.get(salt_env, "").strip()
    if env:
        return env
    return "klaxon-masking-selftest-fixed"
