# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""HMAC-SHA256 edge-case vectors — the single source shared by the generator
self-test and the live test.

The Option-B token is `HMAC-SHA256(key=salt, msg="<family>:<value>")` truncated
to the first 16 hex chars. The deployed pipeline implements it as a HAND-ROLLED
pure-Painless SHA-256-based HMAC (the ingest allowlist has no
`javax.crypto.Mac`; deliberate, zero cluster-config change). This table pins
exactly the places such an implementation is most likely to go wrong, and is
used by BOTH:

  * the OFFLINE self-test (`selftest.run_hmac_vector_selftest`, runs inside
    `klaxon masking generate`, no cluster needed) — a Python port
    (`pure_painless_hmac`) must equal the reference for every vector, and
  * the LIVE test (`live_test.stage_b_simulate_hmac_vectors`) — the deployed
    pure-Painless script must produce the same tokens via `_simulate`.

Groups:

  * `RFC4231_VECTORS`    — RFC 4231 test cases 1-7 with AUTHORITATIVE full
                          digests. NEVER edit these to match an implementation.
  * `KEY_LENGTH_VECTORS` — key-length boundary/padding branches (keys of 64/65/
                          63/0/1/32 bytes). Expected digests are computed from
                          Python's `hmac` module (the reference), not by hand.
  * `KLAXON_VECTORS`     — the Klaxon construction (string salt -> UTF-8,
                          message `family:value` -> UTF-8): 16/64/131/empty-byte
                          salts (131 exercises the hash-first branch), ASCII /
                          umlaut / CJK / emoji values (a latin-1 or mojibake
                          implementation must fail these), a ':'-containing
                          value (separator unambiguity), empty value (pipeline
                          passthrough), preserved spaces, and the 16-hex
                          truncation semantics.

NOTE on RFC 4231 TC7: the Data is the FULL RFC string (152 bytes, ending
"... data. The key needs to be hashed before being used by the HMAC algorithm.").
An earlier draft of this table used a truncated data string that does NOT
produce the RFC digest (Python `hmac` and OpenSSL both confirm: the full string
yields `9b09ff…`, the authoritative value).
"""

from __future__ import annotations

import hashlib
import hmac

# --------------------------------------------------------------------------- #
# 1a. RFC 4231 test cases 1-7 (authoritative full 64-char digests)
# --------------------------------------------------------------------------- #

# (label, key bytes, message bytes, expected full HMAC-SHA256 digest)
RFC4231_VECTORS: tuple[tuple[str, bytes, bytes, str], ...] = (
    (
        "RFC4231-TC1",
        b"\x0b" * 20,
        b"Hi There",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    ),
    (
        "RFC4231-TC2",
        b"Jefe",
        b"what do ya want for nothing?",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ),
    (
        "RFC4231-TC3",
        b"\xaa" * 20,
        b"\xdd" * 50,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    ),
    (
        "RFC4231-TC4",
        bytes(range(0x01, 0x1A)),  # 0x01..0x19, 25 bytes
        b"\xcd" * 50,
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
    ),
    (
        "RFC4231-TC5",  # truncation case: token = first 16 hex a3b6167473100ee0
        b"\x0c" * 20,
        b"Test With Truncation",
        "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
    ),
    (
        "RFC4231-TC6",  # key (0xaa*131) > 64 bytes -> hash-first branch
        b"\xaa" * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    ),
    (
        "RFC4231-TC7",  # key AND data > 64 bytes; data is the FULL RFC string
        b"\xaa" * 131,
        (
            b"This is a test using a larger than block-size key and a larger "
            b"than block-size data. The key needs to be hashed before being "
            b"used by the HMAC algorithm."
        ),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    ),
)

# --------------------------------------------------------------------------- #
# 1b. Key-length branch vectors (the padding / boundary edges)
# --------------------------------------------------------------------------- #

_KEY_LENGTH_MESSAGE = b"edge-case message for the pure-Painless HMAC"


def _hmac_hex(key: bytes, msg: bytes) -> str:
    """The reference: Python's hmac module (authoritative for non-RFC vectors)."""
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


# (label, key bytes) — 64 is the SHA-256 block size; 0xaa keeps keys unambiguous.
_KEY_LENGTH_SPECS: tuple[tuple[str, bytes], ...] = (
    ("key-64B-exact-boundary", b"\xaa" * 64),  # used as-is, no hash, no pad
    ("key-65B-hash-first", b"\xaa" * 65),      # hash-first branch, boundary side
    ("key-63B-zero-pad", b"\xaa" * 63),        # zero-pad-to-64 branch
    ("key-0B-empty", b""),                     # zero-pad the whole block
    ("key-1B-pad", b"\xaa"),                   # padding path
    ("key-32B-pad", b"\xaa" * 32),             # padding path
)

# (label, key bytes, message bytes, expected full digest)
KEY_LENGTH_VECTORS: tuple[tuple[str, bytes, bytes, str], ...] = tuple(
    (label, key, _KEY_LENGTH_MESSAGE, _hmac_hex(key, _KEY_LENGTH_MESSAGE))
    for label, key in _KEY_LENGTH_SPECS
)

# --------------------------------------------------------------------------- #
# 1c. Klaxon-format vectors: HMAC(key=salt.encode(), msg=f"{family}:{value}")
# --------------------------------------------------------------------------- #

# Salts: 16 bytes (32 hex), exactly 64 bytes, 131 bytes (> 64 -> hash-first),
# and empty (0 bytes).
_SALT_16 = "00112233445566778899aabbccddeeff"
_SALT_64 = "0123456789abcdef" * 4
_SALT_131 = "0123456789abcdef" * 8 + "012"
_SALT_0 = ""


def _klaxon_full(salt: str, family: str, value: str) -> str:
    return _hmac_hex(salt.encode(), f"{family}:{value}".encode())


def _klaxon_token(full: str, family: str, value: str) -> str:
    # The pipeline's token(): empty value passes through unchanged (the
    # empty-value guard), everything else is [FAMILY_<first 16 hex>].
    if not value:
        return ""
    return f"[{family}_{full[:16]}]"


# (label, salt, family, value, expected_full_digest, expected_token)
KLAXON_VECTORS: tuple[tuple[str, str, str, str, str, str], ...] = tuple(
    (label, salt, family, value, _klaxon_full(salt, family, value),
     _klaxon_token(_klaxon_full(salt, family, value), family, value))
    for label, salt, family, value in (
        ("klaxon-s16-ascii", _SALT_16, "USER", "marcomoenig"),
        ("klaxon-s16-umlaut", _SALT_16, "USER", "märco"),
        ("klaxon-s16-cjk", _SALT_16, "USER", "テスト"),
        ("klaxon-s16-emoji-trunc", _SALT_16, "USER", "admin🦊"),
        ("klaxon-s16-colon-value", _SALT_16, "USER", "user:name"),
        ("klaxon-s16-empty-value", _SALT_16, "USER", ""),
        ("klaxon-s16-spaces", _SALT_16, "USER", "  padded  "),
        # Truncation trap: this digest starts with "00", so a naive re-encode of
        # the first 8 digest bytes as an integer (hex(int.from_bytes(...))) would
        # DROP the leading zero — the token must be the raw first 16 hex chars.
        ("klaxon-s64-ip-trunc", _SALT_64, "IP", "192.168.50.42"),
        ("klaxon-s64-host", _SALT_64, "HOST", "web-01.example.com"),
        ("klaxon-s64-agent", _SALT_64, "AGENT", "agent-7"),
        ("klaxon-s131-hashfirst", _SALT_131, "USER", "long-key-branch"),
        ("klaxon-s0-empty-salt", _SALT_0, "USER", "no-salt"),
    )
)

# Convenience aggregation for the offline self-test and unit tests.
ALL_HMAC_VECTORS: tuple[tuple[str, bytes, bytes, str], ...] = (
    RFC4231_VECTORS + KEY_LENGTH_VECTORS
    + tuple((label, salt.encode(), f"{family}:{value}".encode(), full)
            for label, salt, family, value, full, _token in KLAXON_VECTORS)
)
