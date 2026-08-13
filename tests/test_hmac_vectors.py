# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Tests for the HMAC edge-case vector suite (pure-Painless HMAC self-test).

The deployed pipeline implements HMAC-SHA256 as a hand-rolled pure-Painless
SHA-256-based MAC. These tests pin the vector table (RFC 4231 KATs, key-length
branches, Klaxon UTF-8/truncation vectors), the offline Python port
(`selftest.pure_painless_hmac`) against the `hmac` reference, and the
structural checks on the generated Painless source. A regression in any of them
must fail `klaxon masking generate` (the generator aborts and emits nothing).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

import pytest

from klaxon_mcp import masking, selftest
from klaxon_mcp.hmac_vectors import (
    ALL_HMAC_VECTORS,
    KEY_LENGTH_VECTORS,
    KLAXON_VECTORS,
    RFC4231_VECTORS,
)
from klaxon_mcp.masked_stream import build_pipeline, load_tenant_config, token


def _script(cfg: Any = None) -> str:
    cfg = cfg or load_tenant_config("customer-a")
    return build_pipeline(cfg, "test-salt")["processors"][0]["script"]["source"]


# --------------------------------------------------------------------------- #
# RFC 4231 KATs (authoritative full digests)
# --------------------------------------------------------------------------- #


def test_rfc4231_port_matches_authoritative_digests() -> None:
    for label, key, msg, expected in RFC4231_VECTORS:
        assert selftest.pure_painless_hmac(key, msg) == expected, label
        assert hmac.new(key, msg, hashlib.sha256).hexdigest() == expected, label


def test_rfc4231_tc7_uses_full_rfc_data() -> None:
    """Guard against re-truncating the RFC 4231 TC7 data: the full 152-byte
    string is what produces the authoritative `9b09ff…` digest."""
    tc7 = next(v for v in RFC4231_VECTORS if v[0] == "RFC4231-TC7")
    _label, key, msg, expected = tc7
    assert len(msg) == 152
    assert msg.endswith(b"used by the HMAC algorithm.")
    assert hmac.new(key, msg, hashlib.sha256).hexdigest() == expected


def test_rfc4231_tc5_truncation_prefix() -> None:
    """TC5 is the explicit truncation case: the token is the FIRST 16 hex of the
    full digest (a3b6167473100ee0), not a re-encoded 8-byte integer."""
    tc5 = next(v for v in RFC4231_VECTORS if v[0] == "RFC4231-TC5")
    _label, _key, _msg, expected = tc5
    assert expected[:16] == "a3b6167473100ee0"


def test_truncation_is_first_16_hex_not_int_reencode() -> None:
    """The Klaxon truncation-trap vector: the digest starts with "00", so a
    naive `hex(int.from_bytes(digest[:8], 'big'))` would drop the leading zero
    nibble. The token must be the raw first 16 hex chars of the full digest."""
    vec = next(v for v in KLAXON_VECTORS if v[0] == "klaxon-s64-ip-trunc")
    _label, salt, family, value, full, tok = vec
    assert full[:16] == "00aaf3a2df691a0c"
    raw8 = hmac.new(
        salt.encode(), f"{family}:{value}".encode(), hashlib.sha256
    ).digest()[:8]
    naive = hex(int.from_bytes(raw8, "big"))[2:]
    assert naive != full[:16]  # the int re-encode drops the leading '0'
    assert tok == f"[{family}_{full[:16]}]"  # the correct truncation


# --------------------------------------------------------------------------- #
# The offline port vs the reference, for every vector
# --------------------------------------------------------------------------- #


def test_port_matches_reference_for_all_vectors() -> None:
    for label, key, msg, expected in ALL_HMAC_VECTORS:
        assert selftest.pure_painless_hmac(key, msg) == hmac.new(
            key, msg, hashlib.sha256
        ).hexdigest(), label
        assert selftest.pure_painless_hmac(key, msg) == expected, label


def test_key_length_branches_covered() -> None:
    sizes = {len(k) for _l, k, _m, _e in KEY_LENGTH_VECTORS}
    assert sizes == {64, 65, 63, 0, 1, 32}
    by_label = {v[0]: v for v in KEY_LENGTH_VECTORS}
    # The 64-byte key must be used as-is (no pre-hash): HMAC over a 64-byte key
    # equals the port output, and the port does NOT hash it.
    _l64, k64, m64, e64 = by_label["key-64B-exact-boundary"]
    assert selftest.pure_painless_hmac(k64, m64) == e64 == hmac.new(
        k64, m64, hashlib.sha256
    ).hexdigest()
    assert len(k64) == 64
    # The 65-byte key takes the hash-first branch.
    _l65, k65, _m, _e = by_label["key-65B-hash-first"]
    assert len(k65) == 65
    assert selftest.pure_painless_hmac(k65, b"x") == hmac.new(
        k65, b"x", hashlib.sha256
    ).hexdigest()


def test_run_hmac_vector_selftest_passes() -> None:
    assert selftest.run_hmac_vector_selftest() == []


def test_klaxon_vectors_cover_utf8_colon_empty_spaces_and_truncation() -> None:
    labels = {v[0]: v for v in KLAXON_VECTORS}
    # UTF-8 multi-byte values (umlaut, CJK, emoji).
    for label in ("klaxon-s16-umlaut", "klaxon-s16-cjk", "klaxon-s16-emoji-trunc"):
        _l, salt, family, value, full, tok = labels[label]
        assert full == hmac.new(
            salt.encode(), f"{family}:{value}".encode(), hashlib.sha256
        ).hexdigest()
        assert tok == f"[{family}_{full[:16]}]"
    # ':'-containing value: the family:value separator stays unambiguous.
    _l, salt, _fam, val, full, tok = labels["klaxon-s16-colon-value"]
    assert val == "user:name"
    assert full == hmac.new(
        salt.encode(), b"USER:user:name", hashlib.sha256
    ).hexdigest()
    # Empty value passes through unchanged (token == "").
    _l, salt, _fam, val, full, tok = labels["klaxon-s16-empty-value"]
    assert val == "" and tok == ""
    # Leading/trailing spaces preserved as-is.
    _l, salt, _fam, val, full, tok = labels["klaxon-s16-spaces"]
    assert val == "  padded  "
    assert tok == f"[USER_{full[:16]}]"
    # 131-byte salt exercises the hash-first branch.
    _l, salt, _fam, val, full, tok = labels["klaxon-s131-hashfirst"]
    assert len(salt.encode()) == 131
    assert tok == f"[USER_{full[:16]}]"
    # Empty salt (0-byte key) zero-pads the whole block.
    _l, salt, _fam, val, full, tok = labels["klaxon-s0-empty-salt"]
    assert salt == "" and tok == f"[USER_{full[:16]}]"


def test_pipeline_token_matches_every_klaxon_vector() -> None:
    for label, salt, family, value, _full, expected_token in KLAXON_VECTORS:
        assert token(family, value, salt) == expected_token, label


# --------------------------------------------------------------------------- #
# Structural checks on the generated Painless source
# --------------------------------------------------------------------------- #


def test_verify_hmac_structural_passes_on_generated_script() -> None:
    assert selftest.verify_hmac_structural(_script()) == []
    assert "javax.crypto.Mac" not in _script()


def test_verify_hmac_structural_catches_bad_ipad() -> None:
    tampered = _script().replace("kb[i] ^ 54", "kb[i] ^ 53")
    problems = selftest.verify_hmac_structural(tampered)
    assert any("ipad" in p for p in problems)


def test_verify_hmac_structural_catches_bad_opad() -> None:
    tampered = _script().replace("kb[i] ^ 92", "kb[i] ^ 91")
    problems = selftest.verify_hmac_structural(tampered)
    assert any("opad" in p for p in problems)


def test_verify_hmac_structural_catches_single_digest_shortcut() -> None:
    # Reusing the inner digest for the outer pass = one distinct digest step.
    tampered = _script().replace("sha256(outerInput)", "sha256(innerInput)")
    problems = selftest.verify_hmac_structural(tampered)
    assert any("TWO distinct" in p for p in problems)


def test_verify_hmac_structural_catches_missing_key_branch() -> None:
    tampered = _script().replace("key.length > 64", "key.length > 1000000")
    problems = selftest.verify_hmac_structural(tampered)
    assert any("64 bytes" in p for p in problems)


def test_verify_hmac_structural_catches_latin1_utf8() -> None:
    tampered = _script().replace("65536 + ((c - 55296) << 10)", "c << 10")
    problems = selftest.verify_hmac_structural(tampered)
    assert any("UTF-8" in p or "latin-1" in p for p in problems)


def test_verify_hmac_structural_catches_mac_shortcut() -> None:
    tampered = _script() + "\nctx.x = Mac.getInstance(\"HmacSHA256\");\n"
    problems = selftest.verify_hmac_structural(tampered)
    assert any("javax.crypto.Mac" in p for p in problems)


# --------------------------------------------------------------------------- #
# The generator self-test aborts on an HMAC-vector or structural mismatch
# --------------------------------------------------------------------------- #


def test_generate_aborts_on_hmac_vector_mismatch(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    """A broken pure-Painless HMAC (port mismatch) must abort `generate` and
    emit NO artifacts, printing the failing label + expected + actual."""
    from klaxon_mcp.masking import generate_main

    def broken_vector_selftest() -> list[str]:
        return [
            (
                "  RFC4231-TC1: pure_painless_hmac -> deadbeef but expected "
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
            )
        ]

    monkeypatch.setattr(masking, "run_hmac_vector_selftest", broken_vector_selftest)
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(
        "tenant: test-a\nfields:\n  - field: user.name\n    family: USER\n",
        encoding="utf-8",
    )
    rc = generate_main(["--tenant", "test-a", "--root", str(tmp_path)])
    assert rc != 0
    err = capsys.readouterr().err
    assert "RFC4231-TC1" in err
    assert "deadbeef" in err
    assert "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" in err
    generated = tmp_path / "tenants" / "test-a" / "generated"
    assert not generated.exists() or not list(generated.iterdir())


def test_generate_aborts_on_hmac_structural_mismatch(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    from klaxon_mcp.masking import generate_main

    monkeypatch.setattr(
        masking,
        "verify_hmac_structural",
        lambda script: ["script is missing ipad (0x36) XOR in the HMAC inner pass"],
    )
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(
        "tenant: test-a\nfields:\n  - field: user.name\n    family: USER\n",
        encoding="utf-8",
    )
    rc = generate_main(["--tenant", "test-a", "--root", str(tmp_path)])
    assert rc != 0
    assert "missing ipad" in capsys.readouterr().err
    generated = tmp_path / "tenants" / "test-a" / "generated"
    assert not generated.exists() or not list(generated.iterdir())
