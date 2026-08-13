# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Tests for `klaxon masking generate` / `selftest` / `salt-check` (Option A).

Covers the generator (fields.yaml -> config fragment + pipeline + ISM + index
template), the MANDATORY token-schema self-test (generated Painless must be
byte-identical to `derive_token`; a changed scheme breaks generation), the
`params.salt` pipeline structure, provenance fingerprints, drift detection, and
the deploy-time salt comparison helpers.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from klaxon_mcp import masking
from klaxon_mcp.masked_stream import (
    PROVENANCE_DESCRIPTION_MARKER,
    QUARANTINE_RETENTION_DAYS,
    TEMPLATE_PRIORITY,
    build_config_fragment,
    build_index_template,
    build_ism_policy,
    build_pipeline,
    build_pipeline_template,
    build_quarantine_index_template,
    build_quarantine_ism_policy,
    build_roles_fragment,
    deploy_pipeline,
    derive_token,
    effective_mask_fields_from_config,
    fields_yaml_sha256,
    fingerprint_matches,
    load_tenant_config,
    pipeline_field_names,
    pipeline_has_quarantine_on_failure,
    pipeline_provenance,
    token,
    token_hex,
)
from klaxon_mcp.masking import (
    CONFIG_FRAGMENT_NAME,
    INDEX_TEMPLATE_FILE,
    ISM_POLICY_FILE,
    PIPELINE_TEMPLATE_NAME,
    ROLES_FRAGMENT_FILE,
    SELF_TEST_VALUES,
    check_artifacts,
    check_deployed_salt,
    deployed_pipeline_salt,
    generate_main,
    generated_paths,
    painless_token_reference,
    render_artifacts,
    render_deployable,
    run_generator_selftest,
    run_token_selftest,
    selftest_main,
    tenants_in_repo,
    verify_quarantine_on_failure,
    verify_script_scheme,
    verify_script_structure,
)

SALT = "test-salt"

MINIMAL_FIELDS = """\
tenant: test-a
salt_env: KLAXON_ANONYMIZATION_SALT
mask_free_text_users: true
free_text_fields:
  - field: message
fields:
  - field: destination.ip
    family: IP
  - field: user.name
    family: USER
  - field: user.effective.name
    family: USER
  - field: host.hostname
    family: HOST
  - field: related.ip
    family: IP
    array: true
"""


@pytest.fixture
def cfg(tmp_path: Any) -> Any:
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(MINIMAL_FIELDS, encoding="utf-8")
    return load_tenant_config("test-a", root=tmp_path)


# --------------------------------------------------------------------------- #
# Loader validation
# --------------------------------------------------------------------------- #


def test_loader_refuses_related_hash(tmp_path: Any) -> None:
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(
        MINIMAL_FIELDS + "  - field: related.hash\n    family: USER\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="related.hash"):
        load_tenant_config("test-a", root=tmp_path)


def test_loader_rejects_unknown_family(tmp_path: Any) -> None:
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(
        MINIMAL_FIELDS + "  - field: foo.bar\n    family: BOGUS\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="family"):
        load_tenant_config("test-a", root=tmp_path)


def test_loader_rejects_duplicate_field(tmp_path: Any) -> None:
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(
        MINIMAL_FIELDS + "  - field: user.name\n    family: USER\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_tenant_config("test-a", root=tmp_path)


def test_loader_rejects_field_also_in_free_text(tmp_path: Any) -> None:
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(
        MINIMAL_FIELDS + "  - field: message\n    family: USER\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="both field and free_text_field"):
        load_tenant_config("test-a", root=tmp_path)


def test_loader_rejects_malformed_field_name(tmp_path: Any) -> None:
    """L9: a field name that could inject YAML into the generated config
    fragment (colon, hash, quote, whitespace) is refused at load."""
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(
        MINIMAL_FIELDS + "  - field: 'user.name: evil'\n    family: USER\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid field name"):
        load_tenant_config("test-a", root=tmp_path)


def test_loader_rejects_malformed_free_text_field_name(tmp_path: Any) -> None:
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    bad = MINIMAL_FIELDS.replace(
        "free_text_fields:\n  - field: message",
        "free_text_fields:\n  - field: 'message# x'",
    )
    (tenant_dir / "fields.yaml").write_text(bad, encoding="utf-8")
    with pytest.raises(ValueError, match="invalid field name"):
        load_tenant_config("test-a", root=tmp_path)


# --------------------------------------------------------------------------- #
# Token derivation
# --------------------------------------------------------------------------- #


def test_derive_token_is_the_token_function(cfg: Any) -> None:
    assert derive_token("jdoe", "USER", SALT) == token("USER", "jdoe", SALT)
    assert derive_token("192.168.50.42", "IP", SALT) == token(
        "IP", "192.168.50.42", SALT
    )


def test_token_is_deterministic_and_prefixed(cfg: Any) -> None:
    a = token("USER", "jdoe", SALT)
    b = token("USER", "jdoe", SALT)
    assert a == b
    assert a.startswith("[USER_")
    assert a.endswith("]")
    assert len(a) == len("[USER_") + 16 + 1


def test_token_differs_per_salt_and_value(cfg: Any) -> None:
    assert token("USER", "jdoe", SALT) != token("USER", "jdoe", "other-salt")
    assert token("USER", "jdoe", SALT) != token("USER", "jane", SALT)
    assert token("USER", "jdoe", SALT) != token("IP", "jdoe", SALT)


def test_token_is_idempotent_on_existing_tokens(cfg: Any) -> None:
    first = token("USER", "jdoe", SALT)
    assert token("USER", first, SALT) == first


def test_token_is_keyed_hmac_sha256(cfg: Any) -> None:
    """The stream token is HMAC-SHA256(key=salt, msg=`family:value`), truncated
    to 16 hex — a KEYED MAC, not a concatenation hash. Pins the exact
    construction so a revert to concat-SHA-256 fails here before the self-test
    even runs."""
    import hashlib as _hashlib
    import hmac as _hmac

    def py(salt: str, family: str, value: str) -> str:
        digest = _hmac.new(
            salt.encode(), f"{family}:{value}".encode(), _hashlib.sha256
        ).hexdigest()
        return f"[{family}_{digest[:16]}]"

    assert derive_token("alice", "USER", SALT) == py(SALT, "USER", "alice")
    assert token_hex("IP", "192.168.50.42", SALT) == _hmac.new(
        SALT.encode(), b"IP:192.168.50.42", _hashlib.sha256
    ).hexdigest()[:16]
    # Family separation: same value, different family -> different token.
    assert token("jdoe", "USER", SALT) != token("jdoe", "HOST", SALT)
    # Family is part of the MAC message: salt+value alone is not the key.
    assert token_hex("USER", "alice", SALT) != _hmac.new(
        SALT.encode(), b"alice", _hashlib.sha256
    ).hexdigest()[:16]
    # Unicode values are MAC'd over UTF-8 (matches the Painless utf8()).
    assert token("USER", "müller", SALT) == py(SALT, "USER", "müller")


# --------------------------------------------------------------------------- #
# Token-schema self-test (mandatory): Painless reference vs derive_token
# --------------------------------------------------------------------------- #


def test_painless_reference_matches_derive_token_byte_for_byte(cfg: Any) -> None:
    """The reference transcription of the Painless token() must equal derive_token
    for every representative value/family."""
    for value, family in SELF_TEST_VALUES:
        expected = derive_token(value, family, SALT)
        actual = painless_token_reference(family, value, SALT)
        assert actual == expected, (
            f"family={family} value={value!r}: Painless reference {actual!r} != "
            f"derive_token {expected!r}"
        )
        assert actual == token(family, value, SALT)


def test_run_token_selftest_passes(cfg: Any) -> None:
    assert run_token_selftest(SALT) == []


def test_run_token_selftest_fails_when_scheme_changed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Changing the scheme in derive_token (e.g. a different hash/truncation)
    MUST make the self-test fail — generation breaks, not the deployed pipeline."""

    def bad_derive_token(value: str, family: str, salt: str) -> str:
        if not value:
            return value
        if masking.TOKEN_RE.fullmatch(value):  # keep idempotency, like the real scheme
            return value
        digest = hashlib.sha512(f"{family}:{value}:{salt}".encode()).hexdigest()
        return f"[{family}_{digest[:24]}]"

    monkeypatch.setattr(masking, "derive_token", bad_derive_token)
    problems = run_token_selftest(SALT)
    assert problems
    # Every non-special value diverges (only empty + already-token pass through).
    assert len(problems) == len(SELF_TEST_VALUES) - 2


def test_generator_selftest_fails_on_tampered_script(cfg: Any) -> None:
    """A hand-edited (or wrongly generated) script that no longer encodes the
    derive_token scheme must be caught by the script-scheme verification."""
    source = build_pipeline(cfg, SALT)["processors"][0]["script"]["source"]
    assert verify_script_scheme(source) == []
    # The scheme is a KEYED HMAC; changing the inner pad (ipad 0x36 = 54)
    # breaks the MAC construction and must be flagged by the scheme markers.
    tampered = source.replace("kb[i] ^ 54", "kb[i] ^ 53")
    assert verify_script_scheme(tampered)
    assert run_generator_selftest(cfg, SALT) == []


def test_generator_selftest_reports_params_salt_mismatch(
    cfg: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the rendered pipeline's params.salt does not match the salt the selftest
    ran with, that is a problem (the deployable artifact would carry the wrong salt)."""
    real_build = masking.build_pipeline

    def broken(tenant_cfg: Any, salt: str) -> dict[str, Any]:
        pipeline = real_build(tenant_cfg, salt)
        pipeline["processors"][0]["script"]["params"] = {"salt": "wrong"}
        return pipeline

    monkeypatch.setattr(masking, "build_pipeline", broken)
    problems = run_generator_selftest(cfg, SALT)
    assert any("params.salt mismatch" in p for p in problems)


# --------------------------------------------------------------------------- #
# Structural compile-safety of the generated Painless script
# --------------------------------------------------------------------------- #


def test_verify_script_structure_passes_on_generated_script(cfg: Any) -> None:
    """The generator emits functions before statements and no ctx['_source']."""
    source = build_pipeline(cfg, SALT)["processors"][0]["script"]["source"]
    assert verify_script_structure(source) == []
    assert "ctx['_source']" not in source
    # Functions precede the first top-level statement. The HMAC helper set must
    # all be emitted before `def SALT =`.
    first_def = source.index("def SALT =")
    for name, rtype in (
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
        ("EMAIL", "Pattern"),
    ):
        assert source.index(f"{rtype} {name}(") < first_def, name


def test_verify_script_structure_catches_ctx_source(cfg: Any) -> None:
    """Bug 2 regression: a leftover ctx['_source'] must fail the structure check."""
    source = build_pipeline(cfg, SALT)["processors"][0]["script"]["source"]
    tampered = source.replace("ctx.clear();", "ctx['_source'].clear();")
    problems = verify_script_structure(tampered)
    assert any("ctx['_source']" in p for p in problems)


def test_verify_script_structure_catches_functions_after_statements(cfg: Any) -> None:
    """Bug 1 regression: Painless rejects functions declared after top-level
    statements (`unexpected token ['(']`); the structure check must too."""
    source = build_pipeline(cfg, SALT)["processors"][0]["script"]["source"]
    # Pull the whole `token` function out and re-append it after the main
    # logic, i.e. clearly after every top-level statement.
    token_fn = "String token(String family, String value, String SALT) {"
    start = source.index(token_fn)
    end = source.index("}\n", start) + len("}\n")
    body = source[start:end]
    tampered = source[:start] + source[end:] + "\n" + body
    problems = verify_script_structure(tampered)
    assert any("token" in p and "AFTER" in p for p in problems)


def test_verify_script_structure_catches_missing_function(cfg: Any) -> None:
    """A dropped function declaration is a compile failure at ingest time."""
    source = build_pipeline(cfg, SALT)["processors"][0]["script"]["source"]
    start = source.index("String hmacSha256Hex(String salt, String message) {")
    end = source.index("}\n", start) + len("}\n")
    tampered = source[:start] + source[end:]
    problems = verify_script_structure(tampered)
    assert any("missing function" in p and "hmacSha256Hex" in p for p in problems)


def test_generator_selftest_includes_structure_check(
    cfg: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tampering the emitted structure (ctx['_source']) must fail the whole
    generator self-test, not just the scheme check."""
    real_build = masking.build_pipeline

    def broken(tenant_cfg: Any, salt: str) -> dict[str, Any]:
        pipeline = real_build(tenant_cfg, salt)
        script = pipeline["processors"][0]["script"]
        script["source"] = script["source"].replace(
            "ctx.clear();", "ctx['_source'].clear();"
        )
        return pipeline

    monkeypatch.setattr(masking, "build_pipeline", broken)
    problems = run_generator_selftest(cfg, SALT)
    assert any("ctx['_source']" in p for p in problems)


# --------------------------------------------------------------------------- #
# Pipeline construction
# --------------------------------------------------------------------------- #


def test_pipeline_meta_carries_provenance(cfg: Any) -> None:
    pipeline = build_pipeline_template(cfg)
    meta = pipeline["_meta"]
    assert meta["tenant"] == "test-a"
    assert meta["source"] == "tenants/test-a/fields.yaml"
    assert meta["sha256"] == fields_yaml_sha256(cfg)
    assert meta["generator_version"]
    assert meta["generated_by"] == "klaxon masking generate"
    assert meta["fields"] == [
        "destination.ip",
        "user.name",
        "user.effective.name",
        "host.hostname",
        "related.ip",
    ]
    assert meta["free_text_fields"] == ["message"]


def test_pipeline_has_on_failure_flag(cfg: Any) -> None:
    """The on_failure block is FAIL-CLOSED: it reroutes a masking-failure doc
    OUT of the masked stream into the quarantine stream, preserving the original
    destination + failure reason (see `check_quarantine_routing` in the live
    test for the behavioural proof)."""
    pipeline = build_pipeline_template(cfg)
    script = pipeline["processors"][0]["script"]
    assert script["lang"] == "painless"
    on_failure = script["on_failure"]
    # Two handlers: capture {{ _ingest.on_failure_message }} (the only way
    # OpenSearch 3.x exposes it — not a script variable), then reroute.
    assert len(on_failure) == 2
    assert on_failure[0] == {
        "set": {
            "field": "klaxon.quarantine.reason",
            "value": "{{ _ingest.on_failure_message }}",
            "ignore_failure": True,
        }
    }
    assert on_failure[1]["script"]["lang"] == "painless"
    source = on_failure[1]["script"]["source"]
    assert "original_index" in source
    assert "masking_error" in source
    assert "ctx['_index']" in source
    assert cfg.quarantine_routing_index in source
    # FAIL-CLOSED marker: the doc is routed to quarantine, never left in the
    # masked stream (the old fail-open `set klaxon.masking_error` is gone).
    assert not any(
        h.get("set", {}).get("field") == "klaxon.masking_error" for h in on_failure
    )
    assert pipeline_has_quarantine_on_failure(pipeline)


def test_pipeline_quarantine_self_test(cfg: Any) -> None:
    """The mandatory self-test accepts the quarantine on_failure and REJECTS a
    revert to the old fail-open form (generation must abort)."""
    pipeline = build_pipeline_template(cfg)
    on_failure = pipeline["processors"][0]["script"]["on_failure"]
    assert verify_quarantine_on_failure(on_failure) == []
    assert run_generator_selftest(cfg, "salt") == []
    # Revert to fail-open: only flag masking_error, doc stays in the masked
    # stream -> the self-test must flag it.
    fail_open = [{"set": {"field": "klaxon.masking_error", "value": "boom"}}]
    problems = verify_quarantine_on_failure(fail_open)
    assert problems, "a fail-open on_failure must be rejected by the self-test"
    assert any("quarantine" in p for p in problems)


def test_pipeline_template_uses_salt_placeholder_in_params(cfg: Any) -> None:
    """The committed template keeps the salt out of the source: it lives in the
    script processor's `params.salt`, placeholder `__SALT__`."""
    script = build_pipeline_template(cfg)["processors"][0]["script"]
    assert script["params"] == {"salt": "__SALT__"}
    assert "__SALT__" not in script["source"]
    assert SALT not in script["source"]
    assert "def SALT = params.salt;" in script["source"]


def test_deployed_pipeline_bakes_real_salt_in_params(
    cfg: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "real-secret")
    script = deploy_pipeline(cfg)["processors"][0]["script"]
    assert script["params"] == {"salt": "real-secret"}
    assert "real-secret" not in script["source"]


def test_deploy_pipeline_omits_meta_and_embeds_provenance(
    cfg: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OpenSearch rejects `_meta` in ingest pipelines (HTTP 400), so the body
    PUT to the indexer must NOT carry `_meta`; provenance rides in `description`
    instead, and the drift checks must still fingerprint the deployed form."""
    monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "real-secret")
    deployed = deploy_pipeline(cfg)
    assert "_meta" not in deployed
    assert PROVENANCE_DESCRIPTION_MARKER in deployed["description"]
    meta = pipeline_provenance(deployed)
    assert meta["tenant"] == "test-a"
    assert meta["sha256"] == fields_yaml_sha256(cfg)
    assert meta["generator_version"]
    assert fingerprint_matches(deployed, cfg)
    assert pipeline_field_names(deployed) == effective_mask_fields_from_config(cfg)
    # The committed template keeps `_meta` for CI drift.
    assert "_meta" in build_pipeline_template(cfg)


def test_pipeline_never_masks_related_hash(cfg: Any) -> None:
    raw = json.dumps(build_pipeline_template(cfg))
    assert "related.hash" not in raw


def test_ism_policy_retention_and_priority(cfg: Any) -> None:
    ism = build_ism_policy(cfg, retention_days=14)
    policy = ism["policy"]
    hot = policy["states"][0]
    assert hot["name"] == "hot"
    assert policy["states"][1]["name"] == "delete"
    assert hot["transitions"][0]["conditions"]["min_index_age"] == "14d"
    assert ism["policy"]["ism_template"]["priority"] == 100
    assert ism["policy"]["ism_template"]["index_patterns"] == [
        "klaxon-masked-test-a-v5-*"
    ]


def test_index_template_targets_only_masked_stream(cfg: Any) -> None:
    template = build_index_template(cfg, {"properties": {}})
    # The pattern must match the DATA STREAM NAME (klaxon-masked-test-a-v5, no
    # trailing dash) for OpenSearch to create the stream; it also covers the
    # ...-v5-000001 backing indices. Wazuh streams are never matched.
    assert template["index_patterns"] == ["klaxon-masked-test-a-v5*"]
    assert template["priority"] == TEMPLATE_PRIORITY
    assert template["data_stream"] == {}
    settings = template["template"]["settings"]
    assert settings["index.default_pipeline"] == "klaxon-mask-test-a"
    # `index.lifecycle.name` is an Elasticsearch ILM setting that OpenSearch
    # rejects in index templates; the ISM policy attaches via its `ism_template`.
    assert "index.lifecycle.name" not in settings
    assert template["template"]["mappings"] == {"properties": {}}


def test_index_template_omits_mappings_when_none(cfg: Any) -> None:
    """The offline generator emits an index template WITHOUT mappings (the
    operator merges them at deploy time, e.g. via apply-masked-infra)."""
    template = build_index_template(cfg)
    assert "mappings" not in template["template"]
    assert template["priority"] == TEMPLATE_PRIORITY
    assert template["data_stream"] == {}


# --------------------------------------------------------------------------- #
# Quarantine artifacts (fail-closed masking-error routing)
# --------------------------------------------------------------------------- #


def test_quarantine_ism_retention_longer_than_masked(cfg: Any) -> None:
    ism = build_quarantine_ism_policy(cfg)
    policy = ism["policy"]
    hot = policy["states"][0]
    assert hot["name"] == "hot"
    assert policy["states"][1]["name"] == "delete"
    # Forensics: quarantine outlives the masked stream (90d default vs 30d).
    assert hot["transitions"][0]["conditions"]["min_index_age"] == "90d"
    assert QUARANTINE_RETENTION_DAYS == 90
    assert ism["policy"]["ism_template"]["priority"] == 100
    assert ism["policy"]["ism_template"]["index_patterns"] == [
        "klaxon-quarantine-test-a-v5-*"
    ]


def test_quarantine_ism_respects_override(cfg: Any) -> None:
    ism = build_quarantine_ism_policy(cfg, retention_days=180)
    assert ism["policy"]["states"][0]["transitions"][0]["conditions"][
        "min_index_age"
    ] == "180d"


def test_quarantine_index_template_targets_only_quarantine(cfg: Any) -> None:
    template = build_quarantine_index_template(cfg, {"properties": {}})
    # Own namespace: can never overlap the masked-stream LLM allowlist.
    assert template["index_patterns"] == ["klaxon-quarantine-test-a-v5*"]
    assert template["priority"] == TEMPLATE_PRIORITY
    assert template["data_stream"] == {}
    assert template["template"]["mappings"] == {"properties": {}}
    settings = template["template"]["settings"]
    # NO index.default_pipeline — quarantine docs must never re-enter masking.
    assert "index.default_pipeline" not in settings


def test_quarantine_index_template_omits_mappings_when_none(cfg: Any) -> None:
    template = build_quarantine_index_template(cfg)
    assert "mappings" not in template["template"]
    assert "index.default_pipeline" not in template["template"]["settings"]


def test_roles_fragment_least_privilege(cfg: Any) -> None:
    roles = build_roles_fragment(cfg)
    # LLM/report role: read on the MASKED stream ONLY.
    llm = "klaxon_llm_report_test-a:"
    assert llm in roles
    llm_block = roles.split(llm, 1)[1].split("\n\n")[0]
    assert cfg.masked_stream_pattern in llm_block
    assert cfg.quarantine_stream_pattern not in llm_block
    assert "klaxon-quarantine" not in llm_block
    # Ops/security role: read on quarantine + raw events, no LLM mapping.
    ops = "klaxon_ops_test-a:"
    assert ops in roles
    ops_block = roles.split(ops, 1)[1].split("\n\n")[0]
    assert cfg.quarantine_stream_pattern in ops_block
    assert cfg.raw_stream in ops_block
    # Sync service user: write on masked + quarantine (the quarantine write is
    # the fail-closed backstop for the on_failure reroute).
    sync = "klaxon_sync_test-a:"
    assert sync in roles
    sync_block = roles.split(sync, 1)[1]
    assert "write" in sync_block
    assert cfg.quarantine_stream_pattern in sync_block
    # Provenance header rides in a comment.
    assert fields_yaml_sha256(cfg) in roles
    assert cfg.source_rel in roles


def test_pipeline_has_no_hardcoded_field_logic(cfg: Any) -> None:
    """Field names must come from the injected FIELDS/FREE_TEXT tables only."""
    source = build_pipeline_template(cfg)["processors"][0]["script"]["source"]
    table_start = source.index("def FIELDS = ")
    table_end = source.index("def FREE_TEXT = ")
    logic = source[:table_start] + source[table_end:]
    for field in ("destination.ip", "user.name", "host.hostname"):
        assert field not in logic


def test_pipeline_declares_every_free_text_pattern(cfg: Any) -> None:
    """Every Pattern function referenced by maskPattern() must be declared in
    the script, or the deployed pipeline fails to compile and flags every
    document with klaxon.masking_error (regression for a dropped pattern-fn
    block). Patterns are `Pattern <NAME>() { return /regex/; }` functions."""
    source = build_pipeline_template(cfg)["processors"][0]["script"]["source"]
    used = {
        line.split("maskPattern(")[1].split(",")[0].strip().removesuffix("()")
        for line in source.splitlines()
        if "maskPattern(" in line and "String maskPattern" not in line
    }
    assert used, "expected the free-text pass to reference at least one Pattern"
    for symbol in used:
        assert any(
            f"Pattern {symbol}() {{" in line for line in source.splitlines()
        ), f"script uses {symbol}() but never declares it"


# --------------------------------------------------------------------------- #
# Config fragment
# --------------------------------------------------------------------------- #


def test_config_fragment_matches_fields_yaml(cfg: Any) -> None:
    fragment = build_config_fragment(cfg)
    data = yaml.safe_load(fragment)
    assert data["anonymization"]["mask_aggregation_keys"] is True
    assert data["anonymization"]["mask_free_text_users"] is True
    assert data["anonymization"]["mask_fields"] == [
        "destination.ip",
        "user.name",
        "user.effective.name",
        "host.hostname",
        "related.ip",
    ]
    assert data["anonymization"]["masked_streams"] == ["klaxon-masked-test-a-v5-*"]
    assert data["anonymization"]["mask_free_text_fields"] == ["message"]
    kinds = {p["field"]: p["type"] for p in data["gdpr_checker"]["custom_patterns"]}
    assert kinds["destination.ip"] == "IP_ADDRESS"
    assert kinds["user.name"] == "USERNAME"
    assert kinds["user.effective.name"] == "USERNAME"
    assert kinds["host.hostname"] == "HOSTNAME"


def test_config_fragment_custom_patterns_use_field_key_not_pattern(cfg: Any) -> None:
    data = yaml.safe_load(build_config_fragment(cfg))
    for pattern in data["gdpr_checker"]["custom_patterns"]:
        assert "field" in pattern
        assert "pattern" not in pattern


def test_config_fragment_has_provenance_comment(cfg: Any) -> None:
    fragment = build_config_fragment(cfg)
    assert "generated from tenants/test-a/fields.yaml" in fragment
    assert fields_yaml_sha256(cfg) in fragment


# --------------------------------------------------------------------------- #
# Artifact set: determinism, drift, deployable form
# --------------------------------------------------------------------------- #


def test_generated_paths_are_seven_artifacts(cfg: Any) -> None:
    paths = generated_paths(cfg)
    assert len(paths) == 7
    assert paths[0].name == CONFIG_FRAGMENT_NAME
    assert paths[1].name == PIPELINE_TEMPLATE_NAME.format(pipeline=cfg.pipeline_name)
    assert paths[2].name == ISM_POLICY_FILE.format(policy=cfg.ism_policy_name)
    assert paths[3].name == INDEX_TEMPLATE_FILE.format(template=cfg.index_template_name)
    # New fail-closed artifacts.
    assert paths[4].name == ISM_POLICY_FILE.format(policy=cfg.quarantine_ism_policy_name)
    assert paths[5].name == INDEX_TEMPLATE_FILE.format(
        template=cfg.quarantine_index_template_name
    )
    assert paths[6].name == ROLES_FRAGMENT_FILE.format(tenant=cfg.tenant)


def test_render_is_deterministic() -> None:
    cfg = load_tenant_config("customer-a")
    first = render_artifacts(cfg)
    second = render_artifacts(cfg)
    assert first == second
    assert set(first) == {str(p) for p in generated_paths(cfg)}


def test_render_artifacts_are_template_form(cfg: Any) -> None:
    """The committed artifact set is secret-free: pipeline params.salt == __SALT__,
    ISM/template included, config fragment carries the provenance comment."""
    contents = render_artifacts(cfg)
    assert set(contents) == {str(p) for p in generated_paths(cfg)}
    pipeline = json.loads(
        contents[str(generated_paths(cfg)[1])]
    )
    assert pipeline["processors"][0]["script"]["params"] == {"salt": "__SALT__"}
    ism = json.loads(contents[str(generated_paths(cfg)[2])])
    assert ism["policy"]["states"][0]["name"] == "hot"
    template = json.loads(contents[str(generated_paths(cfg)[3])])
    assert template["data_stream"] == {}
    assert "generated from tenants/test-a/fields.yaml" in contents[str(generated_paths(cfg)[0])]
    # Quarantine artifacts are part of the committed set too.
    quarantine_ism = json.loads(contents[str(generated_paths(cfg)[4])])
    assert quarantine_ism["policy"]["states"][0]["name"] == "hot"
    quarantine_template = json.loads(contents[str(generated_paths(cfg)[5])])
    assert quarantine_template["data_stream"] == {}
    assert "klaxon-quarantine-test-a-v5*" in quarantine_template["index_patterns"]
    roles = contents[str(generated_paths(cfg)[6])]
    assert "klaxon_llm_report_test-a" in roles
    assert "klaxon_ops_test-a" in roles
    assert "klaxon_sync_test-a" in roles


def test_render_deployable_has_real_salt(cfg: Any) -> None:
    deployable = render_deployable(cfg, "real-secret")
    pipeline = json.loads(deployable[PIPELINE_TEMPLATE_NAME.format(pipeline=cfg.pipeline_name)])
    assert pipeline["processors"][0]["script"]["params"] == {"salt": "real-secret"}
    # The deployable form carries NO `_meta` (OpenSearch rejects it); the
    # provenance rides in `description` so the deployed pipeline stays drift-checked.
    assert "_meta" not in pipeline
    assert pipeline_provenance(pipeline)["generator_version"]
    # The committed form must differ only in the salt slot.
    committed = render_artifacts(cfg)
    committed_pipeline = json.loads(
        committed[str(generated_paths(cfg)[1])]
    )
    assert committed_pipeline["processors"][0]["script"]["params"] != {
        "salt": "real-secret"
    }
    # The deployable set also carries the quarantine + roles artifacts.
    assert cfg.quarantine_ism_policy_name + ".json" in "".join(deployable)
    assert ROLES_FRAGMENT_FILE.format(tenant=cfg.tenant) in deployable


def test_committed_artifacts_match_regeneration() -> None:
    """CI invariant: the committed generated files equal a fresh regeneration."""
    cfg = load_tenant_config("customer-a")
    assert check_artifacts(cfg) == []


def test_check_artifacts_detects_drift(cfg: Any) -> None:
    # Nothing committed for the temp tenant -> every artifact is reported MISSING.
    drift = check_artifacts(cfg)
    assert len(drift) == 7
    assert all("MISSING" in line for line in drift)


def test_check_artifacts_detects_content_drift(cfg: Any, tmp_path: Any) -> None:
    from klaxon_mcp.masking import write_artifacts

    write_artifacts(cfg)
    assert check_artifacts(cfg) == []
    (tmp_path / "tenants" / "test-a" / "generated" / CONFIG_FRAGMENT_NAME).write_text(
        "tampered\n", encoding="utf-8"
    )
    drift = check_artifacts(cfg)
    assert any("DRIFT" in line for line in drift)


def test_tenants_in_repo_finds_customer_a() -> None:
    assert "customer-a" in tenants_in_repo(Path(__file__).resolve().parents[1])


# --------------------------------------------------------------------------- #
# Deploy-time salt comparison helpers
# --------------------------------------------------------------------------- #


def test_deployed_pipeline_salt_reads_params(cfg: Any) -> None:
    assert deployed_pipeline_salt(build_pipeline(cfg, "baked-secret")) == "baked-secret"


def test_deployed_pipeline_salt_falls_back_to_legacy_source(cfg: Any) -> None:
    legacy = {
        "processors": [
            {"script": {"lang": "painless", "source": 'def SALT = "old-secret";\n...'}}
        ]
    }
    assert deployed_pipeline_salt(legacy) == "old-secret"


def test_deployed_pipeline_salt_none_when_unreadable(cfg: Any) -> None:
    assert deployed_pipeline_salt({}) is None
    assert deployed_pipeline_salt({"processors": [{"set": {}}]}) is None


def test_check_deployed_salt_match(cfg: Any) -> None:
    deployed = build_pipeline(cfg, "same-salt")
    ok, message = check_deployed_salt(deployed, "same-salt")
    assert ok
    assert "matches" in message
    assert "same-salt" not in message  # only a 4-char prefix is shown


def test_check_deployed_salt_mismatch(cfg: Any) -> None:
    deployed = build_pipeline(cfg, "deployed-salt")
    ok, message = check_deployed_salt(deployed, "current-salt")
    assert not ok
    assert "SALT MISMATCH" in message
    assert "deployed-salt" not in message and "current-salt" not in message


def test_check_deployed_salt_unreadable(cfg: Any) -> None:
    ok, message = check_deployed_salt({}, "anything")
    assert not ok
    assert "no readable salt" in message


# --------------------------------------------------------------------------- #
# CLI behaviour
# --------------------------------------------------------------------------- #


def test_generate_check_passes_for_repo() -> None:
    assert generate_main(["--tenant", "customer-a", "--check"]) == 0


def test_generate_check_fails_for_missing_tenant() -> None:
    assert generate_main(["--tenant", "does-not-exist", "--check"]) != 0


def test_generate_writes_deployable_to_out(cfg: Any, tmp_path: Any) -> None:
    out_dir = tmp_path / "out"
    rc = generate_main(
        ["--tenant", "test-a", "--root", str(tmp_path), "--out", str(out_dir), "--salt", "x"]
    )
    assert rc == 0
    files = sorted(p.name for p in out_dir.iterdir())
    assert len(files) == 7
    pipeline = json.loads(
        (out_dir / PIPELINE_TEMPLATE_NAME.format(pipeline=cfg.pipeline_name)).read_text(
            encoding="utf-8"
        )
    )
    assert pipeline["processors"][0]["script"]["params"] == {"salt": "x"}
    # The quarantine + roles artifacts are emitted to the deployable dir too.
    assert (out_dir / ROLES_FRAGMENT_FILE.format(tenant=cfg.tenant)).exists()
    assert (
        out_dir
        / ISM_POLICY_FILE.format(policy=cfg.quarantine_ism_policy_name)
    ).exists()
    assert (
        out_dir
        / INDEX_TEMPLATE_FILE.format(template=cfg.quarantine_index_template_name)
    ).exists()


def test_generate_stdout_prints_deployable_artifacts(cfg: Any, tmp_path: Any, capsys: Any) -> None:
    rc = generate_main(
        ["--tenant", "test-a", "--root", str(tmp_path), "--stdout", "--salt", "x"]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "# ====== klaxon-config.yaml ======" in captured.out
    assert "# ====== pipeline-klaxon-mask-test-a.json ======" in captured.out
    assert '"salt": "x"' in captured.out
    # No files should be written in stdout mode.
    assert not (tmp_path / "tenants" / "test-a" / "generated").exists()


def test_generate_aborts_on_selftest_failure_no_artifacts(
    cfg: Any, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changing the token scheme in derive_token MUST make `generate` abort and
    emit NO artifacts (the acceptance criterion for the mandatory self-test)."""

    def bad_derive_token(value: str, family: str, salt: str) -> str:
        digest = hashlib.sha512(f"{family}:{value}:{salt}".encode()).hexdigest()
        return f"[{family}_{digest[:24]}]"

    monkeypatch.setattr(masking, "derive_token", bad_derive_token)
    rc = generate_main(["--tenant", "test-a", "--root", str(tmp_path)])
    assert rc != 0
    generated = tmp_path / "tenants" / "test-a" / "generated"
    assert not generated.exists() or not list(generated.iterdir())


def test_selftest_main_passes() -> None:
    assert selftest_main([]) == 0


def test_selftest_main_with_tenant_passes() -> None:
    assert selftest_main(["--tenant", "customer-a"]) == 0


def test_selftest_main_fails_on_missing_tenant() -> None:
    assert selftest_main(["--tenant", "does-not-exist"]) != 0
