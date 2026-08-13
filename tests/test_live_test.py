# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Offline unit tests for `klaxon masking test` (`klaxon_mcp.live_test`).

The LIVE part (against a real indexer) lives in `tests/test_live_masking.py` and
is marked `integration`/`live` (skipped without credentials). These tests cover
the parts that run without a cluster: credential resolution (env + gitignored
dotenv, never logged), URL sanitisation, the Painless compile probe, the salt
resolution and the Stage-B assertions (validated against the Python twin of the
masking script).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from klaxon_mcp import live_test
from klaxon_mcp.masked_stream import load_tenant_config, pipeline_mask_doc


# Env vars the live-test config reads (credentials + the optional TLS knob).
_LIVE_TEST_ENV = (*live_test.LIVE_ENV_NAMES, live_test.LIVE_ENV_VERIFY_SSL)


@pytest.fixture
def clean_indexer_env() -> None:
    """Snapshot and clear the KLAXON_INDEXER_* env vars, then restore them
    EXACTLY afterwards. Tests that load a dotenv file set os.environ directly,
    so monkeypatch's restore-on-first-touch would wrongly re-persist the loaded
    credentials — this fixture restores the pre-test state unconditionally."""
    saved = {name: os.environ.get(name) for name in _LIVE_TEST_ENV}
    for name in _LIVE_TEST_ENV:
        os.environ.pop(name, None)
    yield
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value

# A tenant whose fields.yaml covers every field referenced by live_test_docs().
LIVE_TEST_FIELDS = """\
tenant: test-live
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
  - field: related.user
    family: USER
    array: true
  - field: related.hosts
    family: HOST
    array: true
  - field: event.original
    family: USER
  - field: host.hostname
    family: HOST
"""


@pytest.fixture
def cfg(tmp_path: Any) -> Any:
    tenant_dir = tmp_path / "tenants" / "test-live"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(LIVE_TEST_FIELDS, encoding="utf-8")
    return load_tenant_config("test-live", root=tmp_path)


# --------------------------------------------------------------------------- #
# Credential resolution: env + local dotenv, never logged
# --------------------------------------------------------------------------- #


def test_resolve_live_config_missing_envs_skips_cleanly(
    clean_indexer_env: None,
) -> None:
    # Explicit non-existent override so a real gitignored tests/live/.env (if
    # the developer has one) is NOT picked up — this test proves the skip gate.
    config, missing = live_test.resolve_live_config(
        env_file="/nonexistent/credentials.env"
    )
    assert config is None
    assert set(missing) == set(live_test.LIVE_ENV_NAMES)


def test_resolve_live_config_reads_dotenv(
    tmp_path: Path, clean_indexer_env: None
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# local credentials — never committed\n"
        "export KLAXON_INDEXER_URL=\"https://indexer:9200\"\n"
        "KLAXON_INDEXER_USER=admin\n"
        "KLAXON_INDEXER_PASSWORD='s3cr3t'\n",
        encoding="utf-8",
    )
    config, missing = live_test.resolve_live_config(env_file=env_file)
    assert missing == ()
    assert config is not None
    assert config.url == "https://indexer:9200"
    assert config.user == "admin"
    assert config.password == "s3cr3t"


def test_load_dotenv_never_overrides_existing_env(
    tmp_path: Path, clean_indexer_env: None
) -> None:
    os.environ["KLAXON_INDEXER_URL"] = "https://already-set:9200"
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# all three come from the file\n"
        "KLAXON_INDEXER_URL=https://from-file:9200\n"
        "KLAXON_INDEXER_USER=admin\n"
        "KLAXON_INDEXER_PASSWORD=s3cr3t\n",
        encoding="utf-8",
    )
    config, missing = live_test.resolve_live_config(env_file=env_file)
    assert missing == ()
    assert config is not None
    # An already-set env var wins over the file; the file fills the rest.
    assert config.url == "https://already-set:9200"
    assert config.user == "admin"
    assert config.password == "s3cr3t"


def test_safe_url_strips_embedded_credentials() -> None:
    assert (
        live_test.safe_url("https://admin:topsecret@indexer:9200")
        == "https://indexer:9200"
    )
    assert live_test.safe_url("https://indexer:9200") == "https://indexer:9200"
    assert (
        live_test.safe_url("https://user@indexer.example:9200/path")
        == "https://indexer.example:9200/path"
    )


def test_url_embedded_credentials_detected() -> None:
    assert live_test._url_has_embedded_credentials("https://a:b@h:9200")
    assert not live_test._url_has_embedded_credentials("https://h:9200")


def test_live_salt_prefers_explicit_then_env_then_fixed(
    cfg: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert live_test.live_salt(cfg, explicit="x") == "x"
    monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "env-salt")
    assert live_test.live_salt(cfg) == "env-salt"
    monkeypatch.delenv("KLAXON_ANONYMIZATION_SALT", raising=False)
    assert live_test.live_salt(cfg) == live_test.DEFAULT_TEST_SALT


def test_verify_ssl_parsing(tmp_path: Path, clean_indexer_env: None) -> None:
    """KLAXON_INDEXER_VERIFY_SSL is optional (default true); false works for a
    self-signed lab. Only the credential vars gate the skip."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "KLAXON_INDEXER_URL=https://indexer:9200\n"
        "KLAXON_INDEXER_USER=admin\n"
        "KLAXON_INDEXER_PASSWORD=s3cr3t\n",
        encoding="utf-8",
    )
    # Default: verify on.
    assert live_test.resolve_live_config(env_file=env_file)[0].verify_ssl is True
    # Explicitly disabled (lab cluster).
    os.environ[live_test.LIVE_ENV_VERIFY_SSL] = "false"
    assert live_test.resolve_live_config(env_file=env_file)[0].verify_ssl is False
    # Unrecognised value falls back to the secure default.
    os.environ[live_test.LIVE_ENV_VERIFY_SSL] = "bogus"
    assert live_test.resolve_live_config(env_file=env_file)[0].verify_ssl is True


# --------------------------------------------------------------------------- #
# Stage A — ingest allowlist preflight
# --------------------------------------------------------------------------- #


def _allowlist_without(classes: list[dict[str, Any]], drop: str) -> dict[str, Any]:
    """A fake _context?context=ingest response with one class removed."""
    return {"name": "ingest", "classes": [c for c in classes if c["name"] != drop]}


_FULL_CLASSES = [
    {"name": "java.lang.String", "methods": [{"name": "sha256"}, {"name": "isEmpty"}, {"name": "substring"}, {"name": "charAt"}, {"name": "length"}, {"name": "indexOf"}], "static_methods": []},
    {"name": "java.util.regex.Pattern", "methods": [{"name": "matcher"}], "static_methods": []},
    {"name": "java.util.regex.Matcher", "methods": [{"name": "find"}], "static_methods": []},
    {"name": "java.lang.StringBuilder", "methods": [{"name": "append"}], "static_methods": []},
    {"name": "java.util.ArrayList", "methods": [], "static_methods": []},
    {"name": "java.util.HashMap", "methods": [], "static_methods": []},
    {"name": "java.util.Map", "methods": [], "static_methods": []},
    {"name": "java.util.List", "methods": [], "static_methods": []},
]


def test_missing_ingest_members_empty_when_complete() -> None:
    assert live_test.missing_ingest_members({"classes": _FULL_CLASSES}) == []


def test_missing_ingest_members_flags_missing_sha256() -> None:
    classes = [
        {**c, "methods": [m for m in c.get("methods", []) if m["name"] != "sha256"]}
        if c["name"] == "java.lang.String"
        else c
        for c in _FULL_CLASSES
    ]
    missing = live_test.missing_ingest_members({"classes": classes})
    assert any("sha256" in m for m in missing)


def test_missing_ingest_members_flags_missing_type() -> None:
    missing = live_test.missing_ingest_members(
        _allowlist_without(_FULL_CLASSES, "java.util.regex.Pattern")
    )
    assert any("Pattern" in m for m in missing)


# --------------------------------------------------------------------------- #
# Stage B assertions validated against the Python twin of the Painless script
# --------------------------------------------------------------------------- #


def test_check_simulated_passes_on_python_twin(cfg: Any) -> None:
    """The Stage-B assertions hold when fed the Python twin's output — i.e. the
    expected tokens match the masking logic the Painless script implements."""
    docs = live_test.live_test_docs()
    sources = [pipeline_mask_doc(d["_source"], cfg, "salt") for d in docs]
    assert live_test.check_simulated(sources, cfg, "salt") == []


def test_check_simulated_detects_raw_username(cfg: Any) -> None:
    sources = [dict(d["_source"]) for d in live_test.live_test_docs()]
    # Undo the masking of doc 1's user.name: the assertions must flag it.
    problems = live_test.check_simulated(sources, cfg, "salt")
    assert problems


def test_check_simulated_detects_masked_hash(cfg: Any) -> None:
    from klaxon_mcp.masked_stream import token

    sources = [dict(d["_source"]) for d in live_test.live_test_docs()]
    sources[0]["related.hash"] = [token("USER", "sha256:aa11", "salt")]
    problems = live_test.check_simulated(sources, cfg, "salt")
    assert any("related.hash" in p for p in problems)


# --------------------------------------------------------------------------- #
# Stage C — quarantine on_failure routing (fail-closed)
# --------------------------------------------------------------------------- #


def _rerouted_source() -> dict[str, Any]:
    return {
        "message": "sudo: pam_unix(sudo:session): session opened for user alice",
        "klaxon": {
            "quarantine": {
                "original_index": "klaxon-masked-test-live-v5-000001",
                "reason": "boom-test",
            },
            "masking_error": True,
        },
    }


def test_check_quarantine_routing_passes_on_expected_reroute(cfg: Any) -> None:
    sources = [_rerouted_source()]
    indexes = [cfg.quarantine_routing_index]
    assert live_test.check_quarantine_routing(sources, indexes, cfg) == []


def test_check_quarantine_routing_flags_wrong_index(cfg: Any) -> None:
    sources = [_rerouted_source()]
    indexes = [cfg.masked_stream_pattern.replace("-*", "-000001")]
    problems = live_test.check_quarantine_routing(sources, indexes, cfg)
    assert any(cfg.quarantine_routing_index in p for p in problems)


def test_check_quarantine_routing_flags_missing_reason(cfg: Any) -> None:
    src = _rerouted_source()
    del src["klaxon"]["quarantine"]["reason"]
    problems = live_test.check_quarantine_routing([src], [cfg.quarantine_routing_index], cfg)
    assert any("reason" in p for p in problems)


def test_check_quarantine_routing_flags_missing_original_index(cfg: Any) -> None:
    src = _rerouted_source()
    del src["klaxon"]["quarantine"]["original_index"]
    problems = live_test.check_quarantine_routing([src], [cfg.quarantine_routing_index], cfg)
    assert any("original_index" in p for p in problems)


def test_check_quarantine_routing_flags_missing_masking_error(cfg: Any) -> None:
    src = _rerouted_source()
    del src["klaxon"]["masking_error"]
    problems = live_test.check_quarantine_routing([src], [cfg.quarantine_routing_index], cfg)
    assert any("masking_error" in p for p in problems)


def test_pipeline_with_forced_failure_keeps_on_failure(cfg: Any) -> None:
    from klaxon_mcp.masked_stream import build_pipeline

    pipeline = build_pipeline(cfg, "salt")
    original_on_failure = pipeline["processors"][0]["script"]["on_failure"]
    variant = live_test._pipeline_with_forced_failure(pipeline)
    # _meta/version stripped (simulate rejects them), source replaced with a
    # throw, on_failure preserved verbatim.
    assert "_meta" not in variant and "version" not in variant
    script = variant["processors"][0]["script"]
    assert script["on_failure"] == original_on_failure
    assert "throw new RuntimeException" in script["source"]
    assert "masking_error" in script["source"].lower() or "original_index" not in script["source"]
