# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Tests for the Option B generator: fields.yaml -> config fragment + pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from klaxon_mcp.generate_masking import (
    CONFIG_FRAGMENT_NAME,
    PIPELINE_TEMPLATE_NAME,
    check_artifacts,
    generated_paths,
    render_artifacts,
    tenants_in_repo,
)
from klaxon_mcp.masked_stream import (
    TEMPLATE_PRIORITY,
    build_config_fragment,
    build_index_template,
    build_ism_policy,
    build_pipeline_template,
    deploy_pipeline,
    fields_yaml_sha256,
    load_tenant_config,
    token,
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
        MINIMAL_FIELDS
        + "  - field: message\n    family: USER\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="both field and free_text_field"):
        load_tenant_config("test-a", root=tmp_path)


# --------------------------------------------------------------------------- #
# Token derivation
# --------------------------------------------------------------------------- #


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


# --------------------------------------------------------------------------- #
# Pipeline construction
# --------------------------------------------------------------------------- #


def test_pipeline_meta_carries_provenance(cfg: Any) -> None:
    pipeline = build_pipeline_template(cfg)
    meta = pipeline["_meta"]
    assert meta["tenant"] == "test-a"
    assert meta["source"] == "tenants/test-a/fields.yaml"
    assert meta["sha256"] == fields_yaml_sha256(cfg)
    assert meta["fields"] == [
        "destination.ip",
        "user.name",
        "user.effective.name",
        "host.hostname",
        "related.ip",
    ]
    assert meta["free_text_fields"] == ["message"]


def test_pipeline_has_on_failure_flag(cfg: Any) -> None:
    pipeline = build_pipeline_template(cfg)
    script = pipeline["processors"][0]["script"]
    assert script["on_failure"] == [
        {"set": {"field": "klaxon.masking_error", "value": "{{ _ingest.on_failure_message }}"}}
    ]


def test_pipeline_template_uses_salt_placeholder(cfg: Any) -> None:
    source = build_pipeline_template(cfg)["processors"][0]["script"]["source"]
    assert "__SALT__" in source
    assert SALT not in source


def test_deployed_pipeline_bakes_real_salt(
    cfg: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "real-secret")
    source = deploy_pipeline(cfg)["processors"][0]["script"]["source"]
    assert "__SALT__" not in source
    assert "real-secret" in source


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
    assert template["index_patterns"] == ["klaxon-masked-test-a-v5-*"]
    assert template["priority"] == TEMPLATE_PRIORITY
    assert template["data_stream"] == {}
    settings = template["template"]["settings"]
    assert settings["index.default_pipeline"] == "klaxon-mask-test-a"
    assert settings["index.lifecycle.name"] == "klaxon-masked-retention-test-a"
    assert template["template"]["mappings"] == {"properties": {}}


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
    assert kinds["host.hostname"] == "HOSTNAME"


def test_config_fragment_has_provenance_comment(cfg: Any) -> None:
    fragment = build_config_fragment(cfg)
    assert "generated from tenants/test-a/fields.yaml" in fragment
    assert fields_yaml_sha256(cfg) in fragment


# --------------------------------------------------------------------------- #
# Artifacts: determinism + drift check
# --------------------------------------------------------------------------- #


def test_render_is_deterministic() -> None:
    cfg = load_tenant_config("customer-a")
    first = render_artifacts(cfg)
    second = render_artifacts(cfg)
    assert first == second
    paths = generated_paths(cfg)
    assert set(first) == {str(paths[0]), str(paths[1])}


def test_committed_artifacts_match_regeneration() -> None:
    """CI invariant: the committed generated files equal a fresh regeneration."""
    cfg = load_tenant_config("customer-a")
    assert check_artifacts(cfg) == []


def test_check_artifacts_detects_drift(cfg: Any, tmp_path: Any) -> None:
    (tmp_path / "tenants" / "test-a" / "generated").mkdir()
    cfg_path, pipeline_path = generated_paths(cfg)
    # Regenerated path is repo-root based; force drift by checking the path
    # that render_artifacts will write (repo root), so simulate with the real
    # repo tenant instead. Here we only prove the drift is reported when the
    # committed file differs from regeneration.
    drift = check_artifacts(cfg)
    assert drift  # nothing committed for the temp tenant -> MISSING reported


def test_tenants_in_repo_finds_customer_a() -> None:
    from klaxon_mcp.generate_masking import main as generate_main

    # The example tenant is committed in the repo.
    assert "customer-a" in tenants_in_repo(Path(__file__).resolve().parents[1])


def test_pipeline_has_no_hardcoded_field_logic(cfg: Any) -> None:
    """Field names must come from the injected FIELDS/FREE_TEXT tables only."""
    source = build_pipeline_template(cfg)["processors"][0]["script"]["source"]
    # The literal field names may only appear inside the table declarations.
    table_start = source.index("def FIELDS = ")
    table_end = source.index("def FREE_TEXT = ")
    logic = source[:table_start] + source[table_end:]
    for field in ("destination.ip", "user.name", "host.hostname"):
        assert field not in logic


# --------------------------------------------------------------------------- #
# CLI behaviour
# --------------------------------------------------------------------------- #


def test_generate_masking_check_passes_for_repo() -> None:
    from klaxon_mcp.generate_masking import main as generate_main

    assert generate_main(["--tenant", "customer-a", "--check"]) == 0


def test_generate_masking_check_fails_for_missing_tenant() -> None:
    from klaxon_mcp.generate_masking import main as generate_main

    assert generate_main(["--tenant", "does-not-exist", "--check"]) != 0
