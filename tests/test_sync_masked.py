# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Tests for the masked-stream sync job and the pipeline masking reference.

Two halves:

1. `pipeline_mask_doc` is the Python twin of the generated Painless script. These
   tests pin the masking logic on representative real-world log lines (LDAP DN,
   PAM, SSH publickey, effective.name, arrays, missing fields, already-tokenised
   input, mask_free_text_users=false) without needing an OpenSearch cluster.

2. `_sync` is the checkpoint/window/preflight logic. A fake indexer records the
   calls so we can assert no duplicate/lost window, no checkpoint advance on
   failure, and preflight aborts.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from klaxon_mcp import sync_masked
from klaxon_mcp.clients import Response
from klaxon_mcp.config import AnonymizationConfig, Config
from klaxon_mcp.masked_stream import (
    build_pipeline_template,
    load_tenant_config,
    pipeline_mask_doc,
    token,
)

SALT = "test-salt"

FIELDS_YAML = """\
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
  - field: related.user
    family: USER
    array: true
"""

FIELDS_YAML_NO_FREETEXT_USERS = FIELDS_YAML.replace(
    "mask_free_text_users: true", "mask_free_text_users: false"
)


@pytest.fixture
def cfg(tmp_path: Any) -> Any:
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(FIELDS_YAML, encoding="utf-8")
    return load_tenant_config("test-a", root=tmp_path)


@pytest.fixture
def cfg_no_freetext(tmp_path: Any) -> Any:
    tenant_dir = tmp_path / "tenants" / "test-a"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "fields.yaml").write_text(
        FIELDS_YAML_NO_FREETEXT_USERS, encoding="utf-8"
    )
    return load_tenant_config("test-a", root=tmp_path)


# --------------------------------------------------------------------------- #
# pipeline_mask_doc: the Python twin of the Painless masking
# --------------------------------------------------------------------------- #


class TestPipelineMaskDoc:
    def test_structured_fields_masked(self, cfg: Any) -> None:
        doc = {
            "user.name": "jdoe",
            "user.effective.name": "jsmith",
            "destination.ip": "10.0.0.5",
            "host.hostname": "web01",
            "message": "user jdoe logged in from 10.0.0.5",
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        assert out["user.name"] == token("USER", "jdoe", SALT)
        assert out["user.effective.name"] == token("USER", "jsmith", SALT)
        assert out["destination.ip"] == token("IP", "10.0.0.5", SALT)
        assert out["host.hostname"] == token("HOST", "web01", SALT)
        msg = out["message"]
        assert token("USER", "jdoe", SALT) in msg
        assert token("IP", "10.0.0.5", SALT) in msg
        assert "jdoe" not in msg
        assert "10.0.0.5" not in msg

    def test_ldap_dn_username_masked(self, cfg: Any) -> None:
        doc = {
            "user.effective.name": "jsmith",
            "message": "cn=jsmith,ou=people,dc=example,dc=com",
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        assert token("USER", "jsmith", SALT) in out["message"]
        assert "jsmith" not in out["message"]

    def test_pam_line_masked(self, cfg: Any) -> None:
        doc = {
            "message": (
                "pam_unix(sshd:auth): authentication failure; logname= uid=0 "
                "euid=0 tty=ssh ruser= rhost=10.1.2.3  user=root"
            )
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        msg = out["message"]
        assert token("IP", "10.1.2.3", SALT) in msg
        assert token("USER", "root", SALT) in msg
        assert "10.1.2.3" not in msg
        assert "user=root" not in msg

    def test_ssh_publickey_masked(self, cfg: Any) -> None:
        doc = {
            "message": (
                "Accepted publickey for jsmith from 10.0.0.9 port 22 ssh2: "
                "RSA SHA256:AbC123Def456"
            )
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        msg = out["message"]
        assert token("USER", "jsmith", SALT) in msg
        assert token("IP", "10.0.0.9", SALT) in msg
        assert "jsmith" not in msg
        assert "10.0.0.9" not in msg

    def test_array_fields_masked_elementwise(self, cfg: Any) -> None:
        doc = {
            "related.ip": ["1.2.3.4", "5.6.7.8"],
            "related.user": ["alice", "bob"],
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        assert out["related.ip"] == [
            token("IP", "1.2.3.4", SALT),
            token("IP", "5.6.7.8", SALT),
        ]
        assert out["related.user"] == [
            token("USER", "alice", SALT),
            token("USER", "bob", SALT),
        ]

    def test_missing_fields_are_a_noop(self, cfg: Any) -> None:
        doc = {"message": "no structured fields here"}
        out = pipeline_mask_doc(doc, cfg, SALT)
        assert out == {"message": "no structured fields here"}

    def test_already_tokenised_input_is_idempotent(self, cfg: Any) -> None:
        t = token("USER", "jdoe", SALT)
        doc = {
            "user.name": t,
            "message": f"login ok for {t} from 10.0.0.9",
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        assert out["user.name"] == t
        msg = out["message"]
        assert t in msg
        assert token("IP", "10.0.0.9", SALT) in msg
        assert "10.0.0.9" not in msg

    def test_mask_free_text_users_false_gates_broader_patterns(
        self, cfg_no_freetext: Any
    ) -> None:
        # SSH publickey and the registry are gated; the IP still masks.
        doc = {
            "user.name": "jdoe",
            "message": "Accepted publickey for jsmith from 10.0.0.9; user jdoe",
        }
        out = pipeline_mask_doc(doc, cfg_no_freetext, SALT)
        msg = out["message"]
        assert token("IP", "10.0.0.9", SALT) in msg
        assert "10.0.0.9" not in msg
        # SSH_PUBKEY gated off: the raw username stays in free text.
        assert "jsmith" in msg
        # USER_NOUN is always-on: "user jdoe" still tokenises.
        assert token("USER", "jdoe", SALT) in msg
        assert "user jdoe" not in msg

    def test_token_matches_structured_value(self, cfg: Any) -> None:
        """The free-text token for a username equals its structured token."""
        doc = {
            "user.name": "jdoe",
            "message": "user jdoe did a thing",
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        structured = out["user.name"]
        assert structured == token("USER", "jdoe", SALT)
        assert structured in out["message"]


# --------------------------------------------------------------------------- #
# _sync: window computation, checkpoint safety, preflight aborts
# --------------------------------------------------------------------------- #

FIXED_NOW = datetime(2026, 8, 5, 12, 0, 0, tzinfo=timezone.utc)


class FakeIndexer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.deployed_pipeline: dict[str, Any] | None = None
        self.checkpoint: str | None = None
        self.reindex_ok = True
        self.reindex_failures: list[Any] | None = None
        self.masking_error_hits = 0

    def _resp(self, status: int, payload: Any, path: str) -> Response:
        return Response(
            status, json.dumps(payload), f"https://indexer.example{path}"
        )

    async def get(self, path: str, body: Any = None) -> Response:
        self.calls.append(("get", path, body))
        if path.startswith("/_ingest/pipeline/"):
            if self.deployed_pipeline is None:
                return self._resp(404, {}, path)
            name = path.rsplit("/", 1)[-1]
            return self._resp(200, {name: self.deployed_pipeline}, path)
        if "/_doc/" in path:
            if self.checkpoint is None:
                return self._resp(404, {}, path)
            return self._resp(200, {"_source": {"checkpoint": self.checkpoint}}, path)
        if path.endswith("/_mapping"):
            return self._resp(
                200,
                {"wazuh-events-v5-000001": {"mappings": {"properties": {}}}},
                path,
            )
        return self._resp(404, {}, path)

    async def post(self, path: str, body: Any = None) -> Response:
        self.calls.append(("post", path, body))
        if path.endswith("/_reindex"):
            if not self.reindex_ok:
                return self._resp(500, {"error": {"type": "boom"}}, path)
            return self._resp(200, {"took": 1, "failures": self.reindex_failures or []}, path)
        if path.endswith("/_search"):
            return self._resp(
                200,
                {"hits": {"total": {"value": self.masking_error_hits, "relation": "eq"}}},
                path,
            )
        return self._resp(404, {}, path)

    async def put(self, path: str, body: Any = None) -> Response:
        self.calls.append(("put", path, body))
        return self._resp(200, {"result": "created"}, path)


def _config(cfg: Any) -> Config:
    return Config(
        indexer_url="https://indexer.example:9200",
        indexer_user="",
        indexer_password="",
        manager_url="",
        manager_user="",
        manager_password="",
        engine_url="",
        verify_ssl=False,
        timeout=60.0,
        schema_field_limit=200,
        schema_probe_batch=100,
        search_max_size=100,
        logtest_default_trace_level="ASSET_ONLY",
        logtest_default_space="custom",
        anonymization=AnonymizationConfig(
            mask_fields=cfg.all_masked_fields,
            mask_free_text_fields=cfg.free_text_fields,
        ),
    )


def _reindex_call(fake: FakeIndexer) -> dict[str, Any] | None:
    for kind, path, body in fake.calls:
        if kind == "post" and path.endswith("/_reindex"):
            return body  # type: ignore[return-value]
    return None


def _checkpoint_puts(fake: FakeIndexer) -> list[dict[str, Any]]:
    puts: list[dict[str, Any]] = []
    for kind, path, body in fake.calls:
        if kind == "put" and "/_doc/" in path:
            assert isinstance(body, dict)
            puts.append(body)
    return puts


@pytest.fixture(autouse=True)
def frozen_now(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sync_masked, "_now", lambda: FIXED_NOW)


def _run_sync(
    cfg: Any, fake: FakeIndexer, **kwargs: Any
) -> int:
    opts = {
        "overlap_hours": 1,
        "initial_lookback_hours": 24,
        "dry_run": False,
        **kwargs,
    }
    return asyncio.run(
        sync_masked._sync(fake, cfg, _config(cfg), **opts)
    )


class TestSyncWindow:
    def test_initial_lookback_when_no_checkpoint(self, cfg: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        assert _run_sync(cfg, fake) == 0
        body = _reindex_call(fake)
        assert body is not None
        assert body["source"]["index"] == cfg.raw_stream
        assert body["dest"]["index"] == cfg.masked_stream
        assert body["dest"]["pipeline"] == cfg.pipeline_name
        assert body["dest"]["op_type"] == "create"
        assert body["conflicts"] == "proceed"
        rng = body["source"]["query"]["range"]["@timestamp"]
        assert rng["lte"] == sync_masked._iso(FIXED_NOW)
        assert rng["gte"] == sync_masked._iso(FIXED_NOW - timedelta(hours=24))

    def test_overlap_back_from_checkpoint(self, cfg: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        checkpoint = FIXED_NOW - timedelta(hours=2)
        fake.checkpoint = sync_masked._iso(checkpoint)
        assert _run_sync(cfg, fake) == 0
        body = _reindex_call(fake)
        assert body is not None
        rng = body["source"]["query"]["range"]["@timestamp"]
        # overlap_hours=1: the scan starts 1h before the checkpoint.
        assert rng["gte"] == sync_masked._iso(checkpoint - timedelta(hours=1))

    def test_checkpoint_advanced_on_success(self, cfg: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        assert _run_sync(cfg, fake) == 0
        puts = _checkpoint_puts(fake)
        assert len(puts) == 1
        assert puts[0]["checkpoint"] == sync_masked._iso(FIXED_NOW)
        assert puts[0]["tenant"] == "test-a"

    def test_checkpoint_not_advanced_on_http_failure(self, cfg: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.reindex_ok = False
        assert _run_sync(cfg, fake) == 1
        assert _checkpoint_puts(fake) == []

    def test_checkpoint_not_advanced_on_reindex_failures(self, cfg: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.reindex_failures = [{"index": "x", "reason": "boom"}]
        assert _run_sync(cfg, fake) == 1
        assert _checkpoint_puts(fake) == []

    def test_dry_run_sends_nothing(self, cfg: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        assert _run_sync(cfg, fake, dry_run=True) == 0
        assert _reindex_call(fake) is None
        assert _checkpoint_puts(fake) == []


class TestSyncPreflight:
    def test_aborts_when_pipeline_not_deployed(self, cfg: Any) -> None:
        fake = FakeIndexer()  # deployed_pipeline stays None
        assert _run_sync(cfg, fake) == 1
        assert _reindex_call(fake) is None

    def test_aborts_on_fingerprint_mismatch(self, cfg: Any) -> None:
        fake = FakeIndexer()
        stale = build_pipeline_template(cfg)
        stale["_meta"]["fields"] = ["something.else"]  # drift
        fake.deployed_pipeline = stale
        assert _run_sync(cfg, fake) == 1
        assert _reindex_call(fake) is None

    def test_aborts_when_config_masks_different_fields(self, cfg: Any) -> None:
        from dataclasses import replace

        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        config = replace(
            _config(cfg),
            anonymization=replace(
                _config(cfg).anonymization, mask_fields=("source.ip",)
            ),
        )
        result = asyncio.run(
            sync_masked._sync(
                fake,
                cfg,
                config,
                overlap_hours=1,
                initial_lookback_hours=24,
                dry_run=False,
            )
        )
        assert result == 1
        assert _reindex_call(fake) is None


class TestReportMaskingErrors:
    def test_warns_on_flagged_documents(self, cfg: Any, capsys: Any) -> None:
        fake = FakeIndexer()
        fake.masking_error_hits = 3
        asyncio.run(sync_masked._report_masking_errors(fake, cfg))
        err = capsys.readouterr().err
        assert "klaxon.masking_error" in err
        assert "3 document(s)" in err

    def test_silent_when_none_flagged(self, cfg: Any, capsys: Any) -> None:
        fake = FakeIndexer()
        fake.masking_error_hits = 0
        asyncio.run(sync_masked._report_masking_errors(fake, cfg))
        assert capsys.readouterr().err == ""
