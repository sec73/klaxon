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
from klaxon_mcp.clients import Response, TransportError
from klaxon_mcp.config import AnonymizationConfig, Config
from klaxon_mcp.masked_stream import (
    build_pipeline,
    build_pipeline_template,
    load_tenant_config,
    pipeline_mask_doc,
    token,
)
from klaxon_mcp.tenants import effective_free_text_fields

SALT = "test-salt"

FIELDS_YAML = """\
tenant: test-a
salt_env: KLAXON_ANONYMIZATION_SALT
mask_free_text_users: true
fields:
  - field: destination.ip
    family: IP
  - field: user.name
    family: USER
  - field: user.effective.name
    family: USER
  - field: host.hostname
    family: HOST
  - field: event.original
    family: USER
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

    def test_event_original_masked_to_single_token(self, cfg: Any) -> None:
        """event.original (a structured scalar USER field) becomes ONE token —
        the whole raw line is replaced, not per-value free-text masked."""
        raw = (
            "Aug 11 06:00:00 web01 sshd[123]: Failed password for jsmith "
            "from 10.0.0.9 port 22"
        )
        out = pipeline_mask_doc({"event.original": raw}, cfg, SALT)
        expected = token("USER", raw, SALT)
        assert out["event.original"] == expected
        assert out["event.original"].startswith("[USER_")
        assert len(out["event.original"]) == len("[USER_") + 16 + 1

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
        # SSH publickey AND the known-identity registry are gated; the IP still
        # masks. USER_NOUN is always-on but needs its `:`/`=` separator, so a
        # BARE username mention ("user jdoe") stays raw while "user: jdoe"
        # tokenises — exactly like the Painless maskFreeText and the response
        # layer (the registry is gated on mask_free_text_users there too).
        doc = {
            "user.name": "jdoe",
            "message": (
                "Accepted publickey for jsmith from 10.0.0.9; user jdoe; "
                "user: jdoe"
            ),
        }
        out = pipeline_mask_doc(doc, cfg_no_freetext, SALT)
        msg = out["message"]
        assert token("IP", "10.0.0.9", SALT) in msg
        assert "10.0.0.9" not in msg
        # SSH_PUBKEY gated off: the raw username stays in free text.
        assert "jsmith" in msg
        # The registry is gated off: a bare "user jdoe" mention stays raw.
        assert "user jdoe" in msg
        # USER_NOUN is always-on: "user: jdoe" (the `:` separator) tokenises
        # even with the registry off.
        assert token("USER", "jdoe", SALT) in msg
        assert "user: jdoe" not in msg

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

    # -- NESTED structured fields (the real Wazuh shape) ------------------- #

    def test_nested_structured_fields_masked(self, cfg: Any) -> None:
        # Real Wazuh events are NESTED (`user: {name: ...}`, `destination: {ip:
        # ...}`). A structured field at a dotted path must be masked wherever
        # it lives.
        doc = {
            "user": {"name": "jdoe", "effective": {"name": "jsmith"}},
            "destination": {"ip": "10.0.0.5"},
            "host": {"hostname": "web01"},
            "message": "user jdoe logged in from 10.0.0.5",
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        assert out["user"]["name"] == token("USER", "jdoe", SALT)
        assert out["user"]["effective"]["name"] == token("USER", "jsmith", SALT)
        assert out["destination"]["ip"] == token("IP", "10.0.0.5", SALT)
        assert out["host"]["hostname"] == token("HOST", "web01", SALT)
        msg = out["message"]
        assert token("USER", "jdoe", SALT) in msg
        assert token("IP", "10.0.0.5", SALT) in msg
        assert "jdoe" not in msg
        assert "10.0.0.5" not in msg

    def test_nested_free_text_reuses_structured_token(self, cfg: Any) -> None:
        # The per-document registry reads the RAW nested source, so uid=<name>
        # in prose maps to the exact structured token.
        doc = {
            "user": {"name": "marcomoenig"},
            "message": "login failed for uid=marcomoenig from 10.20.30.40",
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        assert out["user"]["name"] == token("USER", "marcomoenig", SALT)
        assert token("USER", "marcomoenig", SALT) in out["message"]
        assert "marcomoenig" not in out["message"]
        assert token("IP", "10.20.30.40", SALT) in out["message"]

    def test_nested_input_source_is_not_mutated(self, cfg: Any) -> None:
        # pipeline_mask_doc deep-copies: the free-text registry must still see
        # the RAW source after structured masking, so the input is untouched.
        doc = {"user": {"name": "jdoe"}, "message": "user jdoe did a thing"}
        pipeline_mask_doc(doc, cfg, SALT)
        assert doc == {"user": {"name": "jdoe"}, "message": "user jdoe did a thing"}

    def test_nested_array_fields_masked_elementwise(self, cfg: Any) -> None:
        doc = {
            "related": {"ip": ["1.2.3.4", "5.6.7.8"], "user": ["alice", "bob"]},
            "message": "users alice and bob from 1.2.3.4",
        }
        out = pipeline_mask_doc(doc, cfg, SALT)
        assert out["related"]["ip"] == [
            token("IP", "1.2.3.4", SALT),
            token("IP", "5.6.7.8", SALT),
        ]
        assert out["related"]["user"] == [
            token("USER", "alice", SALT),
            token("USER", "bob", SALT),
        ]
        assert token("USER", "alice", SALT) in out["message"]
        assert token("IP", "1.2.3.4", SALT) in out["message"]

    def test_flat_and_nested_forms_are_equivalent(self, cfg: Any) -> None:
        # Some Wazuh docs flatten a field into a single dotted key; real events
        # nest it. Both must produce the SAME token.
        flat = {"user.name": "jdoe", "message": "uid=jdoe"}
        nested = {"user": {"name": "jdoe"}, "message": "uid=jdoe"}
        out_flat = pipeline_mask_doc(flat, cfg, SALT)
        out_nested = pipeline_mask_doc(nested, cfg, SALT)
        expected = token("USER", "jdoe", SALT)
        assert out_flat["user.name"] == out_nested["user"]["name"] == expected
        assert out_flat["message"] == out_nested["message"]


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
        self.reindex_created = 0
        # Number of /_reindex posts that raise a transport-level error before
        # the request succeeds (retry path). 0 = never fail at transport level.
        self.reindex_transport_errors = 0
        # When True, GET /_tasks/<id> never reports the reindex task completed.
        self.task_pending = False
        self.masking_error_hits = 0
        # Fail-closed backstop counts, keyed by stream namespace.
        self.quarantine_hits = 0
        self.source_hits = 0
        self.delete_by_query_deleted = 0

    def _resp(self, status: int, payload: Any, path: str) -> Response:
        return Response(
            status, json.dumps(payload), f"https://indexer.example{path}"
        )

    async def get(
        self, path: str, body: Any = None, params: Any = None, timeout: Any = None
    ) -> Response:
        self.calls.append(("get", path, body))
        if path.startswith("/_tasks/"):
            if self.task_pending:
                return self._resp(200, {"completed": False}, path)
            return self._resp(
                200,
                {
                    "completed": True,
                    "task": {
                        "status": {
                            "total": self.reindex_created,
                            "created": self.reindex_created,
                            "failures": self.reindex_failures or [],
                        }
                    },
                },
                path,
            )
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

    async def post(
        self, path: str, body: Any = None, params: Any = None, timeout: Any = None
    ) -> Response:
        self.calls.append(("post", path, body))
        if path.endswith("/_reindex"):
            if self.reindex_transport_errors > 0:
                self.reindex_transport_errors -= 1
                raise TransportError(
                    f"POST https://indexer.example{path} failed at transport "
                    "level: ReadTimeout"
                )
            if not self.reindex_ok:
                return self._resp(500, {"error": {"type": "boom"}}, path)
            if params and params.get("wait_for_completion") == "false":
                # Async submission: returns a task id immediately.
                return self._resp(200, {"task": "node:1"}, path)
            return self._resp(
                200,
                {
                    "took": 1,
                    "created": self.reindex_created,
                    "failures": self.reindex_failures or [],
                },
                path,
            )
        if path.endswith("/_delete_by_query"):
            return self._resp(
                200, {"deleted": self.delete_by_query_deleted}, path
            )
        if path.endswith("/_search"):
            pattern = path.split("/")[1]
            if pattern.startswith("klaxon-quarantine-"):
                hits = self.quarantine_hits
            elif pattern.startswith("wazuh-events"):
                hits = self.source_hits
            else:  # the masked stream
                hits = self.masking_error_hits
            return self._resp(
                200,
                {"hits": {"total": {"value": hits, "relation": "eq"}}},
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
        sync_reindex_timeout=1800.0,
        sync_task_timeout=3600.0,
        schema_field_limit=200,
        schema_probe_batch=100,
        search_max_size=100,
        logtest_default_trace_level="ASSET_ONLY",
        logtest_default_space="custom",
        anonymization=AnonymizationConfig(
            mask_fields=cfg.all_masked_fields,
            # Mirrors the generated config fragment: message (built-in) + extras.
            mask_free_text_fields=effective_free_text_fields(cfg),
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
    cfg: Any, fake: FakeIndexer, *, config: Config | None = None, **kwargs: Any
) -> int:
    opts = {
        "overlap_hours": 1,
        "initial_lookback_hours": 24,
        "dry_run": False,
        **kwargs,
    }
    return asyncio.run(
        sync_masked._sync(fake, cfg, config or _config(cfg), **opts)
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


class TestSyncReindexTransportRetry:
    """Transport-level failures are retried with backoff for the SAME window;
    HTTP errors are reported with status + body, never retried blindly.
    Checkpoint semantics stay fail-closed either way."""

    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Do not sleep for real in tests.
        monkeypatch.setattr(sync_masked, "SYNC_RETRY_BACKOFF_SECONDS", (0.0, 0.0, 0.0))

    def test_transport_error_retried_then_succeeds(
        self, cfg: Any, capsys: Any
    ) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.reindex_transport_errors = 1  # first attempt fails, second succeeds
        assert _run_sync(cfg, fake) == 0
        reindex_bodies = [
            body
            for kind, path, body in fake.calls
            if kind == "post" and path.endswith("/_reindex")
        ]
        assert len(reindex_bodies) == 2
        # The SAME window was retried (identical reindex bodies).
        assert reindex_bodies[0] == reindex_bodies[1]
        assert len(_checkpoint_puts(fake)) == 1
        assert "retrying" in capsys.readouterr().err

    def test_transport_error_exhausted_after_n_attempts(
        self, cfg: Any, capsys: Any
    ) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.reindex_transport_errors = 99  # never succeeds at transport level
        assert _run_sync(cfg, fake) == 1
        reindex_posts = [
            body
            for kind, path, body in fake.calls
            if kind == "post" and path.endswith("/_reindex")
        ]
        assert len(reindex_posts) == sync_masked.SYNC_REINDEX_ATTEMPTS
        assert _checkpoint_puts(fake) == []
        err = capsys.readouterr().err
        assert "failed at transport level after 3 attempts" in err
        assert "checkpoint was NOT advanced" in err

    def test_http_error_reported_not_retried(
        self, cfg: Any, capsys: Any
    ) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.reindex_ok = False  # HTTP 500 — an HTTP error, not a transport one
        assert _run_sync(cfg, fake) == 1
        reindex_posts = [
            body
            for kind, path, body in fake.calls
            if kind == "post" and path.endswith("/_reindex")
        ]
        assert len(reindex_posts) == 1  # HTTP errors are NOT retried
        assert _checkpoint_puts(fake) == []
        err = capsys.readouterr().err
        assert "HTTP 500" in err
        assert "checkpoint NOT advanced" in err


class TestSyncReindexTaskPoll:
    """Async-task path: the reindex is submitted with wait_for_completion=false
    and polled via GET /_tasks/<id>. Task completes -> checkpoint advances;
    task fails or times out -> checkpoint NOT advanced."""

    @pytest.fixture(autouse=True)
    def _no_poll_sleep(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sync_masked, "SYNC_TASK_POLL_SECONDS", 0.0)

    def test_task_completes_checkpoint_advanced(self, cfg: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.reindex_created = 7
        assert _run_sync(cfg, fake) == 0
        assert len(_checkpoint_puts(fake)) == 1
        # Submitted as an async task, then polled.
        assert any(
            kind == "post" and path.endswith("/_reindex")
            for kind, path, _ in fake.calls
        )
        assert any(
            kind == "get" and path.startswith("/_tasks/")
            for kind, path, _ in fake.calls
        )

    def test_task_failure_checkpoint_not_advanced(
        self, cfg: Any, capsys: Any
    ) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.reindex_failures = [{"index": "x", "reason": "boom"}]
        assert _run_sync(cfg, fake) == 1
        assert _checkpoint_puts(fake) == []
        assert "failure(s)" in capsys.readouterr().err

    def test_task_poll_timeout_checkpoint_not_advanced(
        self, cfg: Any, capsys: Any
    ) -> None:
        from dataclasses import replace

        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.task_pending = True  # the task never completes
        config = replace(_config(cfg), sync_task_timeout=0.01)
        assert _run_sync(cfg, fake, config=config) == 1
        assert _checkpoint_puts(fake) == []
        err = capsys.readouterr().err
        assert "did not complete within" in err
        assert "checkpoint NOT advanced" in err


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


class TestSyncQuarantineBackstop:
    """Fail-closed: ANY quarantine doc in the window fails the run; the
    checkpoint is NOT advanced and an alert is raised."""

    def test_fails_and_does_not_advance_on_quarantine(self, cfg: Any, capsys: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.quarantine_hits = 2
        assert _run_sync(cfg, fake) == 1
        assert _checkpoint_puts(fake) == []
        err = capsys.readouterr().err
        assert "FAIL-CLOSED BACKSTOP" in err
        assert "2 masking-failure document(s)" in err
        assert "checkpoint NOT advanced" in err

    def test_advances_when_quarantine_empty(self, cfg: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.quarantine_hits = 0
        assert _run_sync(cfg, fake) == 0
        assert len(_checkpoint_puts(fake)) == 1


class TestSyncReconcile:
    """Optional reconcile: source(window) == masked(window) + quarantine(window).

    NOTE: quarantine_hits must be 0 here — any quarantine doc fails the run in
    the FAIL-CLOSED backstop BEFORE reconcile runs (that is correct: masking
    failures are fatal). Reconcile catches silent DROPS (docs that neither made
    it into the masked stream nor were quarantined).
    """

    def test_reconcile_ok(self, cfg: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.source_hits = 5
        fake.masking_error_hits = 5
        fake.quarantine_hits = 0
        monkeypatch.setenv("KLAXON_SYNC_RECONCILE", "true")
        assert _run_sync(cfg, fake) == 0
        assert len(_checkpoint_puts(fake)) == 1

    def test_reconcile_mismatch_warns_by_default(
        self, cfg: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.source_hits = 10
        fake.masking_error_hits = 4
        fake.quarantine_hits = 0
        monkeypatch.setenv("KLAXON_SYNC_RECONCILE", "true")
        assert _run_sync(cfg, fake) == 0  # warn, not fail
        assert "RECONCILE MISMATCH" in capsys.readouterr().err
        assert len(_checkpoint_puts(fake)) == 1

    def test_reconcile_mismatch_fails_when_configured(
        self, cfg: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline_template(cfg)
        fake.source_hits = 10
        fake.masking_error_hits = 4
        fake.quarantine_hits = 0
        monkeypatch.setenv("KLAXON_SYNC_RECONCILE", "true")
        monkeypatch.setenv("KLAXON_SYNC_RECONCILE_FAIL", "true")
        assert _run_sync(cfg, fake) == 1
        assert "checkpoint NOT advanced" in capsys.readouterr().err
        assert _checkpoint_puts(fake) == []


class TestSyncQuarantinePreflight:
    """The preflight aborts when the deployed pipeline lacks the fail-closed
    quarantine on_failure (a pre-quarantine pipeline would leak raw docs into
    the masked stream)."""

    def test_aborts_when_pipeline_lacks_quarantine_on_failure(
        self, cfg: Any, capsys: Any
    ) -> None:
        fake = FakeIndexer()
        stale = build_pipeline_template(cfg)
        # Revert to the old fail-open on_failure (masking_error set, no reroute).
        stale["processors"][0]["script"]["on_failure"] = [
            {"set": {"field": "klaxon.masking_error", "value": "boom"}}
        ]
        fake.deployed_pipeline = stale
        assert _run_sync(cfg, fake) == 1
        assert _reindex_call(fake) is None
        assert "lacks the quarantine on_failure" in capsys.readouterr().err

    def test_pipeline_has_quarantine_on_failure_true_for_generated(
        self, cfg: Any
    ) -> None:
        from klaxon_mcp.masked_stream import pipeline_has_quarantine_on_failure

        assert pipeline_has_quarantine_on_failure(build_pipeline_template(cfg))


class TestMigrateQuarantine:
    """One-time, operator-run migration of legacy masking_error docs."""

    def _run(self, cfg: Any, fake: FakeIndexer, **kwargs: Any) -> int:
        opts = {"dry_run": False, **kwargs}
        return asyncio.run(sync_masked._migrate_quarantine(fake, cfg, **opts))

    def test_migrate_copies_then_deletes(
        self, cfg: Any, capsys: Any
    ) -> None:
        fake = FakeIndexer()
        fake.masking_error_hits = 3
        fake.reindex_created = 3
        fake.delete_by_query_deleted = 3
        assert self._run(cfg, fake) == 0
        out = capsys.readouterr().out
        assert "migrated 3" in out
        assert "deleted 3" in out
        # Reindex dest is the quarantine routing index, op_type create, and the
        # source is filtered to masking_error docs.
        body = _reindex_call(fake)
        assert body is not None
        assert body["dest"]["index"] == cfg.quarantine_routing_index
        assert body["dest"]["op_type"] == "create"
        assert body["dest"].get("pipeline") is None  # never re-enters masking
        assert body["source"]["query"] == {"exists": {"field": "klaxon.masking_error"}}

    def test_migrate_noop_when_nothing_flagged(self, cfg: Any, capsys: Any) -> None:
        fake = FakeIndexer()
        fake.masking_error_hits = 0
        assert self._run(cfg, fake) == 0
        assert _reindex_call(fake) is None
        assert "nothing to migrate" in capsys.readouterr().out

    def test_migrate_dry_run_sends_nothing(self, cfg: Any, capsys: Any) -> None:
        fake = FakeIndexer()
        fake.masking_error_hits = 3
        assert self._run(cfg, fake, dry_run=True) == 0
        assert _reindex_call(fake) is None
        assert "dry run" in capsys.readouterr().out

    def test_migrate_refuses_to_delete_on_reindex_failure(
        self, cfg: Any, capsys: Any
    ) -> None:
        fake = FakeIndexer()
        fake.masking_error_hits = 3
        fake.reindex_failures = [{"index": "x", "reason": "boom"}]
        assert self._run(cfg, fake) == 1
        assert "NOTHING was deleted" in capsys.readouterr().err
        # No delete-by-query was sent.
        assert not any(
            kind == "post" and p.endswith("/_delete_by_query")
            for kind, p, _ in fake.calls
        )

    def test_migrate_flags_count_mismatch(self, cfg: Any, capsys: Any) -> None:
        fake = FakeIndexer()
        fake.masking_error_hits = 3
        fake.reindex_created = 2
        fake.delete_by_query_deleted = 3
        assert self._run(cfg, fake) == 1
        assert "migrated (2) != deleted (3)" in capsys.readouterr().err


class TestSaltCheck:
    """`salt_check_command`: compare the salt baked into the DEPLOYED pipeline
    (params.salt) with the current env salt."""

    @staticmethod
    def _patch_indexer(monkeypatch: pytest.MonkeyPatch, fake: FakeIndexer) -> None:
        from klaxon_mcp import server

        monkeypatch.setattr(server, "get_indexer", lambda: fake)

    def test_ok_when_env_matches_deployed(self, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline(load_tenant_config("customer-a"), "deployed-salt")
        self._patch_indexer(monkeypatch, fake)
        monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "deployed-salt")
        assert sync_masked.salt_check_command("customer-a") == 0
        assert "matches" in capsys.readouterr().out

    def test_error_on_salt_mismatch(self, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline(load_tenant_config("customer-a"), "deployed-salt")
        self._patch_indexer(monkeypatch, fake)
        monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "current-salt")
        assert sync_masked.salt_check_command("customer-a") == 1
        assert "SALT MISMATCH" in capsys.readouterr().out

    def test_error_when_env_unset(self, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
        fake = FakeIndexer()
        fake.deployed_pipeline = build_pipeline(load_tenant_config("customer-a"), "deployed-salt")
        self._patch_indexer(monkeypatch, fake)
        monkeypatch.delenv("KLAXON_ANONYMIZATION_SALT", raising=False)
        assert sync_masked.salt_check_command("customer-a") == 2
        assert "is not set" in capsys.readouterr().err

    def test_error_when_pipeline_not_deployed(self, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
        fake = FakeIndexer()  # deployed_pipeline stays None
        self._patch_indexer(monkeypatch, fake)
        monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", "deployed-salt")
        assert sync_masked.salt_check_command("customer-a") == 1
        assert "not deployed" in capsys.readouterr().err
