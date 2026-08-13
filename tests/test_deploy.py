# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""`klaxon masking deploy` — preflight aborts, ordered idempotent deploy,
YAML->JSON roles, already-exists handling, rollback and the no-secret contract.

The deploy command is a separate operator/CI CLI path (the running server stays
write-incapable). These tests drive `deploy_main` (with `httpx.AsyncClient`
stubbed to a fake indexer) and the lower-level `_deploy_core`/`_smoke_test`
against the fake, asserting the output never contains the password, the salt,
token values or raw data.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from klaxon_mcp import deploy
from klaxon_mcp.masked_stream import load_tenant_config
from klaxon_mcp.tokens import token

TEST_SALT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
USERNAME = "marcomoenig"


class FakeResp:
    def __init__(self, status: int, payload: Any) -> None:
        self.status_code = status
        self._payload = payload

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def text(self) -> str:
        return json.dumps(self._payload) if not isinstance(self._payload, str) else self._payload

    def json(self) -> Any:
        if isinstance(self._payload, str):
            return json.loads(self._payload)
        return self._payload


class FakeIndexer:
    """A stub OpenSearch indexer that echoes PUTs and answers the deploy queries."""

    def __init__(
        self,
        *,
        salt: str = TEST_SALT,
        data_stream_present: bool = False,
        deployed_pipeline: dict[str, Any] | None = None,
        sync_updated: str | None = None,
        reachable: bool = True,
    ) -> None:
        self.salt = salt
        self.data_stream_present = data_stream_present
        self.deployed_pipeline = deployed_pipeline
        self.sync_updated = sync_updated
        self.reachable = reachable
        self.store: dict[str, Any] = {}  # path -> echoed body
        self.puts: list[tuple[str, str, Any]] = []  # (method, path, body)

    # -- helpers the deploy code calls ------------------------------------ #
    async def get(self, path: str) -> FakeResp:
        if not self.reachable:
            raise RuntimeError(f"GET {path} failed at transport level: boom")
        if path == "/wazuh-events-v5-*/_mapping":
            return FakeResp(200, {"idx": {"mappings": {"properties": {}}}})
        if path.startswith("/_data_stream/") and not path.endswith("_simulate"):
            if self.data_stream_present or any(
                p.startswith(path) and "data_stream" in p for p in self.store
            ):
                return FakeResp(200, {"data_streams": [{"name": "klaxon-masked-customer-a-v5"}]})
            return FakeResp(200, {"data_streams": []})
        if path.startswith("/_ingest/pipeline/"):
            name = path.rsplit("/", 1)[1]
            if name in self.store:
                return FakeResp(200, {name: self.store[name]})
            if self.deployed_pipeline is not None and name == self.deployed_pipeline.get("_name"):
                return FakeResp(200, {name: self.deployed_pipeline})
            return FakeResp(404, {"error": {"reason": "pipeline_missing_exception"}})
        if path.startswith("/_plugins/_ism/policies/"):
            name = path.rsplit("/", 1)[1]
            if name in self.store:
                stored = self.store[name]
                if isinstance(stored, dict) and "policy" in stored:
                    return FakeResp(200, {"policy": stored["policy"]})
                return FakeResp(200, {"policy": stored})
            return FakeResp(404, {"error": {"reason": "no such policy"}})
        if path.startswith("/_index_template/"):
            name = path.rsplit("/", 1)[1]
            if name in self.store:
                return FakeResp(
                    200,
                    {"index_templates": [{"name": name, "index_template": self.store[name]}]},
                )
            return FakeResp(404, {"error": {"reason": "index_template_missing_exception"}})
        if path.startswith("/_plugins/_security/api/roles"):
            name = path.rsplit("/", 1)[1] if "/" in path.replace("/_plugins/_security/api/roles", "", 1) else None
            if name and name in self.store:
                return FakeResp(200, {name: self.store[name]})
            if name:
                return FakeResp(404, {"error": {"reason": "no such role"}})
            return FakeResp(200, {"roles": {k: v for k, v in self.store.items() if k.startswith("klaxon_")}})
        if path.startswith("/klaxon-sync-state/_doc/"):
            if self.sync_updated:
                return FakeResp(200, {"_source": {"updated": self.sync_updated}})
            return FakeResp(404, {})
        return FakeResp(404, {"error": {"reason": f"unexpected GET {path}"}})

    async def put(self, path: str, content: str | None = None) -> FakeResp:
        if not self.reachable:
            raise RuntimeError(f"PUT {path} failed at transport level: boom")
        self.puts.append(("PUT", path, content))
        body = json.loads(content or "{}")
        if path.startswith("/_data_stream/"):
            # Creating a data stream: mark it present (auto-created by template).
            self.data_stream_present = True
            return FakeResp(200, {"acknowledged": True})
        self.store[path.rsplit("/", 1)[1]] = body
        return FakeResp(200, {"acknowledged": True})

    async def post(self, path: str, content: str | None = None) -> FakeResp:
        if not self.reachable:
            raise RuntimeError(f"POST {path} failed at transport level: boom")
        if path.endswith("/_simulate"):
            t = token("USER", USERNAME, self.salt)
            return FakeResp(
                200,
                {
                    "docs": [
                        {
                            "doc": {
                                "_source": {
                                    "user": {"name": t},
                                    "message": f"uid={t}",
                                }
                            }
                        }
                    ]
                },
            )
        return FakeResp(404, {"error": {"reason": f"unexpected POST {path}"}})


class FakeHTTP:
    """An async context manager standing in for httpx.AsyncClient."""

    def __init__(self, fake: FakeIndexer) -> None:
        self.fake = fake

    async def __aenter__(self) -> FakeIndexer:
        return self.fake

    async def __aexit__(self, *args: object) -> bool:
        return False


@pytest.fixture
def run_deploy(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> Iterator[Any]:
    """Patch httpx.AsyncClient to the fake and redirect snapshots to tmp_path."""
    fake = FakeIndexer()

    def install(**kw: Any) -> FakeIndexer:
        nonlocal fake
        fake = FakeIndexer(**kw)
        snap = tmp_path / "snap"

        def new_snapshot(cfg: Any) -> Any:
            snap.mkdir(parents=True, exist_ok=True)
            return snap

        monkeypatch.setattr(deploy.httpx, "AsyncClient", lambda **_: FakeHTTP(fake))
        monkeypatch.setattr(deploy, "_new_snapshot_dir", new_snapshot)
        monkeypatch.setattr(
            deploy, "_latest_snapshot_dir", lambda cfg: snap if snap.is_dir() else None
        )
        return fake

    install()
    yield install
    monkeypatch.undo()


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("KLAXON_INDEXER_URL", "https://indexer.example:9200")
    monkeypatch.setenv("KLAXON_INDEXER_USER", "admin")
    monkeypatch.setenv("KLAXON_INDEXER_PASSWORD", "admin-password")
    monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", TEST_SALT)
    yield


class TestPreflight:
    def test_missing_credentials_abort(self, env: None, run_deploy: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("KLAXON_INDEXER_URL")
        # --env points at a nonexistent file so the repo's tests/live/.env cannot
        # re-supply the credentials.
        rc = deploy.deploy_main(
            ["--tenant", "customer-a", "--dry-run", "--env", "/nonexistent/deploy.env"]
        )
        assert rc == 1

    def test_unset_salt_aborts(self, env: None, run_deploy: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("KLAXON_ANONYMIZATION_SALT")
        rc = deploy.deploy_main(
            ["--tenant", "customer-a", "--dry-run", "--env", "/nonexistent/deploy.env"]
        )
        assert rc == 1

    def test_drift_aborts_naming_the_file(self, env: None, run_deploy: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            deploy,
            "check_artifacts",
            lambda cfg, **kw: ["pipeline-klaxon-mask-customer-a.json: DRIFT — ..."],
        )
        rc = deploy.deploy_main(["--tenant", "customer-a", "--dry-run"])
        assert rc == 1

    def test_salt_mismatch_aborts(self, env: None, run_deploy: Any) -> None:
        deployed = {
            "_name": "klaxon-mask-customer-a",
            "processors": [
                {"script": {"source": "x();", "params": {"salt": "a-different-salt"}}}
            ],
        }
        run_deploy(deployed_pipeline=deployed)
        rc = deploy.deploy_main(["--tenant", "customer-a", "--dry-run"])
        assert rc == 1

    def test_running_sync_aborts_unless_force(self, env: None, run_deploy: Any) -> None:
        from datetime import UTC, datetime, timedelta

        recent = (datetime.now(UTC) - timedelta(seconds=60)).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00"
        )
        run_deploy(sync_updated=recent)
        rc = deploy.deploy_main(["--tenant", "customer-a", "--dry-run"])
        assert rc == 1
        # --force proceeds (dry run, no writes).
        rc = deploy.deploy_main(["--tenant", "customer-a", "--dry-run", "--force"])
        assert rc == 0

    def test_unreachable_indexer_aborts_cleanly(self, env: None, run_deploy: Any, monkeypatch: pytest.MonkeyPatch) -> None:
        class BoomHTTP:
            async def __aenter__(self) -> Any:
                raise httpx.TransportError("boom")

            async def __aexit__(self, *args: object) -> bool:
                return False

        monkeypatch.setattr(deploy.httpx, "AsyncClient", lambda **_: BoomHTTP())
        rc = deploy.deploy_main(["--tenant", "customer-a", "--dry-run", "--force"])
        assert rc == 1

    def test_verify_ssl_false_warns(self, env: None, run_deploy: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any) -> None:
        # Parity with `klaxon masking test`: disabling TLS verification on a
        # write command must print a loud warning.
        monkeypatch.setenv("KLAXON_INDEXER_VERIFY_SSL", "false")
        run_deploy()
        rc = deploy.deploy_main(["--tenant", "customer-a", "--dry-run", "--force"])
        assert rc == 0
        assert "TLS verification is DISABLED" in capsys.readouterr().err


class TestDeploy:
    def test_dry_run_writes_nothing(self, env: None, run_deploy: Any) -> None:
        fake = run_deploy()
        rc = deploy.deploy_main(["--tenant", "customer-a", "--dry-run", "--force"])
        assert rc == 0
        assert fake.puts == []  # no indexer mutation

    def test_deploy_order_and_idempotency(self, env: None, run_deploy: Any) -> None:
        fake = run_deploy()
        rc = deploy.deploy_main(["--tenant", "customer-a", "--force"])
        assert rc == 0
        put_paths = [p for _, p, _ in fake.puts]
        # Fixed order: pipeline, ISM x2, templates x2, data stream, roles x3.
        assert put_paths[0] == "/_ingest/pipeline/klaxon-mask-customer-a"
        assert put_paths[1:3] == [
            "/_plugins/_ism/policies/klaxon-masked-retention-customer-a",
            "/_plugins/_ism/policies/klaxon-quarantine-retention-customer-a",
        ]
        assert put_paths[3:5] == [
            "/_index_template/klaxon-masked-customer-a",
            "/_index_template/klaxon-quarantine-customer-a",
        ]
        assert put_paths[5] == "/_data_stream/klaxon-masked-customer-a-v5"
        assert sorted(put_paths[6:]) == sorted(
            [
                "/_plugins/_security/api/roles/klaxon_llm_report_customer-a",
                "/_plugins/_security/api/roles/klaxon_ops_customer-a",
                "/_plugins/_security/api/roles/klaxon_sync_customer-a",
            ]
        )

        # Second run: a no-op that still verifies; data stream now skipped.
        rc2 = deploy.deploy_main(["--tenant", "customer-a", "--force"])
        assert rc2 == 0
        assert fake.puts.count(("PUT", "/_data_stream/klaxon-masked-customer-a-v5", "{}")) == 1

    def test_roles_yaml_to_json_in_code(self, env: None, run_deploy: Any) -> None:
        # The roles fragment is YAML; the deploy must PUT JSON role bodies.
        cfg = load_tenant_config("customer-a")
        roles, mappings = deploy._parse_roles_fragment(cfg)
        assert set(roles) == {
            "klaxon_llm_report_customer-a",
            "klaxon_ops_customer-a",
            "klaxon_sync_customer-a",
        }
        assert mappings == {}
        # Each role spec is a dict (JSON-serialisable) with index_permissions.
        for spec in roles.values():
            assert isinstance(spec, dict)
            assert "index_permissions" in spec

    async def test_smoke_test_ok(self) -> None:
        fake = FakeIndexer()
        lines: list[str] = []
        ok = await deploy._smoke_test(fake, load_tenant_config("customer-a"), TEST_SALT, lines)
        assert ok
        assert lines and "no masking_error" in lines[0]

    async def test_core_deploys_all_roles_and_stream(self) -> None:
        fake = FakeIndexer()
        lines: list[str] = []
        ok = await deploy._deploy_core(
            fake, load_tenant_config("customer-a"), TEST_SALT, retention_days=30, lines=lines
        )
        assert ok
        role_puts = [p for p in fake.puts if "api/roles/" in p[1]]
        assert len(role_puts) == 3


class TestAlreadyExists:
    def test_data_stream_already_exists_is_skip(self, env: None, run_deploy: Any) -> None:
        run_deploy(data_stream_present=True)
        rc = deploy.deploy_main(["--tenant", "customer-a", "--force"])
        assert rc == 0


class TestRollback:
    def test_rollback_restores_snapshot(self, env: None, run_deploy: Any, tmp_path: Any) -> None:
        # Prepare a snapshot dir as if a previous deploy created it.
        snap = tmp_path / "snap"
        snap.mkdir(parents=True, exist_ok=True)
        pipeline = {
            "processors": [{"script": {"source": "old();", "params": {"salt": TEST_SALT}}}]
        }
        (snap / "01-pipeline.json").write_text(json.dumps(pipeline), encoding="utf-8")
        fake = run_deploy()
        rc = deploy.deploy_main(["--tenant", "customer-a", "--rollback"])
        assert rc == 0
        # The snapshot pipeline was PUT back.
        assert any(
            p == "/_ingest/pipeline/klaxon-mask-customer-a" and "old()" in (c or "")
            for _, p, c in fake.puts
        )

    def test_rollback_without_snapshot_fails(self, env: None, run_deploy: Any) -> None:
        run_deploy()
        rc = deploy.deploy_main(["--tenant", "customer-a", "--rollback"])
        assert rc == 1


class TestNoSecretOutput:
    def test_output_never_contains_secrets(self, env: None, run_deploy: Any, capsys: Any) -> None:
        run_deploy()
        rc = deploy.deploy_main(["--tenant", "customer-a", "--force"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "admin-password" not in out
        assert TEST_SALT not in out
        assert "[USER_" not in out  # no token values
        assert "marcomoenig" not in out  # no raw data / usernames

    def test_dry_run_output_has_no_secrets(self, env: None, run_deploy: Any, capsys: Any) -> None:
        run_deploy()
        rc = deploy.deploy_main(["--tenant", "customer-a", "--dry-run", "--force"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "admin-password" not in out
        assert TEST_SALT not in out
