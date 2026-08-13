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
from klaxon_mcp.masked_stream import build_ism_policy, load_tenant_config
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
    """A stub OpenSearch indexer that echoes PUTs and answers the deploy queries.

    ISM policies are simulated as versioned documents like the real plugin:
    GET returns `_seq_no`/`_primary_term` plus the server-managed policy keys,
    and a versioned PUT fails with 409 when its `if_seq_no`/`if_primary_term`
    no longer match. `ism_conflict_before_put=N` makes the NEXT N versioned
    PUTs observe a stale version (a concurrent write landing between GET and
    PUT) and answer 409.
    """

    def __init__(
        self,
        *,
        salt: str = TEST_SALT,
        data_stream_present: bool = False,
        deployed_pipeline: dict[str, Any] | None = None,
        sync_updated: str | None = None,
        reachable: bool = True,
        ism_conflict_before_put: int = 0,
    ) -> None:
        self.salt = salt
        self.data_stream_present = data_stream_present
        self.deployed_pipeline = deployed_pipeline
        self.sync_updated = sync_updated
        self.reachable = reachable
        self.ism_conflict_before_put = ism_conflict_before_put
        self.store: dict[str, Any] = {}  # path -> echoed body
        self.puts: list[tuple[str, str, Any, Any]] = []  # (method, path, body, params)
        self.ism_meta: dict[str, dict[str, int]] = {}  # policy name -> version state
        self._seq_counter = 0

    def _next_seq(self) -> int:
        self._seq_counter += 1
        return self._seq_counter

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
                meta = self.ism_meta.get(name, {})
                stored = self.store[name]
                policy = (
                    stored["policy"]
                    if isinstance(stored, dict) and "policy" in stored
                    else stored
                )
                # Real ISM GET re-serves the policy with server-managed fields
                # and the version metadata the deploy's versioned PUT needs.
                served = dict(policy)
                served.setdefault("policy_id", name)
                served.setdefault("last_updated_time", 1_577_990_933_044)
                served.setdefault("schema_version", 1)
                served.setdefault("error_notification", None)
                return FakeResp(
                    200,
                    {
                        "_id": name,
                        "_version": meta.get("version", 1),
                        "_seq_no": meta.get("seq_no", 1),
                        "_primary_term": meta.get("primary_term", 1),
                        "policy": served,
                    },
                )
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

    async def put(
        self,
        path: str,
        content: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> FakeResp:
        if not self.reachable:
            raise RuntimeError(f"PUT {path} failed at transport level: boom")
        self.puts.append(("PUT", path, content, params))
        body = json.loads(content or "{}")
        if path.startswith("/_data_stream/"):
            # Creating a data stream: mark it present (auto-created by template).
            self.data_stream_present = True
            return FakeResp(200, {"acknowledged": True})
        if path.startswith("/_plugins/_ism/policies/"):
            return self._ism_put(path.rsplit("/", 1)[1], body, params)
        self.store[path.rsplit("/", 1)[1]] = body
        return FakeResp(200, {"acknowledged": True})

    def _ism_put(
        self,
        name: str,
        body: dict[str, Any],
        params: dict[str, Any] | None,
    ) -> FakeResp:
        """Simulate the ISM plugin's optimistic-concurrency write."""
        meta = self.ism_meta.get(name)
        if meta is None:
            # Create: plain PUT on a missing policy always succeeds.
            meta = {"version": 1, "seq_no": self._next_seq(), "primary_term": 1}
            self.ism_meta[name] = meta
            self.store[name] = body
            return FakeResp(200, {"acknowledged": True})
        if self.ism_conflict_before_put > 0:
            # A concurrent write lands between the deploy's GET and PUT: bump
            # the version so the if_seq_no the deploy read becomes stale -> 409.
            self.ism_conflict_before_put -= 1
            meta["seq_no"] = self._next_seq()
        if params and (
            params.get("if_seq_no") != meta["seq_no"]
            or params.get("if_primary_term") != meta["primary_term"]
        ):
            return FakeResp(
                409,
                {
                    "error": {
                        "reason": (
                            "version conflict, document already exists "
                            f"(current version [{meta['version']}])"
                        )
                    }
                },
            )
        meta["version"] += 1
        meta["seq_no"] = self._next_seq()
        self.store[name] = body
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
        put_paths = [p for _, p, _, _ in fake.puts]
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
        assert fake.puts.count(("PUT", "/_data_stream/klaxon-masked-customer-a-v5", "{}", None)) == 1

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
            for _, p, c, _ in fake.puts
        )

    def test_rollback_without_snapshot_fails(self, env: None, run_deploy: Any) -> None:
        run_deploy()
        rc = deploy.deploy_main(["--tenant", "customer-a", "--rollback"])
        assert rc == 1


class TestIsmOptimisticConcurrency:
    """ISM policies are versioned documents: the deploy must GET-first, skip
    when identical, update with if_seq_no/if_primary_term when different,
    create with a plain PUT when missing, and retry-once a 409.
    """

    ISM_PATH = "/_plugins/_ism/policies/klaxon-masked-retention-customer-a"
    LABEL = "ISM klaxon-masked-retention-customer-a"

    @staticmethod
    def _policy(retention_days: int = 30) -> dict[str, Any]:
        return build_ism_policy(load_tenant_config("customer-a"), retention_days)

    def _ism_puts(self, fake: FakeIndexer) -> list[tuple[str, Any]]:
        return [
            (p, prm)
            for m, p, c, prm in fake.puts
            if p.startswith("/_plugins/_ism/policies/")
        ]

    async def test_missing_ism_created_with_plain_put(self) -> None:
        fake = FakeIndexer()
        lines: list[str] = []
        ok = await deploy._put_ism_policy(
            fake, self.LABEL, self.ISM_PATH, self._policy(), lines=lines
        )
        assert ok
        ism_puts = self._ism_puts(fake)
        assert len(ism_puts) == 1  # one plain PUT
        assert ism_puts[0][1] is None  # no version params on a create
        assert lines[0].startswith("[ok] ISM")

    async def test_existing_identical_ism_skips(self) -> None:
        fake = FakeIndexer()
        policy = self._policy()
        await fake.put(self.ISM_PATH, content=json.dumps(policy))
        lines: list[str] = []
        ok = await deploy._put_ism_policy(
            fake, self.LABEL, self.ISM_PATH, policy, lines=lines
        )
        assert ok
        # The pre-create PUT is the only ISM write — the re-deploy skipped.
        assert len(self._ism_puts(fake)) == 1
        assert lines == [f"[skip] {self.LABEL} unchanged"]

    async def test_existing_different_ism_uses_versioned_put(self) -> None:
        fake = FakeIndexer()
        # Pre-create with a DIFFERENT retention so the artifact differs.
        await fake.put(
            self.ISM_PATH, content=json.dumps(self._policy(retention_days=7))
        )
        lines: list[str] = []
        ok = await deploy._put_ism_policy(
            fake, self.LABEL, self.ISM_PATH, self._policy(), lines=lines
        )
        assert ok
        ism_puts = self._ism_puts(fake)
        assert len(ism_puts) == 2  # pre-create + versioned update
        assert ism_puts[1][1] == {"if_seq_no": 1, "if_primary_term": 1}
        assert lines[0].startswith("[ok] ISM")

    async def test_409_once_retries_and_succeeds(self) -> None:
        fake = FakeIndexer(ism_conflict_before_put=1)
        await fake.put(
            self.ISM_PATH, content=json.dumps(self._policy(retention_days=7))
        )
        lines: list[str] = []
        ok = await deploy._put_ism_policy(
            fake, self.LABEL, self.ISM_PATH, self._policy(), lines=lines
        )
        assert ok
        ism_puts = self._ism_puts(fake)
        assert len(ism_puts) == 3  # pre-create + stale PUT (409) + retried PUT
        assert ism_puts[1][1] == {"if_seq_no": 1, "if_primary_term": 1}  # stale
        assert ism_puts[2][1] == {"if_seq_no": 2, "if_primary_term": 1}  # fresh
        assert any(l.startswith("[retry]") for l in lines)
        assert lines[-1].startswith("[ok] ISM")

    async def test_409_twice_fails_with_clear_message(self) -> None:
        fake = FakeIndexer(ism_conflict_before_put=2)
        await fake.put(
            self.ISM_PATH, content=json.dumps(self._policy(retention_days=7))
        )
        lines: list[str] = []
        ok = await deploy._put_ism_policy(
            fake, self.LABEL, self.ISM_PATH, self._policy(), lines=lines
        )
        assert not ok
        # pre-create + attempt 1 (stale, 409) + attempt 2 (stale, 409) -> fail.
        assert len(self._ism_puts(fake)) == 3
        assert sum(1 for l in lines if l.startswith("[retry]")) == 1
        assert lines[-1].startswith("[fail]")
        assert "HTTP 409" in lines[-1]
        assert "re-run the deploy" in lines[-1]

    async def test_get_ism_policy_exposes_seq_and_primary_term(self) -> None:
        # The real ISM GET returns _seq_no/_primary_term at the TOP level of the
        # response, next to the wrapped policy — the versioned PUT reads them
        # from the SAME GET. Assert the helper parses that shape.
        fake = FakeIndexer()
        await fake.put(self.ISM_PATH, content=json.dumps(self._policy()))
        body, seq_no, primary_term = await deploy._get_ism_policy(
            fake, self.ISM_PATH
        )
        assert isinstance(body, dict)
        assert body.get("description")  # the unwrapped policy body
        assert (seq_no, primary_term) == (1, 1)

    async def test_get_ism_policy_missing_returns_none(self) -> None:
        fake = FakeIndexer()
        body, seq_no, primary_term = await deploy._get_ism_policy(
            fake, self.ISM_PATH
        )
        assert (body, seq_no, primary_term) == (None, None, None)

    def test_end_to_end_rerun_is_a_noop_for_pipeline_and_ism(
        self, env: None, run_deploy: Any, capsys: Any
    ) -> None:
        fake = run_deploy()
        assert deploy.deploy_main(["--tenant", "customer-a", "--force"]) == 0
        capsys.readouterr()  # clear run 1 output
        ism_puts_after_first = len(self._ism_puts(fake))
        assert deploy.deploy_main(["--tenant", "customer-a", "--force"]) == 0
        out = capsys.readouterr().out
        # Run 2 writes no ISM policy (identical -> skip) and skips the pipeline.
        assert len(self._ism_puts(fake)) == ism_puts_after_first
        assert "[skip] pipeline klaxon-mask-customer-a unchanged" in out
        assert "[skip] ISM klaxon-masked-retention-customer-a unchanged" in out
        assert "[skip] ISM klaxon-quarantine-retention-customer-a unchanged" in out


class TestRollbackIsmOptimisticConcurrency:
    """Regression: `--rollback` must re-deploy ISM policies through the SAME
    shared helper as deploy (_put_ism_policy). It used a plain PUT on an
    existing ISM policy and died with HTTP 409 "version conflict, document
    already exists"; it must GET-first-compare/skip, issue a versioned PUT
    (if_seq_no/if_primary_term), and retry-once a 409 — exactly like deploy.
    """

    ISM_PATH = "/_plugins/_ism/policies/klaxon-masked-retention-customer-a"

    @staticmethod
    def _policy(retention_days: int = 30) -> dict[str, Any]:
        return build_ism_policy(load_tenant_config("customer-a"), retention_days)

    def _ism_puts(self, fake: FakeIndexer) -> list[tuple[str, Any]]:
        return [
            (p, prm)
            for m, p, c, prm in fake.puts
            if p.startswith("/_plugins/_ism/policies/")
        ]

    @staticmethod
    def _snapshot(tmp_path: Any, **files: dict[str, Any]) -> Any:
        """A snapshot dir holding the given `NN-<resource>.json` files."""
        snap = tmp_path / "snap"
        snap.mkdir(parents=True, exist_ok=True)
        for name, body in files.items():
            (snap / name).write_text(json.dumps(body), encoding="utf-8")
        return snap

    async def test_rollback_missing_ism_uses_plain_put(self, tmp_path: Any) -> None:
        # No live policy -> 404 -> plain PUT (create), just like deploy.
        fake = FakeIndexer()
        snap = self._snapshot(
            tmp_path, **{"02-ism-masked.json": self._policy(retention_days=7)["policy"]}
        )
        lines: list[str] = []
        ok = await deploy._rollback(fake, load_tenant_config("customer-a"), snap, lines)
        assert ok
        ism_puts = self._ism_puts(fake)
        assert len(ism_puts) == 1  # one plain PUT
        assert ism_puts[0][1] is None  # no version params on a create
        assert lines[0].startswith("[ok] rollback ism-masked")

    async def test_rollback_existing_identical_ism_skips(self, tmp_path: Any) -> None:
        # Live policy already matches the snapshot -> no write at all.
        fake = FakeIndexer()
        await fake.put(
            self.ISM_PATH, content=json.dumps(self._policy(retention_days=7))
        )
        snap = self._snapshot(
            tmp_path, **{"02-ism-masked.json": self._policy(retention_days=7)["policy"]}
        )
        lines: list[str] = []
        ok = await deploy._rollback(fake, load_tenant_config("customer-a"), snap, lines)
        assert ok
        # The pre-create PUT is the only ISM write — the rollback skipped.
        assert len(self._ism_puts(fake)) == 1
        assert lines == [
            "[skip] rollback ism-masked klaxon-masked-retention-customer-a unchanged"
        ]

    async def test_rollback_existing_different_ism_uses_versioned_put(
        self, tmp_path: Any
    ) -> None:
        # Live policy differs from the snapshot -> VERSIONED PUT (a plain PUT
        # would have 409'd). The deployed policy ends at the snapshot content.
        fake = FakeIndexer()
        await fake.put(
            self.ISM_PATH, content=json.dumps(self._policy(retention_days=30))
        )
        snap = self._snapshot(
            tmp_path, **{"02-ism-masked.json": self._policy(retention_days=7)["policy"]}
        )
        lines: list[str] = []
        ok = await deploy._rollback(fake, load_tenant_config("customer-a"), snap, lines)
        assert ok
        ism_puts = self._ism_puts(fake)
        assert len(ism_puts) == 2  # pre-create + versioned update
        assert ism_puts[1][1] == {"if_seq_no": 1, "if_primary_term": 1}
        # Live policy now holds the snapshot content (retention 7d).
        live = fake.store["klaxon-masked-retention-customer-a"]["policy"]
        assert live["states"][0]["transitions"][0]["conditions"]["min_index_age"] == "7d"
        assert lines[0].startswith("[ok] rollback ism-masked")

    async def test_rollback_409_once_retries_and_succeeds(self, tmp_path: Any) -> None:
        fake = FakeIndexer(ism_conflict_before_put=1)
        await fake.put(
            self.ISM_PATH, content=json.dumps(self._policy(retention_days=30))
        )
        snap = self._snapshot(
            tmp_path, **{"02-ism-masked.json": self._policy(retention_days=7)["policy"]}
        )
        lines: list[str] = []
        ok = await deploy._rollback(fake, load_tenant_config("customer-a"), snap, lines)
        assert ok
        ism_puts = self._ism_puts(fake)
        assert len(ism_puts) == 3  # pre-create + stale PUT (409) + retried PUT
        assert ism_puts[1][1] == {"if_seq_no": 1, "if_primary_term": 1}  # stale
        assert ism_puts[2][1] == {"if_seq_no": 2, "if_primary_term": 1}  # fresh
        assert any(l.startswith("[retry]") for l in lines)
        assert lines[-1].startswith("[ok] rollback ism-masked")

    async def test_rollback_409_twice_fails_with_clear_message(
        self, tmp_path: Any
    ) -> None:
        fake = FakeIndexer(ism_conflict_before_put=2)
        await fake.put(
            self.ISM_PATH, content=json.dumps(self._policy(retention_days=30))
        )
        snap = self._snapshot(
            tmp_path, **{"02-ism-masked.json": self._policy(retention_days=7)["policy"]}
        )
        lines: list[str] = []
        ok = await deploy._rollback(fake, load_tenant_config("customer-a"), snap, lines)
        assert not ok
        assert len(self._ism_puts(fake)) == 3
        assert sum(1 for l in lines if l.startswith("[retry]")) == 1
        assert lines[-1].startswith("[fail]")
        assert "HTTP 409" in lines[-1]
        assert "re-run the deploy" in lines[-1]

    def test_rollback_end_to_end_restores_and_is_a_noop_second_time(
        self, env: None, run_deploy: Any, tmp_path: Any, capsys: Any
    ) -> None:
        # Live cluster has the CURRENT policy (retention 30); the snapshot holds
        # the OLD one (retention 7). --rollback must versioned-PUT the snapshot
        # content; a second --rollback is a no-op (skip-if-identical).
        cfg = load_tenant_config("customer-a")
        fake = run_deploy()
        ism_name = cfg.ism_policy_name
        ism_path = f"/_plugins/_ism/policies/{ism_name}"
        # Seed a LIVE (current) policy — retention 30 — like a real cluster.
        # Note: FakeIndexer.store is keyed by the policy NAME, not the full path.
        fake.ism_meta[ism_name] = {"version": 1, "seq_no": 1, "primary_term": 1}
        fake.store[ism_name] = self._policy(retention_days=30)
        self._snapshot(
            tmp_path, **{"02-ism-masked.json": self._policy(retention_days=7)["policy"]}
        )

        rc = deploy.deploy_main(["--tenant", "customer-a", "--rollback"])
        assert rc == 0
        ism_puts = self._ism_puts(fake)
        # One VERSIONED update (no plain PUT that would 409).
        assert ism_puts == [(ism_path, {"if_seq_no": 1, "if_primary_term": 1})]
        # Live policy now matches the snapshot content.
        live = fake.store[ism_name]["policy"]
        assert live["states"][0]["transitions"][0]["conditions"]["min_index_age"] == "7d"

        capsys.readouterr()  # clear run 1 output
        n_before = len(fake.puts)
        rc2 = deploy.deploy_main(["--tenant", "customer-a", "--rollback"])
        assert rc2 == 0
        assert len(fake.puts) == n_before  # no write at all
        out = capsys.readouterr().out
        assert (
            "[skip] rollback ism-masked klaxon-masked-retention-customer-a unchanged"
            in out
        )


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
