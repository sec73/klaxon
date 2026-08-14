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

# The OpenSearch ISM defaults/metadata the plugin adds when a PUT body omits
# them (mirrors deploy.ISM_SERVER_DEFAULTS). The FakeIndexer injects these on
# GET when ism_inject_defaults=True, so tests exercise the real re-served shape.
_ISM_RETRY_DEFAULT = {"count": 3, "backoff": "exponential", "delay": "1m"}


def _inject_ism_server_defaults(policy: dict[str, Any]) -> dict[str, Any]:
    """The policy as OpenSearch ISM re-serves it: resolved defaults + metadata
    the PUT body omitted (retry on every action, rollover.copy_alias: false,
    and `ism_template` re-served as a LIST of entries each carrying a
    `last_updated_time` timestamp)."""
    import copy

    served = copy.deepcopy(policy)
    for state in served.get("states", []) or []:
        if not isinstance(state, dict):
            continue
        for action in state.get("actions", []) or []:
            if not isinstance(action, dict):
                continue
            action.setdefault("retry", dict(_ISM_RETRY_DEFAULT))
            rollover = action.get("rollover")
            if isinstance(rollover, dict):
                rollover.setdefault("copy_alias", False)
    template = served.get("ism_template")
    if isinstance(template, dict):
        entry = dict(template)
        entry.setdefault("last_updated_time", 1_786_700_788_793)
        served["ism_template"] = [entry]
    elif isinstance(template, list):
        for entry in template:
            if isinstance(entry, dict):
                entry.setdefault("last_updated_time", 1_786_700_788_793)
    return served


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
        ism_double_nested: bool = False,
        ism_inject_defaults: bool = False,
    ) -> None:
        self.salt = salt
        self.data_stream_present = data_stream_present
        self.deployed_pipeline = deployed_pipeline
        self.sync_updated = sync_updated
        self.reachable = reachable
        self.ism_conflict_before_put = ism_conflict_before_put
        self.ism_double_nested = ism_double_nested
        self.ism_inject_defaults = ism_inject_defaults
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
                if self.ism_inject_defaults:
                    # Real ISM re-serves the policy with resolved defaults the
                    # PUT body omitted (retry, rollover.copy_alias,
                    # ism_template[].last_updated_time) — see ISM_SERVER_DEFAULTS.
                    policy = _inject_ism_server_defaults(policy)
                # Real ISM GET re-serves the policy with server-managed fields
                # and the version metadata the deploy's versioned PUT needs.
                served = dict(policy)
                served.setdefault("policy_id", name)
                served.setdefault("last_updated_time", 1_577_990_933_044)
                served.setdefault("schema_version", 1)
                served.setdefault("error_notification", None)
                if self.ism_double_nested:
                    # The shape observed on the live cluster (the bug that broke
                    # the deploy verify): the policy document is DOUBLE-nested
                    # (`response["policy"]["policy"]`) with the server-managed
                    # keys on the OUTER `policy` wrapper.
                    policy_payload: dict[str, Any] = {
                        "policy_id": name,
                        "last_updated_time": 1_577_990_933_044,
                        "schema_version": 1,
                        "error_notification": None,
                        "policy": dict(policy),
                    }
                else:
                    policy_payload = served
                return FakeResp(
                    200,
                    {
                        "_id": name,
                        "_version": meta.get("version", 1),
                        "_seq_no": meta.get("seq_no", 1),
                        "_primary_term": meta.get("primary_term", 1),
                        "policy": policy_payload,
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


class TestIsmEnvelope:
    """Regression: the REAL ISM GET returns the policy DOUBLE-nested
    (`response["policy"]["policy"]`) next to `_id`/`_version`/`_seq_no`/
    `_primary_term`. The fingerprint must compare the innermost policy — not the
    envelope — so a correctly-deployed policy verifies, and a genuine drift is
    reported with the differing JSON path instead of a bare "fingerprint
    differs". The FakeIndexer is switched to `ism_double_nested=True` for the
    envelope shape; pipeline/template verify is covered by the regression tests
    at the bottom.
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

    async def test_verify_passes_with_double_nested_envelope_same_content(
        self,
    ) -> None:
        # Same content served in the real double-nested envelope -> PASSES
        # (this was the deploy failure: the envelope was fingerprinted raw).
        fake = FakeIndexer(ism_double_nested=True)
        await fake.put(self.ISM_PATH, content=json.dumps(self._policy()))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, self.LABEL, self.ISM_PATH, self._policy(), kind="ism", lines=lines
        )
        assert ok
        assert lines == [f"[ok] {self.LABEL} (verified)"]

    async def test_verify_fails_on_drift_and_reports_the_field(self) -> None:
        # Content differs (retention 30d -> 90d) -> FAILS and the diff names the
        # differing JSON path with the human-readable values, not canonicalized
        # seconds and not a bare "fingerprint differs".
        fake = FakeIndexer(ism_double_nested=True)
        await fake.put(
            self.ISM_PATH, content=json.dumps(self._policy(retention_days=90))
        )
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake,
            self.LABEL,
            self.ISM_PATH,
            self._policy(retention_days=30),
            kind="ism",
            lines=lines,
        )
        assert not ok
        assert any("fingerprint differs" in l for l in lines)
        assert any("min_index_age" in l for l in lines)
        assert any("30d" in l and "90d" in l for l in lines)

    async def test_verify_fails_when_state_removed_and_reports_path(self) -> None:
        # The delete state is removed entirely -> the diff reports the list
        # length mismatch instead of a generic fingerprint failure.
        sent = self._policy()
        drift = self._policy()
        drift["policy"]["states"] = [drift["policy"]["states"][0]]
        fake = FakeIndexer(ism_double_nested=True)
        await fake.put(self.ISM_PATH, content=json.dumps(drift))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, self.LABEL, self.ISM_PATH, sent, kind="ism", lines=lines
        )
        assert not ok
        assert any("states" in l and "length" in l for l in lines)

    async def test_get_ism_policy_parses_double_nested_envelope(self) -> None:
        # The skip-compare path (`_put_ism_policy`) must also see the innermost
        # policy, otherwise a re-deploy would never skip an identical policy.
        fake = FakeIndexer(ism_double_nested=True)
        await fake.put(self.ISM_PATH, content=json.dumps(self._policy()))
        body, seq_no, primary_term = await deploy._get_ism_policy(
            fake, self.ISM_PATH
        )
        assert isinstance(body, dict)
        assert body.get("description")  # the actual policy, not the envelope
        assert (seq_no, primary_term) == (1, 1)

    def test_duration_normalization_makes_equivalent_units_equal(self) -> None:
        # The indexer may re-serve `30d` as `43200m`: canonicalization must make
        # them fingerprint-equal, while a genuinely different duration differs.
        sent = deploy._normalize_ism_durations({"min_index_age": "30d"})
        served = deploy._normalize_ism_durations({"min_index_age": "43200m"})
        assert sent == served
        assert deploy._fingerprint(sent) == deploy._fingerprint(served)
        assert deploy._fingerprint(sent) != deploy._fingerprint(
            deploy._normalize_ism_durations({"min_index_age": "90d"})
        )
        # Size fields are durations-never: `min_size` is not touched.
        assert deploy._normalize_ism_durations({"min_size": "50gb"}) == {
            "min_size": "50gb"
        }

    def test_ism_policy_from_envelope_accepts_both_nested_shapes(self) -> None:
        policy = self._policy()["policy"]
        double_nested = {
            "_id": "x",
            "_version": 3,
            "_seq_no": 42,
            "_primary_term": 1,
            "policy": {
                "policy_id": "x",
                "last_updated_time": 1_577_990_933_044,
                "schema_version": 1,
                "error_notification": None,
                "policy": policy,
            },
        }
        assert deploy._ism_policy_from_envelope(double_nested) is policy
        # Single-nested fallback (older shapes / the pre-fix test double).
        assert deploy._ism_policy_from_envelope({"policy": policy}) is policy
        assert deploy._ism_policy_from_envelope({}) is None
        assert deploy._ism_policy_from_envelope({"policy": 5}) is None

    def test_json_diff_reports_paths(self) -> None:
        diffs = deploy._json_diff(
            {"a": 1, "b": {"c": "x"}},
            {"a": 2, "b": {"c": "y"}, "d": 3},
        )
        assert any("$.a" in d for d in diffs)
        assert any("$.b.c" in d for d in diffs)
        assert any("$.d" in d for d in diffs)
        assert deploy._json_diff({"a": 1}, {"a": 1}) == []

    def test_double_nested_ism_end_to_end_deploy_passes(
        self, env: None, run_deploy: Any, capsys: Any
    ) -> None:
        # The real-world double-nested envelope: `masking deploy` verifies both
        # ISM policies instead of failing with "fingerprint differs".
        run_deploy(ism_double_nested=True)
        rc = deploy.deploy_main(["--tenant", "customer-a", "--force"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "[ok] ISM klaxon-masked-retention-customer-a (verified)" in out
        assert "[ok] ISM klaxon-quarantine-retention-customer-a (verified)" in out

    def test_double_nested_ism_rerun_is_a_noop(
        self, env: None, run_deploy: Any, capsys: Any
    ) -> None:
        # With the double-nested envelope the re-run must skip the identical
        # policies (the `_get_ism_policy` compare now sees the real policy).
        fake = run_deploy(ism_double_nested=True)
        assert deploy.deploy_main(["--tenant", "customer-a", "--force"]) == 0
        capsys.readouterr()  # clear run 1 output
        ism_puts_after_first = len(self._ism_puts(fake))
        assert deploy.deploy_main(["--tenant", "customer-a", "--force"]) == 0
        out = capsys.readouterr().out
        assert len(self._ism_puts(fake)) == ism_puts_after_first
        assert "[skip] ISM klaxon-masked-retention-customer-a unchanged" in out
        assert "[skip] ISM klaxon-quarantine-retention-customer-a unchanged" in out


class TestIsmServerDefaults:
    """OpenSearch ISM re-serves a policy with resolved defaults and metadata the
    PUT body omitted (see `deploy.ISM_SERVER_DEFAULTS`): `retry` on every
    action, `copy_alias: false` on rollover actions, and `last_updated_time` on
    every `ism_template[]` entry. These are ISM behaviors, not drift — the
    verify must ignore them while still catching real changes. The FakeIndexer
    models the re-served shape with `ism_inject_defaults=True`."""

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

    async def test_verify_passes_with_injected_defaults(self) -> None:
        # Sent without retry/copy_alias vs deployed re-served WITH the ISM
        # defaults -> PASSES (they are not drift).
        fake = FakeIndexer(ism_double_nested=True, ism_inject_defaults=True)
        await fake.put(self.ISM_PATH, content=json.dumps(self._policy()))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, self.LABEL, self.ISM_PATH, self._policy(), kind="ism", lines=lines
        )
        assert ok
        assert lines == [f"[ok] {self.LABEL} (verified)"]

    async def test_verify_ignores_ism_template_last_updated_time(self) -> None:
        # last_updated_time is pure metadata: present on the deployed side, it
        # must be ignored, not reported as drift.
        fake = FakeIndexer(ism_double_nested=True, ism_inject_defaults=True)
        await fake.put(self.ISM_PATH, content=json.dumps(self._policy()))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, self.LABEL, self.ISM_PATH, self._policy(), kind="ism", lines=lines
        )
        assert ok
        assert not any("last_updated_time" in l for l in lines)

    async def test_explicit_retry_is_respected(self) -> None:
        # Sent EXPLICITLY sets retry {count:5}; deployed matches -> PASSES (the
        # default logic must not clobber an explicit value).
        sent = self._policy()
        sent["policy"]["states"][0]["actions"][0]["retry"] = {
            "count": 5,
            "backoff": "exponential",
            "delay": "2m",
        }
        fake = FakeIndexer(ism_double_nested=True, ism_inject_defaults=True)
        await fake.put(self.ISM_PATH, content=json.dumps(sent))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, self.LABEL, self.ISM_PATH, sent, kind="ism", lines=lines
        )
        assert ok

    async def test_explicit_retry_differing_from_default_fails(self) -> None:
        # Sent retry {count:5} vs deployed carrying the ISM default
        # {count:3}: because sent EXPLICITLY set retry, the default-stripping
        # must NOT hide the difference -> FAILS at the retry path.
        sent = self._policy()
        sent["policy"]["states"][0]["actions"][0]["retry"] = {
            "count": 5,
            "backoff": "exponential",
            "delay": "2m",
        }
        deployed = self._policy()
        deployed["policy"]["states"][0]["actions"][0]["retry"] = dict(
            _ISM_RETRY_DEFAULT
        )
        fake = FakeIndexer(ism_double_nested=True)
        await fake.put(self.ISM_PATH, content=json.dumps(deployed))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, self.LABEL, self.ISM_PATH, sent, kind="ism", lines=lines
        )
        assert not ok
        assert any("retry" in l for l in lines)

    async def test_changed_min_index_age_still_fails(self) -> None:
        # Genuine drift (30d -> 90d) must survive the defaults-stripping and
        # report the differing field path.
        sent = self._policy(retention_days=30)
        deployed = self._policy(retention_days=90)
        fake = FakeIndexer(ism_double_nested=True, ism_inject_defaults=True)
        await fake.put(self.ISM_PATH, content=json.dumps(deployed))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, self.LABEL, self.ISM_PATH, sent, kind="ism", lines=lines
        )
        assert not ok
        assert any("min_index_age" in l for l in lines)

    async def test_removed_state_still_fails(self) -> None:
        # A removed state is real drift and must be reported even when the
        # deployed side carries ISM defaults.
        sent = self._policy()
        deployed = self._policy()
        deployed["policy"]["states"] = [deployed["policy"]["states"][0]]
        fake = FakeIndexer(ism_double_nested=True, ism_inject_defaults=True)
        await fake.put(self.ISM_PATH, content=json.dumps(deployed))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, self.LABEL, self.ISM_PATH, sent, kind="ism", lines=lines
        )
        assert not ok
        assert any("states" in l for l in lines)

    def test_ism_server_defaults_constant_is_the_single_source(self) -> None:
        defaults = deploy.ISM_SERVER_DEFAULTS
        assert defaults["retry"] == dict(_ISM_RETRY_DEFAULT)
        assert defaults["copy_alias"] is False
        assert "last_updated_time" in defaults

    def test_normalize_drops_defaults_only_when_absent_in_sent(self) -> None:
        sent = {
            "states": [{"actions": [{"rollover": {}}]}],
            "ism_template": {"index_patterns": ["x*"], "priority": 100},
        }
        deployed = {
            "states": [
                {
                    "actions": [
                        {
                            "rollover": {"copy_alias": False},
                            "retry": dict(_ISM_RETRY_DEFAULT),
                        }
                    ]
                }
            ],
            "ism_template": [
                {
                    "index_patterns": ["x*"],
                    "priority": 100,
                    "last_updated_time": 1_786_700_788_793,
                }
            ],
        }
        sent_n, deployed_n = deploy._normalize_ism_server_defaults(sent, deployed)
        assert sent_n == deployed_n == {
            "states": [{"actions": [{"rollover": {}}]}],
            "ism_template": [{"index_patterns": ["x*"], "priority": 100}],
        }

    def test_normalize_keeps_explicit_non_default_values(self) -> None:
        sent = {"states": [{"actions": [{"retry": {"count": 5}}]}]}
        deployed = {"states": [{"actions": [{"retry": {"count": 5}}]}]}
        sent_n, deployed_n = deploy._normalize_ism_server_defaults(sent, deployed)
        assert sent_n == sent
        assert deployed_n == deployed

    def test_ism_template_dict_vs_list_shape_is_canonicalized(self) -> None:
        # The artifact carries `ism_template` as a single dict; ISM stores and
        # re-serves it as a LIST of entries (each with a last_updated_time).
        # Both must compare equal after normalization.
        sent = {
            "ism_template": {
                "index_patterns": ["klaxon-masked-customer-a-v5*"],
                "priority": 100,
            }
        }
        deployed = {
            "ism_template": [
                {
                    "index_patterns": ["klaxon-masked-customer-a-v5*"],
                    "priority": 100,
                    "last_updated_time": 1_786_700_788_793,
                }
            ]
        }
        sent_n, deployed_n = deploy._normalize_ism_server_defaults(sent, deployed)
        assert sent_n == deployed_n == {
            "ism_template": [
                {
                    "index_patterns": ["klaxon-masked-customer-a-v5*"],
                    "priority": 100,
                }
            ]
        }

    def test_end_to_end_deploy_passes_with_injected_defaults(
        self, env: None, run_deploy: Any, capsys: Any
    ) -> None:
        # The real-world re-served shape (defaults injected on GET): `masking
        # deploy` verifies both ISM policies instead of reporting drift.
        run_deploy(ism_double_nested=True, ism_inject_defaults=True)
        rc = deploy.deploy_main(["--tenant", "customer-a", "--force"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "[ok] ISM klaxon-masked-retention-customer-a (verified)" in out
        assert "[ok] ISM klaxon-quarantine-retention-customer-a (verified)" in out

    def test_rerun_skips_identical_with_injected_defaults(
        self, env: None, run_deploy: Any, capsys: Any
    ) -> None:
        # The skip-if-identical compare must also strip the injected defaults,
        # or a re-run would never skip.
        fake = run_deploy(ism_double_nested=True, ism_inject_defaults=True)
        assert deploy.deploy_main(["--tenant", "customer-a", "--force"]) == 0
        capsys.readouterr()  # clear run 1 output
        ism_puts_after_first = len(self._ism_puts(fake))
        assert deploy.deploy_main(["--tenant", "customer-a", "--force"]) == 0
        out = capsys.readouterr().out
        assert len(self._ism_puts(fake)) == ism_puts_after_first
        assert "[skip] ISM klaxon-masked-retention-customer-a unchanged" in out
        assert "[skip] ISM klaxon-quarantine-retention-customer-a unchanged" in out


class TestVerifyRegression:
    """Pipeline and template verify must be byte-identical to before the ISM
    envelope fix — only the ISM path normalizes/extracts differently."""

    async def test_pipeline_verify_unchanged(self) -> None:
        fake = FakeIndexer()
        path = "/_ingest/pipeline/klaxon-mask-customer-a"
        body = {"processors": [{"set": {"field": "x", "value": 1}}]}
        await fake.put(path, content=json.dumps(body))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, "pipeline klaxon-mask-customer-a", path, body,
            kind="pipeline", lines=lines,
        )
        assert ok
        assert lines == ["[ok] pipeline klaxon-mask-customer-a (verified)"]

    async def test_template_verify_unchanged(self) -> None:
        fake = FakeIndexer()
        path = "/_index_template/klaxon-masked-customer-a"
        body = {
            "index_patterns": ["klaxon-masked-customer-a-v5*"],
            "priority": 200,
            "template": {"settings": {}},
            "data_stream": {},
        }
        await fake.put(path, content=json.dumps(body))
        lines: list[str] = []
        ok = await deploy._verify_after_put(
            fake, "index template klaxon-masked-customer-a", path, body,
            kind="template", lines=lines,
        )
        assert ok
        assert lines == ["[ok] index template klaxon-masked-customer-a (verified)"]


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
