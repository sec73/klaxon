# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""`klaxon masking teardown` — dependency order, idempotency (404 = already
removed), dry-run no-op, confirmation gating, verification-failure non-zero,
sync-state keep-vs-purge, no-secret output, and the hard "never touches
wazuh-*" guarantee.

The teardown command talks to the indexer DIRECTLY (raw httpx, like
`klaxon masking deploy`). These tests drive `teardown_main` with
`httpx.AsyncClient` stubbed to a fake indexer that models the Option B
resources, and assert the output never contains the password, the salt, token
values or raw data.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from klaxon_mcp import teardown

PASSWORD = "admin-password"
SALT = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


class FakeResp:
    def __init__(self, status: int, payload: Any) -> None:
        self.status_code = status
        self._payload = payload

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def text(self) -> str:
        return json.dumps(self._payload)

    def json(self) -> Any:
        if isinstance(self._payload, str):
            return json.loads(self._payload)
        return self._payload


def _cat_rows(rows: list[tuple[str, int]]) -> list[dict[str, str]]:
    return [{"index": name, "docs.count": str(count)} for name, count in rows]


class FakeIndexer:
    """A stub OpenSearch indexer modelling the Option B resources.

    State:
      * indices:      {index_name: doc_count} — includes `.ds-klaxon-*` backing
                      indices, the `klaxon-sync-state` marker index and the
                      raw `wazuh-*` indices (never mutated).
      * data_streams / templates / ism_policies / pipelines: sets of names.
      * sync_docs:    doc ids present under klaxon-sync-state/_doc/.
      * delete_fail:  paths whose DELETE returns 500 even when present (to
                      simulate a failed teardown leaving leftovers).
    """

    def __init__(
        self,
        *,
        indices: dict[str, int] | None = None,
        data_streams: set[str] | None = None,
        templates: set[str] | None = None,
        ism_policies: set[str] | None = None,
        pipelines: set[str] | None = None,
        sync_docs: set[str] | None = None,
        delete_fail: set[str] | None = None,
    ) -> None:
        self.indices = dict(indices or {})
        self.data_streams = set(data_streams or ())
        self.templates = set(templates or ())
        self.ism_policies = set(ism_policies or ())
        self.pipelines = set(pipelines or ())
        self.sync_docs = set(sync_docs or ())
        self.delete_fail = set(delete_fail or ())
        self.deletes: list[str] = []

    @staticmethod
    def full() -> FakeIndexer:
        """A fully deployed tenant: every resource present, raw streams live."""
        return FakeIndexer(
            indices={
                ".ds-klaxon-masked-customer-a-v5-000001": 100,
                "klaxon-sync-state": 1,
                "wazuh-events-v5-2026.08.14-000001": 1000,
                "wazuh-events-v5-2026.08.14-000002": 500,
                "wazuh-findings-v5-2026.08.14-000001": 50,
            },
            data_streams={"klaxon-masked-customer-a-v5"},
            templates={"klaxon-masked-customer-a"},
            ism_policies={"klaxon-masked-retention-customer-a"},
            pipelines={"klaxon-mask-customer-a"},
            sync_docs={"klaxon-sync-customer-a"},
        )

    @staticmethod
    def raw_only() -> FakeIndexer:
        """Nothing deployed (already torn down), raw streams still live."""
        return FakeIndexer(
            indices={
                "wazuh-events-v5-2026.08.14-000001": 1000,
                "wazuh-findings-v5-2026.08.14-000001": 50,
            }
        )

    # -- request handling ------------------------------------------------ #
    async def get(self, path: str, params: dict[str, Any] | None = None) -> FakeResp:
        if path == "/_cat/indices" and params:
            pattern = params.get("index")
            if isinstance(pattern, str):
                import fnmatch

                rows = [
                    (name, count)
                    for name, count in self.indices.items()
                    if fnmatch.fnmatch(name, pattern)
                ]
                return FakeResp(200, _cat_rows(rows))
            return FakeResp(200, _cat_rows(list(self.indices.items())))
        if path.startswith("/_data_stream/"):
            name = path.rsplit("/", 1)[1]
            if name in self.data_streams:
                return FakeResp(200, {"data_streams": [{"name": name}]})
            return FakeResp(404, {"error": {"reason": "no such data stream"}})
        if path.startswith("/_index_template/"):
            name = path.rsplit("/", 1)[1]
            if name in self.templates:
                return FakeResp(
                    200, {"index_templates": [{"name": name, "index_template": {}}]}
                )
            return FakeResp(404, {"error": {"reason": "index_template_missing_exception"}})
        if path.startswith("/_plugins/_ism/policies/"):
            name = path.rsplit("/", 1)[1]
            if name in self.ism_policies:
                return FakeResp(200, {"policy_id": name, "policy": {}})
            return FakeResp(404, {"error": {"reason": "no such policy"}})
        if path.startswith("/_ingest/pipeline/"):
            name = path.rsplit("/", 1)[1]
            if name in self.pipelines:
                return FakeResp(200, {name: {"description": ""}})
            return FakeResp(404, {"error": {"reason": "pipeline_missing_exception"}})
        if path.startswith("/klaxon-sync-state/_doc/"):
            doc_id = path.rsplit("/", 1)[1]
            if doc_id in self.sync_docs:
                return FakeResp(200, {"_source": {"checkpoint": "2026-08-14T00:00:00Z"}})
            return FakeResp(404, {"error": {"reason": "no such doc"}})
        if path == "/klaxon-sync-state/_count":
            if "klaxon-sync-state" not in self.indices:
                return FakeResp(404, {"error": {"reason": "index_not_found_exception"}})
            return FakeResp(200, {"count": len(self.sync_docs)})
        return FakeResp(404, {"error": {"reason": f"unexpected GET {path}"}})

    async def delete(self, path: str) -> FakeResp:
        self.deletes.append(path)
        if path in self.delete_fail:
            return FakeResp(500, {"error": {"reason": "simulated delete failure"}})
        if path.startswith("/_data_stream/"):
            name = path.rsplit("/", 1)[1]
            if name in self.data_streams:
                self.data_streams.discard(name)
                # Removing the stream removes its backing indices.
                prefix = f".ds-{name}-"
                for idx in [i for i in self.indices if i.startswith(prefix)]:
                    del self.indices[idx]
                return FakeResp(200, {"acknowledged": True})
            return FakeResp(404, {"error": {"reason": "no such data stream"}})
        if path.startswith("/_index_template/"):
            name = path.rsplit("/", 1)[1]
            if name in self.templates:
                self.templates.discard(name)
                return FakeResp(200, {"acknowledged": True})
            return FakeResp(404, {"error": {"reason": "no such template"}})
        if path.startswith("/_plugins/_ism/policies/"):
            name = path.rsplit("/", 1)[1]
            if name in self.ism_policies:
                self.ism_policies.discard(name)
                return FakeResp(200, {"acknowledged": True})
            return FakeResp(404, {"error": {"reason": "no such policy"}})
        if path.startswith("/_ingest/pipeline/"):
            name = path.rsplit("/", 1)[1]
            if name in self.pipelines:
                self.pipelines.discard(name)
                return FakeResp(200, {"acknowledged": True})
            return FakeResp(404, {"error": {"reason": "no such pipeline"}})
        if path.startswith("/klaxon-sync-state/_doc/"):
            doc_id = path.rsplit("/", 1)[1]
            if doc_id in self.sync_docs:
                self.sync_docs.discard(doc_id)
                return FakeResp(200, {"result": "deleted"})
            return FakeResp(404, {"error": {"reason": "no such doc"}})
        if path == "/klaxon-sync-state":
            if "klaxon-sync-state" in self.indices:
                del self.indices["klaxon-sync-state"]
                return FakeResp(200, {"acknowledged": True})
            return FakeResp(404, {"error": {"reason": "index_not_found_exception"}})
        if path.startswith("/") and path[1:] in self.indices:
            del self.indices[path[1:]]
            return FakeResp(200, {"acknowledged": True})
        return FakeResp(404, {"error": {"reason": f"unexpected DELETE {path}"}})


class FakeHTTP:
    """An async context manager standing in for httpx.AsyncClient."""

    def __init__(self, fake: FakeIndexer) -> None:
        self.fake = fake

    async def __aenter__(self) -> FakeIndexer:
        return self.fake

    async def __aexit__(self, *args: object) -> bool:
        return False


@pytest.fixture
def run_teardown(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """Patch httpx.AsyncClient to the fake and return an installer."""
    fake = FakeIndexer()

    def install(fake_or_none: Any = None, **kw: Any) -> FakeIndexer:
        nonlocal fake
        fake = fake_or_none if fake_or_none is not None else FakeIndexer(**kw)
        monkeypatch.setattr(teardown.httpx, "AsyncClient", lambda **_: FakeHTTP(fake))
        return fake

    install()
    yield install
    monkeypatch.undo()


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("KLAXON_INDEXER_URL", "https://indexer.example:9200")
    monkeypatch.setenv("KLAXON_INDEXER_USER", "admin")
    monkeypatch.setenv("KLAXON_INDEXER_PASSWORD", PASSWORD)
    monkeypatch.setenv("KLAXON_ANONYMIZATION_SALT", SALT)
    yield


class TestDryRun:
    def test_dry_run_lists_all_resources_and_changes_nothing(
        self, env: None, run_teardown: Any, capsys: Any
    ) -> None:
        fake = run_teardown(FakeIndexer.full())
        rc = teardown.teardown_main(["--tenant", "customer-a", "--dry-run"])
        assert rc == 0
        assert fake.deletes == []  # no indexer mutation
        out = capsys.readouterr().out
        # Every resource is listed, in dependency order.
        assert "klaxon-masked-customer-a-v5" in out
        assert "klaxon-sync-state/_doc/klaxon-sync-customer-a" in out
        assert "klaxon-masked-customer-a" in out
        assert "klaxon-masked-retention-customer-a" in out
        assert "klaxon-mask-customer-a" in out
        assert "KEPT" in out  # sync marker kept by default
        # Raw streams are never touched by a dry run.
        assert "no changes made" in out

    def test_dry_run_does_not_need_credentials(
        self, monkeypatch: pytest.MonkeyPatch, run_teardown: Any
    ) -> None:
        for name in ("KLAXON_INDEXER_URL", "KLAXON_INDEXER_USER", "KLAXON_INDEXER_PASSWORD"):
            monkeypatch.delenv(name, raising=False)
        rc = teardown.teardown_main(["--tenant", "customer-a", "--dry-run"])
        assert rc == 0


class TestConfirmation:
    def test_without_yes_or_dry_run_aborts_on_non_tty(
        self, env: None, run_teardown: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        fake = run_teardown(FakeIndexer.full())

        class NonTty:
            def isatty(self) -> bool:
                return False

        monkeypatch.setattr(teardown.sys, "stdin", NonTty())
        rc = teardown.teardown_main(["--tenant", "customer-a"])
        assert rc == 1  # aborted — destructive command without confirmation
        assert fake.deletes == []
        assert "aborted" in capsys.readouterr().err

    def test_confirm_declined_aborts(
        self, env: None, run_teardown: Any, monkeypatch: pytest.MonkeyPatch, capsys: Any
    ) -> None:
        fake = run_teardown(FakeIndexer.full())
        monkeypatch.setattr(teardown, "_confirm", lambda prompt: False)
        rc = teardown.teardown_main(["--tenant", "customer-a"])
        assert rc == 1
        assert fake.deletes == []

    def test_confirm_accepted_executes(
        self, env: None, run_teardown: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = run_teardown(FakeIndexer.full())
        monkeypatch.setattr(teardown, "_confirm", lambda prompt: True)
        rc = teardown.teardown_main(["--tenant", "customer-a"])
        assert rc == 0
        assert fake.deletes  # teardown ran


class TestRemovalOrder:
    def test_yes_full_teardown_order(self, env: None, run_teardown: Any) -> None:
        fake = run_teardown(FakeIndexer.full())
        rc = teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        assert rc == 0
        # Dependency order: data stream first (its backing indices go with it,
        # exactly like the real data-stream DELETE), then template, ISM policy,
        # pipeline. No sync-state delete without --purge-sync-state.
        assert fake.deletes == [
            "/_data_stream/klaxon-masked-customer-a-v5",
            "/_index_template/klaxon-masked-customer-a",
            "/_plugins/_ism/policies/klaxon-masked-retention-customer-a",
            "/_ingest/pipeline/klaxon-mask-customer-a",
        ]
        # Everything is gone.
        assert fake.data_streams == set()
        assert fake.templates == set()
        assert fake.ism_policies == set()
        assert fake.pipelines == set()

    def test_orphaned_backing_indices_are_swept(
        self, env: None, run_teardown: Any
    ) -> None:
        # The data stream is already gone but a `.ds-klaxon-masked-*` backing
        # index is still around (a partial earlier delete). The teardown treats
        # the stream as already-removed AND sweeps the orphaned backing index.
        fake = FakeIndexer(
            indices={
                ".ds-klaxon-masked-customer-a-v5-000001": 100,
                "wazuh-events-v5-2026.08.14-000001": 1000,
                "wazuh-findings-v5-2026.08.14-000001": 50,
            },
            templates={"klaxon-masked-customer-a"},
            ism_policies={"klaxon-masked-retention-customer-a"},
            pipelines={"klaxon-mask-customer-a"},
        )
        run_teardown(fake)
        rc = teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        assert rc == 0
        assert fake.deletes[0] == "/_data_stream/klaxon-masked-customer-a-v5"
        assert fake.deletes[1] == "/.ds-klaxon-masked-customer-a-v5-000001"
        assert ".ds-klaxon-masked-customer-a-v5-000001" not in fake.indices

    def test_purge_sync_state_deletes_marker_and_empty_index(
        self, env: None, run_teardown: Any
    ) -> None:
        fake = run_teardown(FakeIndexer.full())
        rc = teardown.teardown_main(
            ["--tenant", "customer-a", "--yes", "--purge-sync-state"]
        )
        assert rc == 0
        # Marker doc deleted, then the now-empty marker index.
        assert "/klaxon-sync-state/_doc/klaxon-sync-customer-a" in fake.deletes
        assert "/klaxon-sync-state" in fake.deletes
        assert "klaxon-sync-state" not in fake.indices
        assert fake.sync_docs == set()

    def test_purge_sync_state_keeps_index_with_other_tenants(
        self, env: None, run_teardown: Any, capsys: Any
    ) -> None:
        fake = FakeIndexer(
            indices={
                ".ds-klaxon-masked-customer-a-v5-000001": 100,
                "klaxon-sync-state": 2,
                "wazuh-events-v5-2026.08.14-000001": 1000,
                "wazuh-findings-v5-2026.08.14-000001": 50,
            },
            data_streams={"klaxon-masked-customer-a-v5"},
            templates={"klaxon-masked-customer-a"},
            ism_policies={"klaxon-masked-retention-customer-a"},
            pipelines={"klaxon-mask-customer-a"},
            sync_docs={"klaxon-sync-customer-a", "klaxon-sync-customer-b"},
        )
        run_teardown(fake)
        rc = teardown.teardown_main(
            ["--tenant", "customer-a", "--yes", "--purge-sync-state"]
        )
        assert rc == 0
        # Our marker is gone, but the shared index survives (other tenants).
        assert "/klaxon-sync-state/_doc/klaxon-sync-customer-a" in fake.deletes
        assert "/klaxon-sync-state" not in fake.deletes
        assert fake.sync_docs == {"klaxon-sync-customer-b"}
        assert "klaxon-sync-state" in fake.indices
        assert "kept" in capsys.readouterr().out

    def test_sync_marker_kept_by_default(self, env: None, run_teardown: Any) -> None:
        fake = run_teardown(FakeIndexer.full())
        rc = teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        assert rc == 0
        # Without --purge-sync-state the marker (and its index) are untouched.
        assert not any("/klaxon-sync-state" in p for p in fake.deletes)
        assert fake.sync_docs == {"klaxon-sync-customer-a"}
        assert "klaxon-sync-state" in fake.indices


class TestIdempotency:
    def test_missing_resources_are_already_removed(
        self, env: None, run_teardown: Any, capsys: Any
    ) -> None:
        run_teardown(FakeIndexer.raw_only())
        rc = teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        assert rc == 0  # idempotent: 404 == already removed, verification passes
        out = capsys.readouterr().out
        assert "already removed (404)" in out
        assert "raw stream wazuh-events-v5-*: 1000 doc(s), unchanged" in out


class TestVerificationFailure:
    def test_leftover_klaxon_index_fails_verification(
        self, env: None, run_teardown: Any, capsys: Any
    ) -> None:
        # A klaxon-quarantine index (not removed by this teardown) is a leftover.
        fake = FakeIndexer(
            indices={
                ".ds-klaxon-masked-customer-a-v5-000001": 100,
                "klaxon-quarantine-customer-a-v5-000001": 7,
                "wazuh-events-v5-2026.08.14-000001": 1000,
                "wazuh-findings-v5-2026.08.14-000001": 50,
            },
            data_streams={"klaxon-masked-customer-a-v5"},
            templates={"klaxon-masked-customer-a"},
            ism_policies={"klaxon-masked-retention-customer-a"},
            pipelines={"klaxon-mask-customer-a"},
            sync_docs={"klaxon-sync-customer-a"},
        )
        run_teardown(fake)
        rc = teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        assert rc == 1
        err = capsys.readouterr().err
        assert "VERIFICATION FAILED" in err
        assert "klaxon-quarantine-customer-a-v5-000001" in err

    def test_failed_delete_reported_and_exits_nonzero(
        self, env: None, run_teardown: Any, capsys: Any
    ) -> None:
        # The pipeline DELETE fails (500) -> the pipeline stays -> verification
        # fails, and the partial teardown is NOT reported as success.
        fake = FakeIndexer.full()
        fake.delete_fail = {"/_ingest/pipeline/klaxon-mask-customer-a"}
        run_teardown(fake)
        rc = teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        assert rc == 1
        out = capsys.readouterr()
        assert "DELETE returned HTTP 500" in out.out
        assert "ingest pipeline klaxon-mask-customer-a still present" in out.err
        # Everything else still went down in order.
        assert fake.templates == set()
        assert fake.ism_policies == set()
        assert fake.data_streams == set()
        assert fake.pipelines == {"klaxon-mask-customer-a"}


class TestRawStreamSafety:
    def test_raw_streams_untouched_with_unchanged_counts(
        self, env: None, run_teardown: Any, capsys: Any
    ) -> None:
        fake = run_teardown(FakeIndexer.full())
        rc = teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        assert rc == 0
        assert fake.indices["wazuh-events-v5-2026.08.14-000001"] == 1000
        assert fake.indices["wazuh-findings-v5-2026.08.14-000001"] == 50
        out = capsys.readouterr().out
        assert "raw stream wazuh-events-v5-*: 1500 doc(s), unchanged" in out
        assert "raw stream wazuh-findings-v5-*: 50 doc(s), unchanged" in out

    def test_never_touches_wazuh_paths(self, env: None, run_teardown: Any) -> None:
        fake = run_teardown(FakeIndexer.full())
        teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        for path in fake.deletes:
            assert not path.startswith("/wazuh-"), path


class TestGuards:
    def test_require_klaxon_rejects_wazuh(self) -> None:
        with pytest.raises(teardown.TeardownError):
            teardown._require_klaxon("wazuh-events-v5-2026.08.14-000001")
        with pytest.raises(teardown.TeardownError):
            teardown._require_klaxon("_ingest/pipeline/wazuh")

    def test_require_klaxon_accepts_klaxon_names(self) -> None:
        # All teardown resource names (incl. hidden .ds-* backing indices).
        for name in (
            "klaxon-mask-customer-a",
            "klaxon-masked-customer-a",
            "klaxon-masked-retention-customer-a",
            "klaxon-masked-customer-a-v5",
            "klaxon-sync-state",
            ".ds-klaxon-masked-customer-a-v5-000001",
        ):
            teardown._require_klaxon(name)

    def test_invalid_tenant_rejected(self) -> None:
        rc = teardown.teardown_main(["--tenant", "../../etc/passwd", "--dry-run"])
        assert rc == 2
        rc = teardown.teardown_main(["--tenant", "Customer; drop", "--dry-run"])
        assert rc == 2


class TestCredentialsAndSecrets:
    def test_missing_credentials_abort(self, env: None, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("KLAXON_INDEXER_URL")
        rc = teardown.teardown_main(
            ["--tenant", "customer-a", "--yes", "--env", "/nonexistent/teardown.env"]
        )
        assert rc == 1

    def test_unreachable_indexer_aborts_cleanly(
        self, env: None, run_teardown: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class BoomHTTP:
            async def __aenter__(self) -> Any:
                raise httpx.TransportError("boom")

            async def __aexit__(self, *args: object) -> bool:
                return False

        monkeypatch.setattr(teardown.httpx, "AsyncClient", lambda **_: BoomHTTP())
        rc = teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        assert rc == 1

    def test_no_secrets_in_output(self, env: None, run_teardown: Any, capsys: Any) -> None:
        run_teardown(FakeIndexer.full())
        rc = teardown.teardown_main(["--tenant", "customer-a", "--yes"])
        assert rc == 0
        out = capsys.readouterr().out
        assert PASSWORD not in out
        assert SALT not in out
        # Only resource names and statuses are logged.
        assert "indexer.example" not in out


class TestCliWiring:
    def test_wired_into_klaxon_masking(self, env: None, run_teardown: Any) -> None:
        """`klaxon masking teardown --tenant X --dry-run` reaches teardown_main."""
        from klaxon_mcp.__main__ import main

        fake = run_teardown(FakeIndexer.full())
        rc = main(["masking", "teardown", "--tenant", "customer-a", "--dry-run"])
        assert rc == 0
        assert fake.deletes == []

    def test_teardown_requires_tenant(self, env: None) -> None:
        from klaxon_mcp.__main__ import main

        # `--tenant` is required=True, so argparse rejects the invocation with
        # SystemExit(2) (the same behaviour as `masking deploy`).
        with pytest.raises(SystemExit) as exc:
            main(["masking", "teardown"])
        assert exc.value.code == 2
