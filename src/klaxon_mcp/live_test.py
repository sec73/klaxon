# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""`klaxon masking test` — the LIVE integration test for the generated pipeline.

Proves the Painless pipeline `klaxon masking generate` emits is (a) syntactically
valid and (b) behaves correctly on a real OpenSearch/Wazuh 5 indexer — without
writing anything to the cluster:

  Stage A — Ingest allowlist preflight: `GET /_scripts/painless/_context`
            (context=ingest) verifies the cluster's ingest Painless allowlist
            has every API the generated script needs (`String.sha256()`,
            `Pattern`/`Matcher`, `StringBuilder`, collections). `_execute`
            cannot compile an ingest script — its painless_test context lacks
            the ingest-only `sha256` augmentation — so Stage B's `_simulate` is
            the authoritative compile check.
  Stage B — Pipeline simulate:       `POST /_ingest/pipeline/_simulate`
            runs the generated pipeline (inline, so nothing is deployed) over
            representative documents and asserts the masking behaviour.

Credentials are read ONLY from the environment:

  * KLAXON_INDEXER_URL      (e.g. https://indexer:9200)
  * KLAXON_INDEXER_USER     (e.g. admin)
  * KLAXON_INDEXER_PASSWORD (the admin password)

They may be supplied through a local, gitignored `.env` file (`.env.live` or
`tests/live/.env` — see `tests/live/.env.example`), but never in a committed
file. If any of the three is unset the test SKIPS cleanly (a missing password
never fails the suite). The password is never logged, never included in error
messages, and a URL with embedded credentials is sanitised before printing.

Run as `klaxon masking test --tenant customer-a`, or via the skippable pytest
`tests/test_live_masking.py` (marked `integration`/`live`).
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any

import httpx

from .live_config import (
    DEFAULT_TEST_SALT,
    ENV_FILE_CANDIDATES,
    LIVE_ENV_NAMES,
    LIVE_ENV_PASSWORD,
    LIVE_ENV_URL,
    LIVE_ENV_USER,
    LIVE_ENV_VERIFY_SSL,
    LiveIndexerConfig,
    LiveTestError,
    _env_bool,
    _url_has_embedded_credentials,
    find_env_file,
    live_salt,
    load_dotenv_file,
    resolve_live_config,
    safe_url,
)
from .masked_stream import build_pipeline, load_tenant_config, token
from .masking import verify_script_structure

# Explicit re-export for mypy strict: names tests access via `live_test.X`.
__all__ = [
    "DEFAULT_TEST_SALT",
    "ENV_FILE_CANDIDATES",
    "LIVE_ENV_NAMES",
    "LIVE_ENV_PASSWORD",
    "LIVE_ENV_URL",
    "LIVE_ENV_USER",
    "LIVE_ENV_VERIFY_SSL",
    "LiveIndexerConfig",
    "LiveTestError",
    "_env_bool",
    "_url_has_embedded_credentials",
    "check_simulated",
    "find_env_file",
    "live_salt",
    "live_test_docs",
    "load_dotenv_file",
    "missing_ingest_members",
    "resolve_live_config",
    "safe_url",
    "stage_a_ingest_allowlist",
    "stage_b_simulate",
    "test_main",
]

_TIMEOUT = 60.0

#
# `_scripts/painless/_execute` only supports the painless_test/filter/score
# contexts, which do NOT carry the ingest-context allowlist (e.g. the
# `String.sha256()` augmentation the generated script hashes with) — so it can
# never compile an ingest script on a restricted cluster. The authoritative
# compile check is therefore Stage B's `_simulate`, which compiles in the
# ingest context. Stage A instead VERIFIES the cluster's ingest allowlist
# actually contains every API the generated script needs (this is the "Painless
# needs cluster verification of the MessageDigest/Pattern whitelist" caveat
# from docs/option-b-masked-stream.md, made explicit and machine-checked).


# (label, class name, kind, member) — the ingest-context members the script
# relies on. `kind` is "method" (instance method) or "type" (class exists).
_REQUIRED_INGEST_MEMBERS: tuple[tuple[str, str, str, str], ...] = (
    ("String.sha256() — the SHA-256 augmentation the token scheme hashes with", "java.lang.String", "method", "sha256"),
    ("String.isEmpty()", "java.lang.String", "method", "isEmpty"),
    ("String.substring()", "java.lang.String", "method", "substring"),
    ("String.charAt()", "java.lang.String", "method", "charAt"),
    ("String.length()", "java.lang.String", "method", "length"),
    ("String.indexOf()", "java.lang.String", "method", "indexOf"),
    ("Pattern (regex literals + matcher)", "java.util.regex.Pattern", "type", ""),
    ("Matcher (find/group/matches/start/end)", "java.util.regex.Matcher", "type", ""),
    ("StringBuilder", "java.lang.StringBuilder", "type", ""),
    ("ArrayList", "java.util.ArrayList", "type", ""),
    ("HashMap", "java.util.HashMap", "type", ""),
    ("Map", "java.util.Map", "type", ""),
    ("List", "java.util.List", "type", ""),
)


def missing_ingest_members(data: dict[str, Any]) -> list[str]:
    """Ingest-allowlist members the generated script needs but the cluster is
    MISSING. Empty = the allowlist is sufficient for the script to compile."""
    classes = {
        c.get("name"): c
        for c in (data.get("classes") or [])
        if isinstance(c, dict)
    }

    def has_method(cls: str, member: str) -> bool:
        entry = classes.get(cls)
        if not isinstance(entry, dict):
            return False
        return any(m.get("name") == member for m in (entry.get("methods") or []))

    missing: list[str] = []
    for label, cls, kind, member in _REQUIRED_INGEST_MEMBERS:
        if kind == "type":
            if cls not in classes:
                missing.append(f"{label} ({cls} not in the ingest allowlist)")
        else:
            if not has_method(cls, member):
                missing.append(f"{label} ({cls}.{member} not in the ingest allowlist)")
    return missing


async def stage_a_ingest_allowlist(
    client: httpx.AsyncClient,
) -> tuple[bool, str]:
    """Fetch the cluster's ingest Painless allowlist and verify it has every API
    the generated script needs. Returns `(ok, detail)`; `detail` is safe to
    print (never the password/salt)."""
    resp = await client.get("/_scripts/painless/_context?context=ingest")
    if not resp.is_success:
        return (
            False,
            "GET /_scripts/painless/_context?context=ingest failed "
            f"(HTTP {resp.status_code}): {_error_detail(resp)}",
        )
    try:
        data = resp.json()
    except ValueError:
        return False, "ingest allowlist response was not JSON."
    if not isinstance(data, dict):
        return False, "ingest allowlist response had an unexpected shape."
    missing = missing_ingest_members(data)
    if missing:
        return (
            False,
            "ingest Painless allowlist is MISSING APIs the generated script "
            "needs:\n    - " + "\n    - ".join(missing) + "\n    Fix the "
            "cluster's Painless whitelist (or the generated script) before "
            "deploying the pipeline.",
        )
    return (
        True,
        "ingest Painless allowlist has every API the generated script needs "
        "(String.sha256, Pattern/Matcher, StringBuilder, collections).",
    )


# --------------------------------------------------------------------------- #
# Stage B — pipeline simulate via _simulate (inline, write-free)
# --------------------------------------------------------------------------- #


def _masking_error(doc: dict[str, Any]) -> str:
    """The `klaxon.masking_error` value of a simulated document, or "".

    The on_failure `set` uses a dotted field name, so the flag lands NESTED as
    `doc["klaxon"]["masking_error"]` — the flat form would be missed."""
    flat = doc.get("klaxon.masking_error")
    if isinstance(flat, str):
        return flat
    nested = doc.get("klaxon")
    if isinstance(nested, dict):
        value = nested.get("masking_error")
        if isinstance(value, str):
            return value
    return ""


_REGEX_LIMIT_HINT = (
    "the indexer's script.painless.regex.limit-factor (default 6) is too low "
    "for the free-text pass on this message; raise it (e.g. to 20) in "
    "opensearch.yml on the indexer nodes (see docs/option-b-masked-stream.md)."
)


def _error_note(doc: dict[str, Any]) -> str:
    err = _masking_error(doc)
    if not err:
        return ""
    if "Regular expression considered too many characters" in err:
        return f"klaxon.masking_error: {err[:200]} — {_REGEX_LIMIT_HINT}"
    return f"klaxon.masking_error: {err[:300]}"


def live_test_docs() -> list[dict[str, Any]]:
    """Representative documents for the pipeline simulate.

    Doc 1 exercises every acceptance criterion: username/`uid=` token identity,
    `user.effective.name` like `root(uid=0)`, arrays element-wise, `event.original`
    -> one token, `related.hash` untouched, already-tokenised idempotency, and
    free-text IP/email masking. Doc 2 proves `uid=<name>` reuses the structured
    token without a bare-username registry hit. Doc 3 is a no-op document (no
    personal data) with a HOST field. Doc 4 is a dot/digit-heavy free-text line
    with no e-mail, sized to pass on a default `script.painless.regex.limit-factor`
    cluster (longer lines need that setting raised — the test reports it).
    """
    return [
        {
            "_index": "klaxon-masked-customer-a-v5-000001",
            "_id": "1",
            "_source": {
                "user.name": "alice",
                "user.effective.name": "root(uid=0)",
                "related.user": ["bob", "carol"],
                "related.hosts": ["web01", "web02"],
                "related.hash": [
                    "sha256:aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"
                ],
                "event.original": (
                    "Aug 11 09:00:00 web01 sshd[1234]: Accepted publickey for "
                    "alice from 192.168.1.10 port 22"
                ),
                "destination.ip": "[IP_0123456789abcdef]",
                "message": (
                    "sudo: pam_unix(sudo:session): session opened for user alice "
                    "by root(uid=0); uid=alice login as alice; ssh from "
                    "192.168.1.10; users bob and carol; contact noreply@example.com"
                ),
            },
        },
        {
            "_index": "klaxon-masked-customer-a-v5-000001",
            "_id": "2",
            "_source": {
                "user.name": "dave",
                "message": (
                    "login failed for uid=dave from 10.20.30.40 (invalid credentials)"
                ),
            },
        },
        {
            "_index": "klaxon-masked-customer-a-v5-000001",
            "_id": "3",
            "_source": {
                "host.hostname": "server42",
                "message": "kernel: boot sequence complete; no personal data",
            },
        },
        {
            # Doc 4 — a dot/digit-heavy free-text line (no e-mail): exercises the
            # value-type IPV4 masking and the ReDoS-safe possessive EMAIL local
            # part, sized to stay under the default `script.painless.regex.limit-factor`.
            "_index": "klaxon-masked-customer-a-v5-000001",
            "_id": "4",
            "_source": {
                "message": (
                    "packet from 10.0.0.1 to 10.0.0.2 via 192.168.1.10 "
                    "and 203.0.113.5"
                ),
            },
        },
    ]


async def stage_b_simulate(
    client: httpx.AsyncClient, pipeline: dict[str, Any], docs: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """POST the generated pipeline INLINE to `_ingest/pipeline/_simulate` (no
    deployment, nothing persisted). Returns `(masked_sources, errors)` where
    `errors` lists per-document failure strings (raw `error` blocks and any
    `klaxon.masking_error` flag from the on_failure processor).

    The simulate endpoint only accepts the pipeline definition (`processors`,
    optionally `description`) — `_meta`/`version` are rejected, so they are
    stripped from the inline body (they are provenance for the deployed
    artifact, not part of the pipeline logic)."""
    inline = {k: v for k, v in pipeline.items() if k not in ("_meta", "version")}
    resp = await client.post(
        "/_ingest/pipeline/_simulate", json={"pipeline": inline, "docs": docs}
    )
    if not resp.is_success:
        raise LiveTestError(
            "POST /_ingest/pipeline/_simulate failed "
            f"(HTTP {resp.status_code}): {_error_detail(resp)}"
        )
    payload = resp.json() if resp.content else {}
    if not isinstance(payload, dict):
        raise LiveTestError(
            "POST /_ingest/pipeline/_simulate returned a non-JSON body."
        )
    sources: list[dict[str, Any]] = []
    errors: list[str] = []
    for entry in payload.get("docs") or []:
        if not isinstance(entry, dict):
            errors.append("malformed doc result in simulate response")
            sources.append({})
            continue
        if entry.get("error"):
            errors.append(str(entry["error"])[:500])
            sources.append({})
            continue
        doc = entry.get("doc") or {}
        src = doc.get("_source")
        if isinstance(src, dict):
            sources.append(src)
            note = _error_note(src)
            if note:
                errors.append(note)
        else:
            errors.append("simulate doc carried no _source")
            sources.append({})
    return sources, errors


# --------------------------------------------------------------------------- #
# Behaviour assertions on the simulated documents (offline-testable)
# --------------------------------------------------------------------------- #


def check_simulated(
    sources: list[dict[str, Any]], cfg: Any, salt: str
) -> list[str]:
    """Masking assertions on the Stage-B simulated `_source` documents.

    Returns a list of problems (empty = the pipeline masked every document
    correctly). Pure function so the same assertions run from the CLI and the
    pytest without a cluster.
    """
    problems: list[str] = []
    docs = live_test_docs()
    if len(sources) != len(docs):
        problems.append(
            f"expected {len(docs)} simulated docs, got {len(sources)}"
        )
        return problems

    def tok(family: str, value: str) -> str:
        return token(family, value, salt)

    # ---- Doc 1: the comprehensive document ----
    d1, raw1 = sources[0], docs[0]["_source"]
    note1 = _error_note(d1)
    if note1:
        problems.append(f"doc 1 rejected: {note1}")
    if d1.get("user.name") != tok("USER", "alice"):
        problems.append(f"doc 1 user.name -> {d1.get('user.name')!r} (expected {tok('USER', 'alice')!r})")
    if d1.get("user.effective.name") != tok("USER", "root(uid=0)"):
        problems.append(
            f"doc 1 user.effective.name -> {d1.get('user.effective.name')!r} "
            f"(expected {tok('USER', 'root(uid=0)')!r})"
        )
    if d1.get("related.user") != [tok("USER", "bob"), tok("USER", "carol")]:
        problems.append(f"doc 1 related.user not masked element-wise: {d1.get('related.user')!r}")
    if d1.get("related.hosts") != [tok("HOST", "web01"), tok("HOST", "web02")]:
        problems.append(f"doc 1 related.hosts not masked element-wise: {d1.get('related.hosts')!r}")
    if d1.get("related.hash") != raw1["related.hash"]:
        problems.append(f"doc 1 related.hash was masked: {d1.get('related.hash')!r}")
    if d1.get("destination.ip") != "[IP_0123456789abcdef]":
        problems.append(
            f"doc 1 already-tokenised destination.ip was re-masked: {d1.get('destination.ip')!r}"
        )
    if d1.get("event.original") != tok("USER", raw1["event.original"]):
        problems.append(
            f"doc 1 event.original -> {d1.get('event.original')!r} (expected one token {tok('USER', raw1['event.original'])!r})"
        )

    msg = d1.get("message")
    if not isinstance(msg, str):
        problems.append("doc 1 message missing after simulate")
    else:
        alice_tok = tok("USER", "alice")
        for raw, expected in (
            ("alice", alice_tok),
            ("root(uid=0)", tok("USER", "root(uid=0)")),
            ("bob", tok("USER", "bob")),
            ("carol", tok("USER", "carol")),
            ("192.168.1.10", tok("IP", "192.168.1.10")),
            ("noreply@example.com", tok("EMAIL", "noreply@example.com")),
        ):
            if expected not in msg:
                problems.append(f"doc 1 message missing token for {raw!r}: {expected!r}")
            if raw in msg:
                problems.append(f"doc 1 message still contains raw {raw!r}")
        # uid=<same-username> inside message reuses the structured token.
        if alice_tok not in msg:
            problems.append(
                "doc 1: uid=alice / user.name did not map to the SAME token "
                "(free-text registry consistency)"
            )

    # ---- Doc 2: uid=<name> reuses the structured token ----
    d2, raw2 = sources[1], docs[1]["_source"]
    note2 = _error_note(d2)
    if note2:
        problems.append(f"doc 2 rejected: {note2}")
    if d2.get("user.name") != tok("USER", "dave"):
        problems.append(f"doc 2 user.name -> {d2.get('user.name')!r} (expected {tok('USER', 'dave')!r})")
    msg2 = d2.get("message")
    if not isinstance(msg2, str):
        problems.append("doc 2 message missing after simulate")
    else:
        dave_tok = tok("USER", "dave")
        if dave_tok not in msg2:
            problems.append(
                "doc 2: uid=dave did not map to the user.name token "
                f"({dave_tok!r} not in message)"
            )
        if "dave" in msg2:
            problems.append("doc 2 message still contains raw 'dave'")
        ip_tok = tok("IP", "10.20.30.40")
        if ip_tok not in msg2 or "10.20.30.40" in msg2:
            problems.append("doc 2 message did not mask 10.20.30.40")

    # ---- Doc 3: no personal data -> no-op ----
    d3, raw3 = sources[2], docs[2]["_source"]
    note3 = _error_note(d3)
    if note3:
        problems.append(f"doc 3 rejected: {note3}")
    if d3.get("host.hostname") != tok("HOST", "server42"):
        problems.append(f"doc 3 host.hostname -> {d3.get('host.hostname')!r}")
    if d3.get("message") != raw3["message"]:
        problems.append(
            f"doc 3 no-op message changed: {d3.get('message')!r}"
        )

    # ---- Doc 4: dot/digit-heavy free text (regex-limit regression) ----
    d4, raw4 = sources[3], docs[3]["_source"]
    note4 = _error_note(d4)
    if note4:
        problems.append(f"doc 4 rejected: {note4}")
    msg4 = d4.get("message")
    if not isinstance(msg4, str):
        problems.append("doc 4 message missing after simulate")
    else:
        ips = ("10.0.0.1", "10.0.0.2", "192.168.1.10", "203.0.113.5")
        for ip in ips:
            if tok("IP", ip) not in msg4 or ip in msg4:
                problems.append(f"doc 4 did not mask IP {ip!r}")

    return problems


# --------------------------------------------------------------------------- #
# Orchestration + CLI
# --------------------------------------------------------------------------- #


async def _run_live_test(
    cfg: Any,
    live: LiveIndexerConfig,
    salt: str,
) -> tuple[str, bool]:
    """Run Stage A + Stage B against the live indexer; `(report, ok)`."""
    lines: list[str] = []
    lines.append(f"masking test[{cfg.tenant}] live indexer: {safe_url(live.url)}")

    script = build_pipeline(cfg, salt)["processors"][0]["script"]["source"]

    # Offline structural fast-fail (functions before statements, no ctx['_source']).
    structural = verify_script_structure(script)
    if structural:
        lines.append("FAIL (offline structure check, before any HTTP):")
        lines.extend(f"  {p}" for p in structural)
        return "\n".join(lines), False

    if _url_has_embedded_credentials(live.url):
        lines.append(
            "WARNING: KLAXON_INDEXER_URL contains embedded credentials; use "
            "KLAXON_INDEXER_USER/PASSWORD instead (embedded credentials are "
            "never printed)."
        )
    if not live.verify_ssl:
        lines.append(
            "WARNING: KLAXON_INDEXER_VERIFY_SSL=false — TLS verification is "
            "DISABLED. Use it only against a self-signed lab cluster; for "
            "anything else trust the cluster CA (SSL_CERT_FILE / system trust "
            "store) instead."
        )

    async with httpx.AsyncClient(
        base_url=live.url,
        auth=(live.user, live.password),
        verify=live.verify_ssl,
        timeout=_TIMEOUT,
        headers={"Content-Type": "application/json"},
    ) as client:
        # Stage A — ingest allowlist preflight. `_execute` cannot compile an
        # ingest script (its painless_test context lacks the ingest-only
        # String.sha256() augmentation), so the authoritative compile check is
        # Stage B's _simulate; Stage A verifies the cluster CAN compile it.
        ok, detail = await stage_a_ingest_allowlist(client)
        lines.append(
            "Stage A — ingest allowlist preflight (context=ingest): "
            f"{'ok' if ok else 'FAIL'}"
        )
        lines.append(f"  {detail}")
        if not ok:
            return "\n".join(lines), False

        # Stage B — pipeline simulate (authoritative compile + behaviour check).
        pipeline = build_pipeline(cfg, salt)
        docs = live_test_docs()
        try:
            sources, errors = await stage_b_simulate(client, pipeline, docs)
        except LiveTestError as exc:
            lines.append("Stage B — pipeline simulate (_simulate): FAIL")
            lines.append(f"  {exc}")
            return "\n".join(lines), False
        lines.append(
            f"Stage B — pipeline simulate (_simulate): {len(docs)} doc(s), "
            f"{len(errors)} failure(s)"
        )
        for i, err in enumerate(errors):
            lines.append(f"  doc {i + 1}: {err}")

        problems = check_simulated(sources, cfg, salt)
        if problems:
            lines.append("Stage B — masking behaviour: FAIL")
            lines.extend(f"  {p}" for p in problems)
            return "\n".join(lines), False

        lines.append(
            "ok: pipeline compiles and masks correctly on the live indexer "
            "(same token for user.name and uid=, arrays element-wise, "
            "event.original single token, related.hash untouched, idempotent)."
        )
        return "\n".join(lines), True


def _error_detail(resp: httpx.Response) -> str:
    """A safe one-line description of an indexer error response. Only reasons
    are extracted — the raw body (and anything that could echo params) is never
    included, so the password/salt cannot leak."""
    try:
        payload = resp.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        err = payload.get("error")
        if isinstance(err, dict):
            reason = err.get("reason")
            caused = err.get("caused_by")
            if isinstance(caused, dict) and caused.get("reason"):
                reason = f"{reason}: {caused['reason']}"
            if reason:
                return str(reason)[:500]
    text = (resp.text or "")[:300]
    return text or "(no error detail in response)"


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="klaxon masking test",
        description=(
            "LIVE integration test for the generated masking pipeline: Stage A "
            "verifies the ingest Painless allowlist has the APIs the script "
            "needs (GET /_scripts/painless/_context), Stage B simulates it via "
            "POST /_ingest/pipeline/_simulate (the authoritative compile + "
            "behaviour check). Nothing is written or deployed. Credentials come "
            "ONLY from KLAXON_INDEXER_URL/USER/PASSWORD (or a gitignored local "
            ".env file); the password is never logged. Skips cleanly when the "
            "credentials are unset."
        ),
    )
    parser.add_argument(
        "--tenant", metavar="TENANT", required=True, help="Tenant to test (fields.yaml)."
    )
    parser.add_argument(
        "--root", type=Path, default=None, help="Repo root (default: auto)."
    )
    parser.add_argument(
        "--env",
        metavar="FILE",
        default=None,
        help="Local dotenv file with KLAXON_INDEXER_* vars (default: first "
        "existing of .env.live, tests/live/.env).",
    )
    parser.add_argument("--salt", metavar="SALT", default=None, help="Explicit test salt.")
    parser.add_argument(
        "--salt-env",
        metavar="VAR",
        default=None,
        help="Env var name for the salt (default: salt_env from fields.yaml).",
    )
    return parser.parse_args(argv)


def test_main(argv: list[str] | None = None) -> int:
    """Console entry for `klaxon masking test`. Exit 0 = pass, 1 = live failure,
    2 = skipped (credentials missing) or bad tenant."""
    args = _parse_args(argv)
    try:
        cfg = load_tenant_config(args.tenant, args.root)
    except (FileNotFoundError, ValueError) as exc:
        print(f"masking test[{args.tenant}] error: {exc}", file=sys.stderr)
        return 2

    live, missing = resolve_live_config(args.env)
    if live is None:
        print(
            f"masking test[{args.tenant}] SKIPPED — live indexer credentials "
            f"not set. Missing: {', '.join(missing)}. Set them in the "
            "environment or in a local .env file (see tests/live/.env.example). "
            "The password is never logged.",
            file=sys.stderr,
        )
        return 2

    salt = live_salt(cfg, args.salt, args.salt_env)
    report, ok = asyncio.run(_run_live_test(cfg, live, salt))
    print(report)
    return 0 if ok else 1
