# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""`klaxon masking` — the single generator for the Option B masked stream.

Reads `tenants/<tenant>/fields.yaml` (the single source of truth) and builds the
deployable artifacts — WITHOUT writing anything to the indexer (Klaxon stays a
read-only proxy; deploying the artifacts is the operator's/CI's job):

  (a) the Klaxon config fragment (`anonymization.mask_fields` +
      `gdpr_checker.custom_patterns`)   -> klaxon-config.yaml
  (b) the ingest pipeline JSON          -> pipeline-klaxon-mask-<tenant>.json
      (`PUT /_ingest/pipeline/klaxon-mask-<tenant>`)
  (c) the ISM retention policy JSON     -> ism-klaxon-masked-retention-<tenant>.json
      (`PUT /_plugins/_ism/policies/klaxon-masked-retention-<tenant>`)
  (d) the index template JSON           -> index-template-klaxon-masked-<tenant>.json
      (`PUT /_index_template/klaxon-masked-<tenant>`)

Commands (wired into `klaxon-mcp` / `klaxon`):

  * `klaxon masking generate --tenant X [--out DIR] [--stdout] [--check]`
      generate:   write the DEPLOYABLE artifact set (real salt in
                  `params.salt`) into `--out DIR` (or print to stdout with
                  `--stdout` / `--out -`). Default (no `--out`/`--stdout`)
                  writes the COMMITTED artifact set (pipeline template with
                  `params.salt = "__SALT__"`, secret-free) into
                  `tenants/<tenant>/generated/` — this is what CI drift-checks.
      --check:    no writes; compare the committed artifacts against fields.yaml
                  and exit non-zero on drift (CI / pre-commit / verify-config).
  * `klaxon masking selftest` — prove the generated Painless token scheme is
      byte-identical to `derive_token` (runs automatically inside `generate`;
      on ANY mismatch generation aborts and emits NO artifacts).
  * `klaxon masking salt-check --tenant X` — compare the salt baked into the
      DEPLOYED pipeline (`GET /_ingest/pipeline/klaxon-mask-<tenant>`) with the
      current `KLAXON_ANONYMIZATION_SALT`; mismatch is an error (tokens would
      no longer be deterministic across deploys).

The salt is read from the SAME environment variable as the response layer
(`KLAXON_ANONYMIZATION_SALT`, or `salt_env` from fields.yaml). Unset ->
a random salt is generated and a WARNING emitted: tokens change if the salt is
not stable, so previously written masked documents stop correlating.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

from .artifact_io import (
    CONFIG_FRAGMENT_NAME,
    INDEX_TEMPLATE_FILE,
    ISM_POLICY_FILE,
    PIPELINE_TEMPLATE_NAME,
    check_artifacts,
    generated_dir,
    generated_paths,
    render_artifacts,
    render_deployable,
    tenants_in_repo,
    write_artifacts,
    write_deployable,
)
from .masked_stream import (
    DEFAULT_RETENTION_DAYS,
    TenantConfig,
    build_pipeline,
    derive_token,
    find_repo_root,
    load_tenant_config,
    resolve_salt,
)
from .selftest import (
    SELF_TEST_VALUES,
    TokenSchemeError,
    _selftest_salt,
    painless_token_reference,
    verify_script_scheme,
    verify_script_structure,
)
from .tokens import TOKEN_RE

# Explicit re-export for mypy strict: these are the names other modules and
# tests import from klaxon_mcp.masking.
__all__ = [
    "CONFIG_FRAGMENT_NAME",
    "INDEX_TEMPLATE_FILE",
    "ISM_POLICY_FILE",
    "PIPELINE_TEMPLATE_NAME",
    "SELF_TEST_VALUES",
    "TOKEN_RE",
    "TokenSchemeError",
    "build_pipeline",
    "check_artifacts",
    "check_deployed_salt",
    "deployed_pipeline_salt",
    "generate_main",
    "generated_dir",
    "generated_paths",
    "painless_token_reference",
    "render_artifacts",
    "render_deployable",
    "run_generator_selftest",
    "run_token_selftest",
    "selftest_main",
    "tenants_in_repo",
    "verify_script_scheme",
    "verify_script_structure",
    "write_artifacts",
    "write_deployable",
]

# --------------------------------------------------------------------------- #
# Token-schema self-test (mandatory)
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Deploy-time salt comparison
# --------------------------------------------------------------------------- #


def deployed_pipeline_salt(pipeline: dict[str, Any]) -> str | None:
    """The salt baked into a deployed pipeline, or None if unreadable.

    Reads `processors[].script.params.salt` (the current format). Falls back to
    parsing a legacy `def SALT = "..."` embedded in the script source so
    pipelines deployed before the `params.salt` change still compare cleanly.
    """
    for proc in pipeline.get("processors") or []:
        if not isinstance(proc, dict):
            continue
        script = proc.get("script")
        if not isinstance(script, dict):
            continue
        params = script.get("params")
        if isinstance(params, dict) and isinstance(params.get("salt"), str):
            return str(params["salt"])
        source = script.get("source")
        if isinstance(source, str):
            legacy = re.search(r'def SALT = "([^"]*)";', source)
            if legacy:
                return str(legacy.group(1))
    return None


def check_deployed_salt(deployed: dict[str, Any], current_salt: str) -> tuple[bool, str]:
    """Compare the deployed pipeline's baked salt with the current env salt.

    Returns `(ok, message)`. A mismatch means tokens written by the deployed
    pipeline no longer match a fresh generate/apply — determinism is lost, so it
    is surfaced as an error. Only a 4-char prefix of each salt is shown, so the
    secret never reaches the log.
    """
    deployed_salt = deployed_pipeline_salt(deployed)
    if deployed_salt is None:
        return (
            False,
            (
                "deployed pipeline carries no readable salt "
                f"(unexpected structure: {sorted(deployed)})."
            ),
        )
    if deployed_salt == current_salt:
        return (
            True,
            (
                "deployed pipeline salt matches the current "
                f"{_prefix(current_salt)} (params.salt present; tokens stay "
                "deterministic)."
            ),
        )
    return (
        False,
        (
            "SALT MISMATCH: deployed pipeline baked "
            f"{_prefix(deployed_salt)}, current env salt is "
            f"{_prefix(current_salt)}. Tokens from the deployed pipeline will "
            "NOT match a fresh generate/apply. Re-deploy with the same "
            "KLAXON_ANONYMIZATION_SALT."
        ),
    )


def _prefix(salt: str) -> str:
    return f"{salt[:4]}…"


# --------------------------------------------------------------------------- #
# Mandatory self-test
#
# The run_* entry points live HERE (not in selftest.py) on purpose: the tests
# monkeypatch `masking.derive_token` and `masking.build_pipeline` to prove the
# self-test fails when the scheme or the rendered script diverges, which only
# works while the entry points resolve those names through this module's
# namespace. The pure predicates they call (verify_script_scheme,
# verify_script_structure, painless_token_reference) live in selftest.py.
# --------------------------------------------------------------------------- #


def run_token_selftest(salt: str) -> list[str]:
    """Byte-compare the Painless reference with `derive_token`; return mismatch lines."""
    mismatches: list[str] = []
    for value, family in SELF_TEST_VALUES:
        expected = derive_token(value, family, salt)
        actual = painless_token_reference(family, value, salt)
        if expected != actual:
            mismatches.append(
                f"  family={family} value={value!r}: derive_token -> {expected!r} "
                f"but Painless reference -> {actual!r}"
            )
    return mismatches


def run_generator_selftest(cfg: TenantConfig, salt: str) -> list[str]:
    """The mandatory self-test for `generate`: token identity + rendered script.

    Returns a list of problems (empty = pass). On any problem the generator
    MUST abort and emit NO artifacts.
    """
    problems = run_token_selftest(salt)
    script = build_pipeline(cfg, salt)["processors"][0]["script"]
    if script.get("params", {}).get("salt") != salt:
        problems.append(
            f"  pipeline params.salt mismatch: expected {salt!r}, got "
            f"{script.get('params', {}).get('salt')!r}"
        )
    problems.extend(verify_script_scheme(script["source"]))
    problems.extend(verify_script_structure(script["source"]))
    return problems


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _parse_generate_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="klaxon masking generate",
        description=(
            "Build the Option B masking artifacts from tenants/<tenant>/fields.yaml "
            "(no writes to the indexer — deploying is the operator's/CI's job)."
        ),
    )
    parser.add_argument("--tenant", metavar="TENANT", help="Tenant to generate.")
    parser.add_argument(
        "--out",
        metavar="DIR",
        help="Write the DEPLOYABLE artifact set (real salt in params.salt) into "
        "DIR. '-' prints them to stdout (same as --stdout).",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the deployable artifact set to stdout instead of writing files.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="No writes: compare the committed tenants/<tenant>/generated/* "
        "artifacts against fields.yaml and exit non-zero on drift (CI/pre-commit).",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=None,
        metavar="N",
        help="ISM delete-after retention for the masked stream (default 30).",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repo root (default: nearest ancestor of the working directory "
        "that contains tenants/).",
    )
    parser.add_argument(
        "--salt",
        metavar="SALT",
        help="Explicit salt for the deployable pipeline (default: the "
        "KLAXON_ANONYMIZATION_SALT env var, or salt_env from fields.yaml).",
    )
    parser.add_argument(
        "--salt-env",
        metavar="VAR",
        help="Override the env var name (default: salt_env from fields.yaml, "
        "else KLAXON_ANONYMIZATION_SALT).",
    )
    return parser.parse_args(argv)


def _generate_one(
    tenant: str, root: Path, args: argparse.Namespace, retention_days: int
) -> int:
    try:
        cfg = load_tenant_config(tenant, root)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[{tenant}] error: {exc}", file=sys.stderr)
        return 1

    salt_env = args.salt_env or cfg.salt_env
    if args.check:
        # --check emits nothing, so no real salt is baked; keep CI silent.
        salt = _selftest_salt(args.salt, salt_env)
    else:
        salt = args.salt if args.salt is not None else resolve_salt(salt_env)

    # MANDATORY self-test: prove the Painless scheme is byte-identical to
    # derive_token BEFORE emitting anything. On any problem: abort, no artifacts.
    problems = run_generator_selftest(cfg, salt)
    if problems:
        print(
            f"[{tenant}] SELF-TEST FAILED — no artifacts emitted:", file=sys.stderr
        )
        for problem in problems:
            print(problem, file=sys.stderr)
        print(
            f"[{tenant}] The generated Painless token scheme diverged from "
            "derive_token (see masked_stream._painless_script / masking.py). "
            "Fix the generator or revert the derive_token change before "
            "generating.",
            file=sys.stderr,
        )
        return 1

    if args.check:
        mismatches = check_artifacts(cfg, retention_days=retention_days)
        if mismatches:
            print(f"[{tenant}] FAIL", file=sys.stderr)
            for line in mismatches:
                print(f"  {line}", file=sys.stderr)
            return 1
        print(f"[{tenant}] ok: generated artifacts match fields.yaml")
        return 0

    if args.stdout or args.out == "-":
        print(
            f"[{tenant}] deployable artifacts (real salt in params.salt) — "
            "deploy to the indexer manually:"
        )
        for name, content in render_deployable(
            cfg, salt, retention_days=retention_days
        ).items():
            print(f"# ====== {name} ======")
            sys.stdout.write(content)
        return 0

    if args.out:
        written = write_deployable(cfg, args.out, salt, retention_days=retention_days)
        print(
            f"[{tenant}] wrote deployable artifacts (real salt) to "
            f"{Path(args.out).resolve()}:"
        )
        for path in written:
            print(f"  {path}")
        return 0

    # Default: the committed (secret-free) artifact set into the conventional dir.
    written = write_artifacts(cfg, retention_days=retention_days)
    print(f"[{tenant}] wrote committed artifacts to {generated_dir(cfg)}:")
    for path in written:
        print(f"  {path}")
    return 0


def generate_main(argv: list[str] | None = None) -> int:
    args = _parse_generate_args(argv)
    root = args.root or find_repo_root()
    retention_days = args.retention_days or DEFAULT_RETENTION_DAYS

    if args.out or args.stdout:
        if not args.tenant:
            print(
                "--tenant is required with --out/--stdout (multiple tenants "
                "cannot share one deployable output).",
                file=sys.stderr,
            )
            return 2
        return _generate_one(args.tenant, root, args, retention_days)

    tenants = [args.tenant] if args.tenant else tenants_in_repo(root)
    if not tenants:
        print("no tenants found (tenants/*/fields.yaml)", file=sys.stderr)
        return 1

    failed = False
    for tenant in tenants:
        if _generate_one(tenant, root, args, retention_days) != 0:
            failed = True
    return 1 if failed else 0


def _parse_selftest_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="klaxon masking selftest",
        description=(
            "Prove the Painless token scheme is byte-identical to "
            "derive_token(value, family, salt). Runs automatically inside "
            "`generate`; this command is for CI/debugging."
        ),
    )
    parser.add_argument(
        "--tenant",
        metavar="TENANT",
        help="Also render and validate that tenant's pipeline script "
        "(scheme markers + params.salt).",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repo root (default: nearest ancestor with tenants/).",
    )
    parser.add_argument("--salt", metavar="SALT", help="Explicit salt.")
    parser.add_argument(
        "--salt-env", metavar="VAR", help="Env var name (default: "
        "KLAXON_ANONYMIZATION_SALT)."
    )
    return parser.parse_args(argv)


def selftest_main(argv: list[str] | None = None) -> int:
    args = _parse_selftest_args(argv)
    salt_env = args.salt_env or "KLAXON_ANONYMIZATION_SALT"
    salt = _selftest_salt(args.salt, salt_env)

    problems: list[str] = []
    if args.tenant:
        try:
            cfg = load_tenant_config(args.tenant, args.root or find_repo_root())
        except (FileNotFoundError, ValueError) as exc:
            print(f"selftest[{args.tenant}] error: {exc}", file=sys.stderr)
            return 2
        problems.extend(run_generator_selftest(cfg, salt))
    else:
        problems.extend(run_token_selftest(salt))

    if problems:
        print(
            "klaxon masking selftest FAILED — Painless token scheme diverged "
            "from derive_token:",
            file=sys.stderr,
        )
        for p in problems:
            print(p, file=sys.stderr)
        return 1
    detail = f" (tenant {args.tenant})" if args.tenant else ""
    print(
        f"klaxon masking selftest ok{detail}: {len(SELF_TEST_VALUES)} "
        "value/family pairs, Painless == derive_token byte-for-byte"
    )
    return 0
