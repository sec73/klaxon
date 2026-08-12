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
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from .masked_stream import (
    DEFAULT_RETENTION_DAYS,
    TOKEN_RE,
    TenantConfig,
    _FREETEXT_PATTERN_ORDER,
    build_config_fragment,
    build_index_template,
    build_ism_policy,
    build_pipeline,
    derive_token,
    find_repo_root,
    load_tenant_config,
    resolve_salt,
)

CONFIG_FRAGMENT_NAME = "klaxon-config.yaml"
# Filename templates, one per artifact. `pipeline`/`ism`/`template` are the
# cfg.*_name values, so the files line up with the OpenSearch resource names.
PIPELINE_TEMPLATE_NAME = "pipeline-{pipeline}.json"
ISM_POLICY_FILE = "ism-{policy}.json"
INDEX_TEMPLATE_FILE = "index-template-{template}.json"


# --------------------------------------------------------------------------- #
# Artifact set
# --------------------------------------------------------------------------- #


def _artifact_contents(
    cfg: TenantConfig, *, salt: str, retention_days: int
) -> dict[str, str]:
    """relative filename -> serialised artifact content (deterministic)."""
    return {
        CONFIG_FRAGMENT_NAME: build_config_fragment(cfg),
        PIPELINE_TEMPLATE_NAME.format(pipeline=cfg.pipeline_name): json.dumps(
            build_pipeline(cfg, salt), indent=2
        )
        + "\n",
        ISM_POLICY_FILE.format(policy=cfg.ism_policy_name): json.dumps(
            build_ism_policy(cfg, retention_days), indent=2
        )
        + "\n",
        INDEX_TEMPLATE_FILE.format(template=cfg.index_template_name): json.dumps(
            build_index_template(cfg), indent=2
        )
        + "\n",
    }


def generated_dir(cfg: TenantConfig) -> Path:
    # Derive from the source file path so the repo root the tenant was loaded
    # with (cwd default or --root) is honoured — `find_repo_root()` alone would
    # ignore --root for the output paths.
    return Path(cfg.source_path).resolve().parent / "generated"


def generated_paths(cfg: TenantConfig) -> tuple[Path, Path, Path, Path]:
    """The four committed artifact paths under tenants/<tenant>/generated/."""
    d = generated_dir(cfg)
    return (
        d / CONFIG_FRAGMENT_NAME,
        d / PIPELINE_TEMPLATE_NAME.format(pipeline=cfg.pipeline_name),
        d / ISM_POLICY_FILE.format(policy=cfg.ism_policy_name),
        d / INDEX_TEMPLATE_FILE.format(template=cfg.index_template_name),
    )


def render_artifacts(
    cfg: TenantConfig, *, retention_days: int = DEFAULT_RETENTION_DAYS
) -> dict[str, str]:
    """The committed (CI-diffable) artifact set: absolute path -> content.

    The pipeline is the SALT-FREE template (`params.salt = "__SALT__"`), so the
    secret never enters version control. `--check` and `verify-config` compare a
    fresh regeneration against these files.
    """
    contents = _artifact_contents(cfg, salt="__SALT__", retention_days=retention_days)
    return {
        str(generated_dir(cfg) / name): content for name, content in contents.items()
    }


def render_deployable(
    cfg: TenantConfig,
    salt: str,
    *,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> dict[str, str]:
    """The deployable artifact set (relative filename -> content).

    The pipeline carries the REAL salt in `params.salt` — this is what an
    operator PUTs to the indexer (`--out DIR` / `--stdout`).
    """
    return _artifact_contents(cfg, salt=salt, retention_days=retention_days)


def write_artifacts(
    cfg: TenantConfig, *, retention_days: int = DEFAULT_RETENTION_DAYS
) -> list[Path]:
    """Write the committed artifact set to tenants/<tenant>/generated/."""
    written: list[Path] = []
    for path, content in render_artifacts(cfg, retention_days=retention_days).items():
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        written.append(p)
    return written


def write_deployable(
    cfg: TenantConfig,
    out_dir: str | Path,
    salt: str,
    *,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> list[Path]:
    """Write the deployable artifact set into `out_dir` (created if needed)."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, content in render_deployable(
        cfg, salt, retention_days=retention_days
    ).items():
        p = out / name
        p.write_text(content, encoding="utf-8")
        written.append(p)
    return written


def check_artifacts(
    cfg: TenantConfig, *, retention_days: int = DEFAULT_RETENTION_DAYS
) -> list[str]:
    """Compare regenerated artifacts with the committed files; return mismatches.

    A hand-edit to a generated artifact that is not reflected in fields.yaml
    shows up here, which is what CI, the pre-commit hook and `verify-config` gate
    on.
    """
    mismatches: list[str] = []
    for path, content in render_artifacts(cfg, retention_days=retention_days).items():
        p = Path(path)
        if not p.exists():
            mismatches.append(
                f"{path}: MISSING (run `klaxon masking generate --tenant "
                f"{cfg.tenant}`)"
            )
            continue
        existing = p.read_text(encoding="utf-8")
        if existing != content:
            mismatches.append(
                f"{path}: DRIFT — regenerated output differs from the committed "
                "file. Edit tenants/<tenant>/fields.yaml and re-run the generator."
            )
    return mismatches


def tenants_in_repo(root: Path) -> list[str]:
    base = root / "tenants"
    if not base.is_dir():
        return []
    return sorted(
        p.name
        for p in base.iterdir()
        if p.is_dir() and (p / "fields.yaml").exists()
    )


# --------------------------------------------------------------------------- #
# Token-schema self-test (mandatory)
# --------------------------------------------------------------------------- #


class TokenSchemeError(Exception):
    """The Painless token scheme diverged from `derive_token` — generation aborts."""


# Representative values per family the self-test pins the scheme on. These are
# deliberately independent of any tenant's fields.yaml: they exercise every
# family, a UUID, an agent id, an empty value and an already-tokenised value
# (idempotency).
SELF_TEST_VALUES: tuple[tuple[str, str], ...] = (
    ("marcomoenig", "USER"),
    ("jdoe", "USER"),
    ("root(uid=0)", "USER"),
    ("550e8400-e29b-41d4-a716-446655440000", "USER"),  # UUID string
    ("müller", "USER"),  # non-ASCII
    ("nc02web", "HOST"),
    ("web-01.example.com", "HOST"),
    ("192.168.50.42", "IP"),
    ("10.0.0.1", "IP"),
    ("2001:db8::1", "IP"),
    ("001", "AGENT"),
    ("c2f7c1a4-9e4b-4c0a-8f6a-5b2d7e1a3c90", "AGENT"),  # agent id
    ("", "USER"),  # empty value stays unchanged
    ("[USER_7570f69ace298df1]", "USER"),  # already a token -> idempotent
)


def painless_token_reference(family: str, value: str, salt: str) -> str:
    """Byte-exact Python transcription of the Painless `token()`/`sha256hex()`.

    Written as a SEPARATE code path from `derive_token()` on purpose: the
    self-test runs both over the representative values and aborts on ANY
    mismatch, so a scheme change in one without the other is caught at generate
    time — changing `derive_token` breaks generation, not the deployed pipeline.
    """
    if value is None:
        return value
    if not value:
        return value  # empty stays empty — mirrors the script's value.isEmpty()
    if TOKEN_RE.fullmatch(value):
        return value  # idempotent passthrough, mirrors the script
    # SHA-256 over `family:value:salt`, first 8 digest bytes -> 16 hex chars.
    digest = hashlib.sha256(f"{family}:{value}:{salt}".encode()).digest()
    return f"[{family}_{digest[:8].hex()}]"


# The token-scheme markers the rendered Painless source MUST contain. If any is
# missing, the script does not implement the scheme `derive_token` implements.
_SCHEME_MARKERS: tuple[str, ...] = (
    "def SALT = params.salt;",
    "if (value.isEmpty()) return value;",
    ".sha256().substring(0, 16)",  # SHA-256, first 16 hex chars
    'sha256hex(family + ":" + value + ":" + SALT)',
    '"[" + family + "_" + sha256hex(family + ":" + value + ":" + SALT) + "]"',
    "Pattern TOKEN_RE()",
    r"^\[(?:IP|USER|HOST|AGENT)_[0-9a-f]{16}\]$",  # the idempotency regex literal
)


def verify_script_scheme(script: str) -> list[str]:
    """Token-scheme markers MISSING from a rendered Painless script.

    Binds the self-test to the actual generated artifact: the script must encode
    exactly the scheme `derive_token` implements (SHA-256 over
    `family:value:salt`, UTF-8, first 16 hex chars, `[FAMILY_<hex>]` display,
    idempotent passthrough, salt injected via `params.salt`). Empty result = the
    script encodes the scheme.
    """
    return [marker for marker in _SCHEME_MARKERS if marker not in script]


# The function declarations the rendered Painless script MUST define: (name,
# return type). The free-text regexes are emitted as `Pattern <NAME>()`
# functions and TOKEN_RE() as a `Pattern` function, matching the live-verified
# shape (`Pattern.compile`/`MessageDigest` are not whitelisted on restricted
# clusters; regex literals in functions are).
_PAINLESS_FUNCTIONS: tuple[tuple[str, str], ...] = (
    ("sha256hex", "String"),
    ("token", "String"),
    ("TOKEN_RE", "Pattern"),
    ("maskPattern", "String"),
    ("isWordChar", "boolean"),
    ("replaceWordBoundary", "String"),
    ("maskRegistry", "String"),
    ("maskFreeText", "String"),
) + tuple((name, "Pattern") for name in _FREETEXT_PATTERN_ORDER)

# The top-level declarations the script emits (functions must precede these).
_PAINLESS_TOP_DECLS: tuple[str, ...] = (
    "def SALT =",
    "def FIELDS =",
    "def FREE_TEXT =",
)

# The first statement of the main logic, which must follow every declaration.
_MAIN_LOGIC_MARKER = "Map masked = new HashMap();"


def verify_script_structure(script: str) -> list[str]:
    """Structural compile-safety problems in a rendered Painless script.

    The scheme markers prove WHAT the script computes; these checks prove the
    script COMPILES the way the live `_execute`/`_simulate` test exercises it:

      * every function declaration precedes any top-level statement (Painless
        rejects functions after statements with `unexpected token ['(']`);
      * the declarations (`def SALT`/`FIELDS`/`FREE_TEXT`) precede the main logic;
      * no `ctx['_source']` remains — in an ingest script processor `ctx` IS the
        document, so `ctx['_source']` is null and NPEs on the first document.

    Empty result = structurally sound (the offline counterpart of the live
    compile check; see `klaxon masking test`).
    """
    problems: list[str] = []

    if "ctx['_source']" in script:
        problems.append(
            "script still references ctx['_source'] — in an ingest script "
            "processor ctx IS the document (no nested _source object); this "
            "NPEs on the first document once the script compiles."
        )

    def_positions = [script.find(decl) for decl in _PAINLESS_TOP_DECLS]
    first_statement = min((p for p in def_positions if p >= 0), default=-1)

    for name, rtype in _PAINLESS_FUNCTIONS:
        sig = f"{rtype} {name}("
        pos = script.find(sig)
        if pos < 0:
            problems.append(
                f"missing function declaration `{sig}...)` — the pipeline "
                "would fail to compile at ingest time."
            )
            continue
        if first_statement >= 0 and pos > first_statement:
            problems.append(
                f"function `{name}` is declared AFTER a top-level statement "
                f"(`{_PAINLESS_TOP_DECLS[0]}...`) — Painless requires ALL "
                "functions before any statement; the indexer rejects the "
                "pipeline with `unexpected token ['(']`."
            )

    main_pos = script.find(_MAIN_LOGIC_MARKER)
    if main_pos < 0:
        problems.append(
            f"main-logic marker `{_MAIN_LOGIC_MARKER}` not found — the emitted "
            "structure changed unexpectedly."
        )
    else:
        for decl, pos in zip(_PAINLESS_TOP_DECLS, def_positions):
            if pos < 0:
                problems.append(f"missing top-level declaration `{decl}`")
            elif pos > main_pos:
                problems.append(
                    f"declaration `{decl}` appears AFTER the main logic — the "
                    "script would use FIELDS/SALT before they are assigned."
                )
        if not any(
            f"Pattern {name}() {{" in script for name in _FREETEXT_PATTERN_ORDER
        ):
            problems.append(
                "no free-text Pattern functions found — the free-text pass "
                "references them by name and the script would fail to compile."
            )

    return problems


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


def _selftest_salt(salt: str | None, salt_env: str) -> str:
    """Salt for the self-test: explicit, else the env value, else a fixed test
    value. The self-test only proves scheme identity (salt-agnostic), so an
    unset env never warns here — a random salt warning only makes sense when a
    real salt is actually baked into a deployable artifact (see `generate`)."""
    if salt is not None:
        return salt
    env = os.environ.get(salt_env, "").strip()
    if env:
        return env
    return "klaxon-masking-selftest-fixed"


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
