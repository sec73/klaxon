# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Console entry point.

Defaults to stdio, which is what an MCP client spawning this process expects.
The HTTP transports exist for running the server on a different host from the
client — see the "Remote deployment" section of the README before using them.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from .config import ConfigError, TransportConfig
from .transport import serve


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="klaxon-mcp",
        description="Klaxon MCP — MCP server for Wazuh 5.x.",
        epilog=(
            "Every flag has an environment equivalent (WAZUH_MCP_TRANSPORT, "
            "WAZUH_MCP_HOST, WAZUH_MCP_PORT, WAZUH_MCP_PATH, "
            "WAZUH_MCP_AUTH_TOKEN, WAZUH_MCP_ALLOWED_HOSTS). Flags win."
        ),
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "http", "sse"],
        help="stdio (default) spawns under an MCP client; http serves streamable HTTP.",
    )
    parser.add_argument("--host", help="Bind address for http/sse. Default 127.0.0.1.")
    parser.add_argument("--port", type=int, help="Bind port for http/sse. Default 8000.")
    parser.add_argument("--path", help="HTTP endpoint path. Default /mcp.")
    parser.add_argument(
        "--allowed-host",
        action="append",
        dest="allowed_hosts",
        metavar="HOST",
        help="Permitted Host header value; repeatable. Enables DNS rebinding protection.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Default INFO.",
    )
    anonymization = parser.add_argument_group(
        "anonymization",
        "One-shot commands for the PII anonymization layer (GDPR). "
        "None of them require the Wazuh environment, and none of them serve.",
    )
    anonymization.add_argument(
        "--anonymization-status",
        action="store_true",
        help="Print whether anonymization is enabled and for which LLM, then exit.",
    )
    anonymization.add_argument(
        "--anonymization-report",
        nargs="?",
        const="",
        metavar="OUTFILE",
        help="Generate the DSGVO/GDPR compliance report. With OUTFILE, write it "
        "there instead of stdout.",
    )
    anonymization.add_argument(
        "--anonymization-export",
        nargs="?",
        const="",
        metavar="OUTFILE",
        help="Export the anonymized (MASKED/BLOCKED) prompt log — the artifact "
        "for data-subject access requests. RAW lines are dropped, so the export "
        "contains no unmasked personal data. With OUTFILE, write it there instead "
        "of stdout.",
    )
    masked_stream = parser.add_argument_group(
        "option b masked stream",
        "Generate/sync/verify the separate masked data stream. All resources are "
        "namespaced klaxon-*; the raw Wazuh streams are never modified. See "
        "docs/option-b-masked-stream.md.",
    )
    masked_stream.add_argument(
        "--tenant",
        metavar="TENANT",
        help="Tenant (directory under tenants/) whose fields.yaml is the source "
        "of truth, e.g. customer-a.",
    )
    masked_stream.add_argument(
        "--generate-masking",
        action="store_true",
        help="DEPRECATED — use `masking generate`. Regenerate the config "
        "fragment + pipeline template from tenants/<tenant>/fields.yaml "
        "(writes files; no Wazuh needed).",
    )
    masked_stream.add_argument(
        "--generate-masking-check",
        action="store_true",
        help="DEPRECATED — use `masking generate --check`. Verify committed "
        "generated artifacts match fields.yaml (no writes); exit non-zero on "
        "drift. Used by CI and pre-commit.",
    )
    masked_stream.add_argument(
        "--sync-masked",
        action="store_true",
        help="Reindex the recent window from wazuh-events-v5-* through the "
        "klaxon-mask-<tenant> pipeline into the masked stream (checkpoint + "
        "preflight). Needs the indexer.",
    )
    masked_stream.add_argument(
        "--verify-config",
        action="store_true",
        help="Drift audit: fields.yaml vs committed config fragment vs effective "
        "Klaxon config vs deployed pipeline. Exit non-zero on drift. Needs the indexer.",
    )
    masked_stream.add_argument(
        "--apply-masked-infra",
        action="store_true",
        help="PUT the masking pipeline (real salt), ISM policy, index template and "
        "data stream for a tenant. Needs the indexer.",
    )
    masked_stream.add_argument(
        "--overlap-hours",
        type=int,
        default=None,
        metavar="N",
        help="Sync overlap window (default 1h): docs within this much of the "
        "checkpoint are re-scanned to catch late arrivals.",
    )
    masked_stream.add_argument(
        "--initial-lookback-hours",
        type=int,
        default=None,
        metavar="N",
        help="First sync lookback when no checkpoint exists (default 24h).",
    )
    masked_stream.add_argument(
        "--retention-days",
        type=int,
        default=None,
        metavar="N",
        help="Masked-stream retention in days (default 30). Raw stream untouched.",
    )
    masked_stream.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would happen without writing or advancing checkpoints.",
    )
    gdpr = parser.add_argument_group(
        "gdpr check",
        "The DSGVO plausibility checker. Needs the Wazuh indexer "
        "(WAZUH_INDEXER_URL) and exits after running — it does not serve.",
    )
    gdpr.add_argument(
        "--gdpr-check",
        nargs="?",
        const="",
        metavar="INDEX",
        help="Run the DSGVO plausibility check and exit. INDEX defaults to "
        "wazuh-events-v5-* (or KLAXON_GDPR_INDEX).",
    )
    gdpr.add_argument(
        "--gdpr-prefix",
        metavar="PREFIX",
        help="Restrict the analysis to a field namespace, e.g. user. or source.",
    )
    gdpr.add_argument(
        "--gdpr-sample",
        type=int,
        default=None,
        metavar="N",
        help="Documents to sample for content analysis (default 10; 0 disables).",
    )
    gdpr.add_argument(
        "--gdpr-auto-add",
        action="store_true",
        help="Add the suggested fields to config.yaml without prompting.",
    )
    gdpr.add_argument(
        "--gdpr-dry-run",
        action="store_true",
        help="Show suggestions only; change nothing.",
    )
    gdpr.add_argument(
        "--gdpr-exclude",
        metavar="FIELDS",
        help="Comma-separated fields to skip (internal fields without GDPR "
        "relevance).",
    )
    gdpr.add_argument(
        "--gdpr-json",
        action="store_true",
        help="Emit the machine-readable JSON report instead of the table.",
    )
    gdpr.add_argument(
        "--gdpr-out",
        metavar="FILE",
        help="Write the JSON report to FILE (in addition to stdout).",
    )
    gdpr.add_argument(
        "--check-gdpr-on-startup",
        action="store_true",
        help="Run a non-interactive DSGVO check before serving. Applies the "
        "suggestions only when --gdpr-auto-add is set, else dry-runs.",
    )

    # `klaxon masking` — the single Option B generator + self-test + salt check.
    subparsers = parser.add_subparsers(
        dest="command", metavar="COMMAND", description="Subcommands."
    )
    masking_parser = subparsers.add_parser(
        "masking",
        help="Generate / verify the Option B masking artifacts (offline) and "
        "check the deployed salt. Supersedes the old --generate-masking flags.",
    )
    masking_sub = masking_parser.add_subparsers(
        dest="masking_command", metavar="SUBCOMMAND"
    )

    gen_parser = masking_sub.add_parser(
        "generate",
        help="Build the deployable artifacts from tenants/<tenant>/fields.yaml "
        "(no writes to the indexer).",
    )
    gen_parser.add_argument(
        "--tenant",
        metavar="TENANT",
        help="Tenant (directory under tenants/) whose fields.yaml is the source "
        "of truth, e.g. customer-a.",
    )
    gen_parser.add_argument(
        "--out",
        metavar="DIR",
        help="Write the DEPLOYABLE artifact set (real salt in params.salt) into "
        "DIR. '-' prints them to stdout (same as --stdout).",
    )
    gen_parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the deployable artifact set to stdout instead of writing files.",
    )
    gen_parser.add_argument(
        "--check",
        action="store_true",
        help="No writes: compare the committed tenants/<tenant>/generated/* "
        "artifacts against fields.yaml and exit non-zero on drift. Used by CI "
        "and the pre-commit hook.",
    )
    gen_parser.add_argument(
        "--retention-days",
        type=int,
        default=None,
        metavar="N",
        help="ISM delete-after retention for the masked stream (default 30).",
    )
    gen_parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repo root (default: nearest ancestor of the working directory that "
        "contains tenants/).",
    )
    gen_parser.add_argument(
        "--salt",
        metavar="SALT",
        help="Explicit salt for the deployable pipeline (default: the "
        "KLAXON_ANONYMIZATION_SALT env var, or salt_env from fields.yaml).",
    )
    gen_parser.add_argument(
        "--salt-env",
        metavar="VAR",
        help="Override the env var name (default: salt_env from fields.yaml, "
        "else KLAXON_ANONYMIZATION_SALT).",
    )

    selftest_parser = masking_sub.add_parser(
        "selftest",
        help="Prove the Painless token scheme is byte-identical to "
        "derive_token(value, family, salt). Runs inside `generate` too.",
    )
    selftest_parser.add_argument(
        "--tenant",
        metavar="TENANT",
        help="Also render and validate that tenant's pipeline script.",
    )
    selftest_parser.add_argument(
        "--root", type=Path, default=None, help="Repo root (default: auto)."
    )
    selftest_parser.add_argument("--salt", metavar="SALT", help="Explicit salt.")
    selftest_parser.add_argument(
        "--salt-env", metavar="VAR", help="Env var name (default: "
        "KLAXON_ANONYMIZATION_SALT)."
    )

    saltcheck_parser = masking_sub.add_parser(
        "salt-check",
        help="Compare the salt baked into the DEPLOYED pipeline with the current "
        "env salt. Needs the indexer.",
    )
    saltcheck_parser.add_argument(
        "--tenant",
        metavar="TENANT",
        required=True,
        help="Tenant whose deployed pipeline salt is compared.",
    )
    saltcheck_parser.add_argument(
        "--root", type=Path, default=None, help="Repo root (default: auto)."
    )
    saltcheck_parser.add_argument(
        "--salt-env",
        metavar="VAR",
        help="Env var name (default: salt_env from fields.yaml, else "
        "KLAXON_ANONYMIZATION_SALT).",
    )

    test_parser = masking_sub.add_parser(
        "test",
        help="LIVE integration test for the generated pipeline: Stage A "
        "verifies the ingest Painless allowlist has the APIs the script needs, "
        "Stage B simulates it via POST /_ingest/pipeline/_simulate (authoritative "
        "compile + behaviour check). No writes, nothing deployed. Needs the "
        "indexer (KLAXON_INDEXER_URL/USER/PASSWORD).",
    )
    test_parser.add_argument(
        "--tenant",
        metavar="TENANT",
        required=True,
        help="Tenant whose generated pipeline is tested.",
    )
    test_parser.add_argument(
        "--root", type=Path, default=None, help="Repo root (default: auto)."
    )
    test_parser.add_argument(
        "--env",
        metavar="FILE",
        default=None,
        help="Local dotenv file with KLAXON_INDEXER_* vars (default: first "
        "existing of .env.live, tests/live/.env).",
    )
    test_parser.add_argument(
        "--salt", metavar="SALT", default=None, help="Explicit test salt."
    )
    test_parser.add_argument(
        "--salt-env",
        metavar="VAR",
        default=None,
        help="Env var name for the salt (default: salt_env from fields.yaml).",
    )

    migrate_parser = masking_sub.add_parser(
        "migrate",
        help="ONE-TIME, operator-run migration of legacy klaxon.masking_error "
        "docs from the masked stream into the quarantine stream. Destructive "
        "(deletes from the masked stream) — never automated. Idempotent.",
    )
    migrate_parser.add_argument(
        "--tenant",
        metavar="TENANT",
        required=True,
        help="Tenant whose masked stream is migrated.",
    )
    migrate_parser.add_argument(
        "--root", type=Path, default=None, help="Repo root (default: auto)."
    )
    migrate_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without reindexing or deleting.",
    )

    deploy_parser = masking_sub.add_parser(
        "deploy",
        help="Deploy the Option B masking artifacts to the indexer in one "
        "idempotent, ordered, self-verifying step (pipeline, ISM policies, "
        "index templates, masked data stream, security roles). Needs admin "
        "indexer credentials (KLAXON_INDEXER_URL/USER/PASSWORD).",
    )
    deploy_parser.add_argument(
        "--tenant", metavar="TENANT", required=True, help="Tenant to deploy."
    )
    deploy_parser.add_argument(
        "--root", type=Path, default=None, help="Repo root (default: auto)."
    )
    deploy_parser.add_argument(
        "--env",
        metavar="FILE",
        default=None,
        help="Local dotenv file with KLAXON_INDEXER_* vars (default: first "
        "existing of .env.live, tests/live/.env).",
    )
    deploy_parser.add_argument(
        "--retention-days",
        type=int,
        default=None,
        metavar="N",
        help="Masked-stream ISM delete-after (default 30; quarantine always 90).",
    )
    deploy_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the full plan and preflight result WITHOUT writing anything.",
    )
    deploy_parser.add_argument(
        "--force",
        action="store_true",
        help="Proceed even if a sync job appears to be running/very recent.",
    )
    deploy_parser.add_argument(
        "--rollback",
        action="store_true",
        help="Re-deploy the last snapshot (tenants/<tenant>/generated/backup/"
        "<ts>/) via the same ordered path. Pipeline rollback is safe: no data "
        "loss, the sync job can simply re-run.",
    )
    return parser.parse_args(argv)


def _run_anonymization_command(args: argparse.Namespace) -> int:
    """Handle the one-shot anonymization commands without touching Wazuh."""
    from .anonymization import Anonymizer
    from .config import AnonymizationConfig, ConfigError

    try:
        config = AnonymizationConfig.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    anon = Anonymizer(config)

    if args.anonymization_status:
        print(anon.status_text())
        return 0

    if args.anonymization_report is not None:
        report = anon.report_text()
        if args.anonymization_report:
            try:
                with open(args.anonymization_report, "w", encoding="utf-8") as fh:
                    fh.write(report + "\n")
            except OSError as exc:
                print(f"report write failed: {exc}", file=sys.stderr)
                return 1
            print(f"report written to {args.anonymization_report}")
        else:
            print(report)
        return 0

    if args.anonymization_export is not None:
        text = Anonymizer.export_masked_log(
            config.log_path, args.anonymization_export or None
        )
        if text.startswith("export failed"):
            print(text, file=sys.stderr)
            return 1
        if args.anonymization_export:
            print(
                f"anonymized log exported to {args.anonymization_export} "
                f"(source: {config.log_path})"
            )
        else:
            print(text)
        return 0

    return 0


def _prompt_yes_no(prompt: str) -> bool:
    """Interactive confirmation; non-TTY input defaults to 'no' (change nothing)."""
    if not sys.stdin.isatty():
        return False
    try:
        answer = input(prompt).strip().lower()
    except EOFError:
        return False
    return answer in {"", "y", "yes"}


def _gdpr_check_once(
    *,
    index: str,
    prefix: str | None,
    sample: int,
    auto_add: bool,
    dry_run: bool,
    exclude: set[str],
    as_json: bool,
    out_file: str | None,
    interactive: bool,
) -> int:
    """Analyse an index and optionally merge the suggestions into config.yaml.

    Shared by `--gdpr-check`, `--check-gdpr-on-startup` and the
    `klaxon_check_gdpr` console script. Needs the Wazuh indexer.
    """
    from . import server
    from .config import Config, ConfigError
    from .gdpr import (
        apply_mask_fields,
        env_hint,
        render_json,
        run_check,
        write_compliance_report,
    )

    try:
        config = Config.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    already = set(server.get_anonymizer().config.mask_fields)
    try:
        result = asyncio.run(
            run_check(
                server.get_indexer(),
                index,
                prefix,
                sample,
                config.gdpr.custom_patterns,
                already,
                exclude,
            )
        )
    except RuntimeError as exc:
        print(f"gdpr check failed: {exc}", file=sys.stderr)
        return 1

    if result.caps_failed is not None:
        print(
            f"gdpr check failed: HTTP {result.caps_failed.status_code} for "
            f"{index!r}. The unmodified error body is below.",
            file=sys.stderr,
        )
        print(result.caps_failed.text[:500], file=sys.stderr)
        return 1

    if as_json:
        report = render_json(result)
        print(report)
        if out_file:
            try:
                with open(out_file, "w", encoding="utf-8") as fh:
                    fh.write(report + "\n")
            except OSError as exc:
                print(f"report write failed: {exc}", file=sys.stderr)
                return 1
    else:
        print(f"=== DSGVO PLAUSIBILITY CHECK ===")
        print(f"index:    {index}")
        print(
            f"checked:  {result.mapped_total} mapped field(s)"
            f" (sampled {sample} document(s) for content)"
        )
        print()
        from .gdpr import render_table

        print(render_table(result.sensitive))
        print()
        print(
            f"{len(result.sensitive)} DSGVO-relevant field(s); "
            f"{len(result.new_fields)} to add."
        )
        if result.new_fields:
            print(f"env equivalent: {env_hint(result.new_fields)}")
        print()

    # Decide what to apply. Non-interactive defaults to no change, which is the
    # safe reading: a check that quietly edits a config file is a surprise.
    to_add = list(result.new_fields)
    if to_add and not dry_run and not auto_add:
        if interactive:
            accepted: list[str] = []
            for field in result.sensitive:
                if field.already_configured:
                    continue
                if _prompt_yes_no(
                    f'Feld "{field.field}" ({field.kind}, {field.priority}) ist '
                    f"DSGVO-relevant. Zur Anonymisierungsliste hinzufügen? [Y/n] "
                ):
                    accepted.append(field.field)
            to_add = accepted
        else:
            print(
                "(non-interactive: use --gdpr-auto-add to apply, or --gdpr-dry-run)",
                file=sys.stderr,
            )
            to_add = []

    changed = False
    if to_add and not dry_run:
        changed, merged, warning = apply_mask_fields(
            config.gdpr.config_file, config.gdpr.log_path, index, to_add
        )
        if changed:
            print(
                f"config.yaml updated ({config.gdpr.config_file}): "
                f"{len(merged)} field(s) in mask_fields. Restart the server to "
                f"pick it up."
            )
        else:
            print("no fields added (all already configured or write failed).")
        if warning:
            print(f"warning: {warning}", file=sys.stderr)

    report_error = write_compliance_report(
        config.gdpr.report_path,
        {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "index": index,
            "checked_fields": result.mapped_total,
            "sensitive_fields_found": len(result.sensitive),
            "anonymization_updated": changed,
            "fields_added": to_add if changed else [],
        },
    )
    if report_error:
        print(report_error, file=sys.stderr)
        return 1

    if not to_add and not dry_run and not auto_add:
        print("dry run: no changes made. Re-run with --gdpr-auto-add to apply.")
    return 0


def _run_gdpr_command(args: argparse.Namespace) -> int:
    index = args.gdpr_check or os.environ.get(
        "KLAXON_GDPR_INDEX", "wazuh-events-v5-*"
    )
    sample = (
        args.gdpr_sample
        if args.gdpr_sample is not None
        else _default_gdpr_sample()
    )
    return _gdpr_check_once(
        index=index,
        prefix=args.gdpr_prefix,
        sample=sample,
        auto_add=args.gdpr_auto_add,
        dry_run=args.gdpr_dry_run,
        exclude=set(
            f.strip() for f in (args.gdpr_exclude or "").split(",") if f.strip()
        ),
        as_json=args.gdpr_json,
        out_file=args.gdpr_out,
        interactive=not args.gdpr_dry_run,
    )


def _default_gdpr_sample() -> int:
    from .config import GdprConfig

    return GdprConfig.from_env().sample_size


def gdpr_cli_main(argv: list[str] | None = None) -> int:
    """Console entry point `klaxon_check_gdpr`: the checker as a CLI tool.

    `klaxon-mcp --gdpr-check` is the same code with the same flags; this name
    exists for scripts that call the checker directly.
    """
    parser = argparse.ArgumentParser(
        prog="klaxon_check_gdpr",
        description="DSGVO plausibility checker for a Wazuh 5 index.",
    )
    parser.add_argument("--index", default="wazuh-events-v5-*", metavar="INDEX")
    parser.add_argument("--prefix", metavar="PREFIX")
    parser.add_argument("--sample", type=int, default=None, metavar="N")
    parser.add_argument("--auto-add", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--exclude", metavar="FIELDS")
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--out", metavar="FILE")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )

    return _gdpr_check_once(
        index=args.index,
        prefix=args.prefix,
        sample=args.sample if args.sample is not None else _default_gdpr_sample(),
        auto_add=args.auto_add,
        dry_run=args.dry_run,
        exclude=set(
            f.strip() for f in (args.exclude or "").split(",") if f.strip()
        ),
        as_json=args.as_json,
        out_file=args.out,
        interactive=not args.dry_run,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    # Logs go to stderr: on stdio, stdout carries the JSON-RPC stream and any
    # stray byte written there corrupts the session.
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        cfg = TransportConfig.from_env()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    overrides: dict[str, object] = {}
    if args.transport is not None:
        overrides["transport"] = args.transport
    if args.host is not None:
        overrides["host"] = args.host
    if args.port is not None:
        overrides["port"] = args.port
    if args.path is not None:
        overrides["path"] = args.path if args.path.startswith("/") else f"/{args.path}"
    if args.allowed_hosts:
        overrides["allowed_hosts"] = tuple(args.allowed_hosts)
    if overrides:
        cfg = replace(cfg, **overrides)  # type: ignore[arg-type]

    # The one-shot anonymization commands need no Wazuh environment and must
    # not be blocked by its absence, so they run before Config.from_env().
    if (
        args.anonymization_status
        or args.anonymization_report is not None
        or args.anonymization_export is not None
    ):
        return _run_anonymization_command(args)

    # Option B generator / self-test / salt check: `klaxon masking ...`.
    # Needs no Wazuh environment for generate/selftest (just files); salt-check
    # needs the indexer and is dispatched to sync_masked below.
    if args.command == "masking":
        from . import masking

        if args.masking_command == "generate":
            argv = ["--tenant", args.tenant] if args.tenant else []
            if args.out:
                argv += ["--out", args.out]
            if args.stdout:
                argv.append("--stdout")
            if args.check:
                argv.append("--check")
            if args.retention_days is not None:
                argv += ["--retention-days", str(args.retention_days)]
            if args.root is not None:
                argv += ["--root", str(args.root)]
            if args.salt:
                argv += ["--salt", args.salt]
            if args.salt_env:
                argv += ["--salt-env", args.salt_env]
            return masking.generate_main(argv)
        if args.masking_command == "selftest":
            argv = []
            if args.tenant:
                argv += ["--tenant", args.tenant]
            if args.root is not None:
                argv += ["--root", str(args.root)]
            if args.salt:
                argv += ["--salt", args.salt]
            if args.salt_env:
                argv += ["--salt-env", args.salt_env]
            return masking.selftest_main(argv)
        if args.masking_command == "salt-check":
            if not args.tenant:
                print(
                    "--tenant is required for `masking salt-check`",
                    file=sys.stderr,
                )
                return 2
            from . import sync_masked

            return sync_masked.salt_check_command(args.tenant)
        if args.masking_command == "test":
            from . import live_test

            argv = ["--tenant", args.tenant]
            if args.root is not None:
                argv += ["--root", str(args.root)]
            if args.env:
                argv += ["--env", args.env]
            if args.salt:
                argv += ["--salt", args.salt]
            if args.salt_env:
                argv += ["--salt-env", args.salt_env]
            return live_test.test_main(argv)
        if args.masking_command == "migrate":
            if not args.tenant:
                print(
                    "--tenant is required for `masking migrate`",
                    file=sys.stderr,
                )
                return 2
            from . import sync_masked

            return sync_masked.migrate_quarantine_command(
                args.tenant, dry_run=args.dry_run
            )
        if args.masking_command == "deploy":
            if not args.tenant:
                print(
                    "--tenant is required for `masking deploy`",
                    file=sys.stderr,
                )
                return 2
            from . import deploy

            argv = ["--tenant", args.tenant]
            if args.root is not None:
                argv += ["--root", str(args.root)]
            if args.env:
                argv += ["--env", args.env]
            if args.retention_days is not None:
                argv += ["--retention-days", str(args.retention_days)]
            if args.dry_run:
                argv.append("--dry-run")
            if args.force:
                argv.append("--force")
            if args.rollback:
                argv.append("--rollback")
            return deploy.deploy_main(argv)
        print(
            "masking: missing subcommand "
            "(generate|selftest|salt-check|test|migrate|deploy)",
            file=sys.stderr,
        )
        return 2

    # Deprecated legacy aliases for the generator — superseded by
    # `masking generate` / `masking generate --check` (same code path).
    if args.generate_masking or args.generate_masking_check:
        from . import masking

        argv = []
        if args.tenant:
            argv += ["--tenant", args.tenant]
        if args.generate_masking_check:
            argv.append("--check")
        return masking.generate_main(argv)

    # The DSGVO plausibility check needs the Wazuh indexer but not the MCP
    # listener; it runs and exits.
    if args.gdpr_check is not None:
        return _run_gdpr_command(args)

    # Option B operational commands (need the indexer, not the MCP listener).
    if args.sync_masked or args.verify_config or args.apply_masked_infra:
        if not args.tenant:
            print(
                "--tenant is required for the masked-stream commands",
                file=sys.stderr,
            )
            return 2
        from . import sync_masked

        if args.sync_masked:
            return sync_masked.sync_command(
                args.tenant,
                overlap_hours=args.overlap_hours or 1,
                initial_lookback_hours=args.initial_lookback_hours or 24,
                dry_run=args.dry_run,
            )
        if args.verify_config:
            return sync_masked.verify_command(args.tenant)
        return sync_masked.apply_infra_command(
            args.tenant,
            retention_days=args.retention_days or 30,
            dry_run=args.dry_run,
        )

    # Optional compliance check before serving. Never prompts: applies only
    # with --gdpr-auto-add, dry-runs otherwise, and serves regardless.
    if args.check_gdpr_on_startup:
        rc = _gdpr_check_once(
            index=os.environ.get("KLAXON_GDPR_INDEX", "wazuh-events-v5-*"),
            prefix=args.gdpr_prefix,
            sample=(
                args.gdpr_sample
                if args.gdpr_sample is not None
                else _default_gdpr_sample()
            ),
            auto_add=args.gdpr_auto_add,
            dry_run=not args.gdpr_auto_add,
            exclude=set(
                f.strip() for f in (args.gdpr_exclude or "").split(",") if f.strip()
            ),
            as_json=False,
            out_file=None,
            interactive=False,
        )
        if rc != 0:
            print(
                "startup DSGVO check did not complete cleanly; serving anyway.",
                file=sys.stderr,
            )

    # Imported here so that --help works without the Wazuh environment set.
    from .server import mcp

    try:
        serve(mcp, cfg)
    except KeyboardInterrupt:  # pragma: no cover
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
