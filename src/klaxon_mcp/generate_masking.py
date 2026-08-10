# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Generator for Option B: one fields.yaml -> both masking artifacts.

Reads `tenants/<tenant>/fields.yaml` (the single source of truth) and emits:

  (a) the Klaxon config fragment (`anonymization.mask_fields` +
      `gdpr_checker.custom_patterns`) -> tenants/<tenant>/generated/klaxon-config.yaml
  (b) the ingest pipeline JSON -> tenants/<tenant>/generated/pipeline-klaxon-mask-<tenant>.json

The pipeline artifact committed to git is the *template* (salt placeholder
`__SALT__`); the deployable pipeline with the real salt is produced at apply /
sync time by `klaxon-mcp apply-masked-infra` so the secret never enters version
control.

Run:
    python -m klaxon_mcp.generate_masking --tenant customer-a            # write
    python -m klaxon_mcp.generate_masking --tenant customer-a --check    # no writes, diff vs committed
    python -m klaxon_mcp.generate_masking --check                        # all tenants

Both artifacts carry a provenance fingerprint (sha256 of fields.yaml + source
path), so any check (CI, pre-commit, `klaxon verify-config`, sync preflight) can
detect artifacts generated from different field-file versions.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .masked_stream import (
    TenantConfig,
    build_config_fragment,
    build_pipeline_template,
    find_repo_root,
    find_tenant_dir,
    load_tenant_config,
)

CONFIG_FRAGMENT_NAME = "klaxon-config.yaml"
PIPELINE_TEMPLATE_NAME = "pipeline-{pipeline}.json"


def generated_dir(cfg: TenantConfig) -> Path:
    return find_tenant_dir(cfg.tenant) / "generated"


def generated_paths(cfg: TenantConfig) -> tuple[Path, Path]:
    d = generated_dir(cfg)
    return (
        d / CONFIG_FRAGMENT_NAME,
        d / PIPELINE_TEMPLATE_NAME.format(pipeline=cfg.pipeline_name),
    )


def render_artifacts(cfg: TenantConfig) -> dict[str, str]:
    """field-name -> serialised generated artifact (deterministic)."""
    config_path, pipeline_path = generated_paths(cfg)
    return {
        str(config_path): build_config_fragment(cfg),
        str(pipeline_path): json.dumps(build_pipeline_template(cfg), indent=2)
        + "\n",
    }


def write_artifacts(cfg: TenantConfig) -> list[Path]:
    """Write both generated artifacts to tenants/<tenant>/generated/."""
    written: list[Path] = []
    for path, content in render_artifacts(cfg).items():
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        written.append(p)
    return written


def check_artifacts(cfg: TenantConfig) -> list[str]:
    """Compare regenerated artifacts with the committed files; return mismatches.

    A hand-edit to a generated artifact that is not reflected in fields.yaml
    shows up here, which is what CI and the pre-commit hook gate on.
    """
    mismatches: list[str] = []
    for path, content in render_artifacts(cfg).items():
        p = Path(path)
        if not p.exists():
            mismatches.append(f"{path}: MISSING (run generate_masking)")
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


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m klaxon_mcp.generate_masking",
        description=(
            "Generate the Klaxon config fragment and the ingest pipeline from "
            "tenants/<tenant>/fields.yaml (Option B)."
        ),
    )
    parser.add_argument("--tenant", metavar="TENANT", help="Tenant to generate.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="No writes: compare regenerated artifacts with the committed files "
        "and exit non-zero on drift.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repo root (default: nearest ancestor of the working directory "
        "that contains tenants/).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    root = args.root or find_repo_root()

    tenants = [args.tenant] if args.tenant else tenants_in_repo(root)
    if not tenants:
        print("no tenants found (tenants/*/fields.yaml)", file=sys.stderr)
        return 1

    failed = False
    for tenant in tenants:
        try:
            cfg = load_tenant_config(tenant, root)
        except (FileNotFoundError, ValueError) as exc:
            print(f"[{tenant}] error: {exc}", file=sys.stderr)
            failed = True
            continue

        if args.check:
            mismatches = check_artifacts(cfg)
            if mismatches:
                failed = True
                print(f"[{tenant}] FAIL", file=sys.stderr)
                for line in mismatches:
                    print(f"  {line}", file=sys.stderr)
            else:
                print(f"[{tenant}] ok: generated artifacts match fields.yaml")
        else:
            written = write_artifacts(cfg)
            print(f"[{tenant}] wrote:")
            for p in written:
                print(f"  {p}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
