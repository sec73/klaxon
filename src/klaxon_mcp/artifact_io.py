# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Artifact filesystem I/O for `klaxon masking generate`.

Renders, writes and drift-checks the four Option B artifacts (config fragment,
ingest pipeline, ISM policy, index template) from a `TenantConfig`. Pure file
I/O plus deterministic serialisation; the builders it calls live in
`masked_stream`. No writes to the indexer — deploying stays the operator's/CI's
job.
"""

from __future__ import annotations

import json
from pathlib import Path

from .masked_stream import (
    DEFAULT_RETENTION_DAYS,
    TenantConfig,
    build_config_fragment,
    build_deployable_pipeline,
    build_index_template,
    build_ism_policy,
    build_pipeline,
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
    cfg: TenantConfig, *, salt: str, retention_days: int, deployable: bool = False
) -> dict[str, str]:
    """relative filename -> serialised artifact content (deterministic).

    `deployable=True` renders the pipeline body actually PUT to OpenSearch
    (`build_deployable_pipeline`: real salt, NO `_meta` — OpenSearch rejects it
    — provenance embedded in `description`). `deployable=False` (default) is the
    committed template form with `_meta` intact, which CI drift-checks.
    """
    pipeline_builder = build_deployable_pipeline if deployable else build_pipeline
    return {
        CONFIG_FRAGMENT_NAME: build_config_fragment(cfg),
        PIPELINE_TEMPLATE_NAME.format(pipeline=cfg.pipeline_name): json.dumps(
            pipeline_builder(cfg, salt), indent=2
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

    The pipeline carries the REAL salt in `params.salt` and NO `_meta` (OpenSearch
    rejects it; provenance is embedded in `description`) — this is what an
    operator PUTs to the indexer (`--out DIR` / `--stdout`).
    """
    return _artifact_contents(cfg, salt=salt, retention_days=retention_days, deployable=True)


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
