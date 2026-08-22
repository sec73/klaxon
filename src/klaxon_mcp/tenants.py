# SPDX-FileCopyrightText: 2026 sec73 GmbH <https://www.sec73.io>
# SPDX-License-Identifier: Apache-2.0
#
# Author: Marco Moenig <marco.moenig@sec73.io>

"""Tenant model + `fields.yaml` loader for the Option B masked stream.

The single source of truth for one tenant's masking is `tenants/<tenant>/
fields.yaml`; this module parses and validates it into a frozen `TenantConfig`
(the object every artifact builder and the sync job consume), derives the
generated resource names, fingerprints the source file, and builds the Klaxon
`anonymization:` + `gdpr_checker:` YAML config fragment. Pure filesystem + YAML
parsing — no indexer interaction.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .validation import validate_tenant

# Field names from fields.yaml flow verbatim into the generated Klaxon config
# fragment (unquoted YAML) and the Painless field table. The charset is what a
# WCS/ECS dotted field name needs — the absence of ':', '#', quotes, whitespace
# and control characters is what keeps the generated YAML well-formed.
_FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")

_FAMILIES = frozenset({"IP", "USER", "HOST", "AGENT"})

# The built-in default free-text field: the free-text pass ALWAYS runs over it
# (pipeline AND response layer), independent of fields.yaml. It must NOT be
# listed in `free_text_fields` (the validator rejects it) — the generator, the
# Python twin and the config fragment inject it. `free_text_fields` holds only
# EXTRA fields.
DEFAULT_FREE_TEXT_FIELD = "message"


def effective_free_text_fields(cfg: TenantConfig) -> tuple[str, ...]:
    """The free-text fields the free-text pass runs over: the built-in
    `message` plus any extra `free_text_fields` from fields.yaml. The single
    source of truth so the generated pipeline (`FREE_TEXT`), its `_meta`, the
    Python twin, the drift fingerprint and the Klaxon config fragment
    (`mask_free_text_fields`) all agree — `message` is always present, so the
    emitted `FREE_TEXT` list is never empty."""
    extras = tuple(f for f in cfg.free_text_fields if f != DEFAULT_FREE_TEXT_FIELD)
    return (DEFAULT_FREE_TEXT_FIELD, *extras)


@dataclass(frozen=True)
class FieldSpec:
    """One masking field from fields.yaml."""

    field: str
    family: str
    array: bool = False

    def to_painless_row(self) -> list[Any]:
        return [self.field, self.family, self.array]


@dataclass(frozen=True)
class TenantConfig:
    """The single source of truth for one tenant's masking."""

    tenant: str
    salt_env: str
    mask_free_text_users: bool
    fields: tuple[FieldSpec, ...]
    free_text_fields: tuple[str, ...]
    source_path: str

    @property
    def pipeline_name(self) -> str:
        return f"klaxon-mask-{self.tenant}"

    @property
    def ism_policy_name(self) -> str:
        return f"klaxon-masked-retention-{self.tenant}"

    @property
    def index_template_name(self) -> str:
        return f"klaxon-masked-{self.tenant}"

    @property
    def masked_stream(self) -> str:
        return f"klaxon-masked-{self.tenant}-v5"

    @property
    def masked_stream_pattern(self) -> str:
        """Query/allowlist pattern for the masked data stream.

        `klaxon-masked-<tenant>-v5*` (NOT `...-v5-*`): the data stream is named
        `klaxon-masked-<tenant>-v5` with NO trailing dash (see `masked_stream`),
        so a `-*` suffix matches neither the stream name nor resolves to its
        backing indices, and every query returns 0 documents. The `*` directly
        after `v5` matches the stream name itself and its `...-v5-000001`
        backing indices.
        """
        return f"{self.masked_stream}*"

    @property
    def quarantine_index_template_name(self) -> str:
        return f"klaxon-quarantine-{self.tenant}"

    @property
    def quarantine_stream(self) -> str:
        return f"klaxon-quarantine-{self.tenant}-v5"

    @property
    def quarantine_stream_pattern(self) -> str:
        """Query/ISM pattern for the quarantine data stream.

        Deliberately NOT `klaxon-masked-<tenant>-v5*` — the quarantine stream
        lives in its OWN `klaxon-quarantine-` namespace so it can never overlap
        the LLM allowlist `klaxon-masked-<tenant>-v5*`.
        """
        return f"{self.quarantine_stream}-*"

    @property
    def quarantine_routing_index(self) -> str:
        """The concrete index the pipeline's on_failure reroutes failed docs to.

        It matches the quarantine index template (`klaxon-quarantine-<tenant>
        -v5*`), so it is auto-created (as a data stream) on first write and is
        covered by the quarantine ISM retention.
        """
        return f"klaxon-quarantine-{self.tenant}-v5-raw"

    @property
    def quarantine_ism_policy_name(self) -> str:
        return f"klaxon-quarantine-retention-{self.tenant}"

    @property
    def raw_stream(self) -> str:
        return "wazuh-events-v5-*"

    @property
    def sync_state_index(self) -> str:
        return "klaxon-sync-state"

    @property
    def sync_state_doc_id(self) -> str:
        return f"klaxon-sync-{self.tenant}"

    @property
    def all_masked_fields(self) -> tuple[str, ...]:
        return tuple(f.field for f in self.fields)

    @property
    def source_rel(self) -> str:
        """Repo-root-relative source path, for committed/portable artifacts."""
        return f"tenants/{self.tenant}/fields.yaml"


def find_repo_root(start: str | Path | None = None) -> Path:
    """Locate the repo root by walking up from `start` (default: cwd) to the
    nearest ancestor that contains a `tenants/` directory (the Option B marker).

    Falls back to `start`/cwd if no ancestor qualifies. The lookup is
    independent of where the package is installed, so it works both from the
    `src/` layout and from a site-packages install (e.g. `pip install .` in
    CI, where `__file__` lives outside the checkout).
    """
    current = Path(start or Path.cwd()).resolve()
    for candidate in (current, *current.parents):
        if (candidate / "tenants").is_dir():
            return candidate
    return current


def find_tenant_dir(tenant: str, root: str | Path | None = None) -> Path:
    """The `tenants/<tenant>` directory (repo root by default).

    The tenant name is validated here — the single choke point before it is
    used as a path component, a resource name and an index-pattern component
    everywhere downstream (`klaxon-mask-<tenant>`, `klaxon-masked-<tenant>-v5*`,
    sync-state doc id, ...).
    """
    base = Path(root) if root is not None else find_repo_root()
    return base / "tenants" / validate_tenant(tenant)


def _validate_field_name(field: str, path: str) -> None:
    """Reject a field name that could break the generated YAML/Painless output."""
    if not _FIELD_NAME_RE.match(field):
        raise ValueError(
            f"invalid field name {field!r} in {path}: permitted charset is "
            "[A-Za-z0-9_.@-] (dotted ECS-style names, e.g. 'source.ip', "
            "'@timestamp')."
        )


def load_tenant_config(
    tenant: str, root: str | Path | None = None
) -> TenantConfig:
    """Parse and validate `tenants/<tenant>/fields.yaml`."""
    tenant_dir = find_tenant_dir(tenant, root)
    path = tenant_dir / "fields.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"missing masking source of truth: {path}. Create it first."
        )
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    if data.get("tenant") != tenant:
        raise ValueError(
            f"tenants/{tenant}/fields.yaml must declare tenant: {tenant!r}, "
            f"got {data.get('tenant')!r}"
        )
    salt_env = str(data.get("salt_env", "KLAXON_ANONYMIZATION_SALT"))
    mask_free_text_users = bool(data.get("mask_free_text_users", True))

    fields: list[FieldSpec] = []
    seen: set[str] = set()
    for entry in data.get("fields", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("field"), str):
            raise ValueError(f"invalid field entry in {path}: {entry!r}")
        field = entry["field"]
        _validate_field_name(field, str(path))
        if field in seen:
            raise ValueError(f"duplicate field {field!r} in {path}")
        seen.add(field)
        family = str(entry.get("family", "USER")).upper()
        if family not in _FAMILIES:
            raise ValueError(f"field {field!r}: unknown family {family!r}")
        if field == "related.hash":
            # File hashes are security IOCs, not personal data. Hard-refuse.
            raise ValueError(
                f"field {field!r} is intentionally not maskable (IOC); remove it "
                "from fields.yaml."
            )
        fields.append(
            FieldSpec(field=field, family=family, array=bool(entry.get("array", False)))
        )

    free_text_fields: list[str] = []
    for entry in data.get("free_text_fields", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("field"), str):
            raise ValueError(f"invalid free_text_fields entry in {path}: {entry!r}")
        field = entry["field"]
        _validate_field_name(field, str(path))
        if field == DEFAULT_FREE_TEXT_FIELD:
            raise ValueError(
                f"{field!r} is the built-in default free-text field and must "
                "not be listed in free_text_fields (the free-text pass always "
                "runs over it)"
            )
        if field in seen:
            raise ValueError(f"{field!r} listed as both field and free_text_field")
        free_text_fields.append(field)

    if not fields:
        raise ValueError(f"{path} declares no fields")

    return TenantConfig(
        tenant=tenant,
        salt_env=salt_env,
        mask_free_text_users=mask_free_text_users,
        fields=tuple(fields),
        free_text_fields=tuple(free_text_fields),
        source_path=str(path),
    )


def fields_yaml_sha256(cfg: TenantConfig) -> str:
    """sha256 of the fields.yaml source file (the provenance fingerprint)."""
    digest = hashlib.sha256()
    with open(cfg.source_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Klaxon config fragment
# --------------------------------------------------------------------------- #


def _gdpr_kind(family: str) -> str:
    return {
        "IP": "IP_ADDRESS",
        "USER": "USERNAME",
        "HOST": "HOSTNAME",
        "AGENT": "AGENT_ID",
    }[family]


def _gdpr_priority(family: str) -> str:
    return "high" if family in {"IP", "USER"} else "medium"


def build_config_fragment(cfg: TenantConfig) -> str:
    """The Klaxon `anonymization:` + `gdpr_checker:` YAML fragment for a tenant.

    Deterministic: same fields.yaml -> same fragment.
    """
    mask_fields = "\n".join(f"    - {f.field}" for f in cfg.fields)
    custom = "\n".join(
        f"    - field: {f.field}\n      type: {_gdpr_kind(f.family)}\n"
        f"      priority: {_gdpr_priority(f.family)}"
        for f in cfg.fields
    )
    # `message` is the built-in default free-text field (always emitted);
    # `cfg.free_text_fields` holds only the EXTRA fields from fields.yaml.
    free_text = "\n".join(f"    - {f}" for f in effective_free_text_fields(cfg))
    sha = fields_yaml_sha256(cfg)
    return (
        f"# generated from {cfg.source_rel} (sha256: {sha})\n"
        f"# Hand-edit only via {cfg.source_rel} + "
        "`klaxon masking generate`. CI enforces this.\n"
        "anonymization:\n"
        "  mask_aggregation_keys: true\n"
        f"  mask_free_text_users: {str(cfg.mask_free_text_users).lower()}\n"
        "  mask_fields:\n"
        f"{mask_fields}\n"
        "  masked_streams:\n"
        f"    - {cfg.masked_stream_pattern}\n"
        + (f"  mask_free_text_fields:\n{free_text}\n" if free_text else "")
        + "gdpr_checker:\n"
        "  custom_patterns:\n"
        f"{custom}\n"
    )
