# Drift prevention & CI

Option B's safety property depends on the generated artifacts matching
`fields.yaml` — and on the response layer and the deployed pipeline agreeing on
the token scheme and the field list. Klaxon enforces this in several places so
a hand-edit that is not reflected in the source of truth fails loudly instead
of silently weakening masking.

---

## Contents

- [Where the single source of truth lives](#where-the-single-source-of-truth-lives)
- [The provenance fingerprint](#the-provenance-fingerprint)
- [`klaxon masking generate --check`](#klaxon-masking-generate---check)
- [CI: `verify-masking-config`](#ci-verify-masking-config)
- [Pre-commit hook](#pre-commit-hook)
- [Fail-closed startup](#fail-closed-startup)
- [Sync-job preflight](#sync-job-preflight)
- [`klaxon verify-config`](#klaxon-verify-config)
- [The `generator_version` stamping gotcha](#the-generator_version-stamping-gotcha)

---

## Where the single source of truth lives

`tenants/<tenant>/fields.yaml` is the single source of truth (see
[multi-tenant.md](multi-tenant.md)). Everything else is generated from it: the
Klaxon config fragment, the ingest pipeline (Painless script), the ISM policies
(masked + quarantine), the index templates (masked + quarantine) and the
security-plugin roles fragment. Source paths in generated artifacts are
repo-root-relative (`tenants/<tenant>/fields.yaml`), so regeneration is
byte-identical across machines.

## The provenance fingerprint

The committed artifacts carry `_meta` with:

- the source path (repo-root-relative),
- `sha256` of the source `fields.yaml`,
- the tenant name,
- `generator_version` (the installed package version) and `generated_by`.

This is what the drift checks compare. **OpenSearch rejects `_meta` in ingest
pipelines**, so the deployed pipeline carries the same provenance JSON-encoded
in its `description` (after a `klaxon-provenance: ` marker) instead. The
`pipeline_provenance` / `fingerprint_matches` helpers read either form, so a
deployed pipeline (from `description`) and a committed template (from `_meta`)
compare against the current `fields.yaml` + the effective Klaxon config the
same way.

## `klaxon masking generate --check`

The no-write drift check: regenerates the committed artifact set and compares
it byte-for-byte against `tenants/<tenant>/generated/*`, exiting non-zero on
any difference. Used by CI, the pre-commit hook and `verify-config`.

```bash
klaxon masking generate --check
```

A mismatch is reported as:

```
<path>: DRIFT — regenerated output differs from the committed file. Edit tenants/<tenant>/fields.yaml and re-run the generator.
```

## Pre-commit hook

`.pre-commit-config.yaml` registers a local hook (`language: system`, id
`klaxon-masking-drift`) that runs `python -m klaxon_mcp masking generate --check`
before every commit, so a regenerated-artifact drift never lands in a commit.

There is no dedicated CI workflow for the masking check in this tree: the drift
gate is the pre-commit hook plus the `generate --check` command (and
`verify-config` / the sync preflight for the deployed side). To gate a CI job
on it, run the same `python -m klaxon_mcp masking generate --check` plus
`masking selftest --tenant customer-a` and the masking unit tests.

## Fail-closed startup

The response layer refuses to start when it would silently bypass the
generated config:

* if both `KLAXON_ANONYMIZATION_MASK_FIELDS` (env) and the YAML `mask_fields`
  are set and differ, `Config.from_env()` raises `ConfigError` instead of
  letting the environment override the file (the env is the known
  silent-bypass vector against the Option B config; precedence is still
  env > YAML when they agree — the guard only fires on a *conflict*);
* if any `masked_streams` pattern could match the quarantine stream
  (`klaxon-quarantine-<tenant>-v5-*` — raw masking-failure documents),
  `Config.from_env()` raises `ConfigError` — the LLM allowlist must never
  overlap the quarantine namespace, and the generated config fragment never
  adds it (a hand-edit or broad pattern like `klaxon-*` is caught).

Security-critical boolean switches (`KLAXON_ANONYMIZE_EXTERNAL_LLM`,
`KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS`,
`KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS`,
`KLAXON_ANONYMIZATION_WHITELIST_ENABLED`, `KLAXON_ANONYMIZATION_LOG_RAW`) are
parsed strict: an unrecognised value is a `ConfigError`, so a typo can never
silently disable masking.

## Sync-job preflight

Before every sync, `--sync-masked` fetches the deployed pipeline and compares
its fingerprint (sha256 of `fields.yaml` + field lists, carried in the deployed
pipeline's `description` — OpenSearch rejects `_meta`) against the current
`fields.yaml` and the effective Klaxon config. It additionally verifies the
deployed pipeline's `on_failure` actually contains the fail-closed quarantine
routing (a pre-quarantine pipeline would leave masking-failure documents in the
masked stream). Any drift aborts the sync
(`PREFLIGHT FAILED — not syncing`) rather than writing masked data with a stale
pipeline.

## `klaxon --verify-config`
`klaxon-mcp --verify-config --tenant X` (or `klaxon --verify-config --tenant X`)
runs the same checks as the sync preflight as a standalone drift audit (needs
the indexer): the deployed pipeline must match `fields.yaml` and the effective
Klaxon config and carry the quarantine `on_failure`, and the deployed salt must
match the current environment salt (`klaxon masking salt-check`). The
`klaxon masking generate --check` artifact comparison (over all seven
committed artifacts, including the quarantine ISM/template and the roles
fragment) runs without an indexer.

## The `generator_version` stamping gotcha

`generator_version` is part of the committed artifacts. Bumping the package
version in `pyproject.toml` without re-running
`klaxon masking generate --tenant customer-a` shows up as CI/pre-commit drift —
not because the masking changed, but because the provenance stamp changed.
Regenerate the artifacts (and reinstall the editable package) whenever the
version bumps, so the stamp matches the installed metadata.
