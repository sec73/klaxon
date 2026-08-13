# Multi-tenant setup

Option B (ingest-side masking, [`option-b-masked-stream.md`](option-b-masked-stream.md))
is organised per **tenant**. One tenant = one `tenants/<tenant>/fields.yaml`
(the single source of truth) + one generated resource set. All generated
resources are namespaced with the tenant: `klaxon-mask-<tenant>`,
`klaxon-masked-<tenant>-v5` (data stream; backing indices `...-v5-*`),
`klaxon-masked-retention-<tenant>`, `klaxon-masked-<tenant>` (template),
sync-state doc `klaxon-sync-<tenant>`.

> Want the end-to-end stream operation (pipeline, deploy, sync job, query
> redirection) instead? See [`option-b-masked-stream.md`](option-b-masked-stream.md).
> This doc is the tenant-focused view: the `fields.yaml` schema, the generator
> workflow, and the salt.

---

## Contents

- [The `fields.yaml` schema](#the-fieldsyaml-schema)
- [The generator (`klaxon masking generate`)](#the-generator-klaxon-masking-generate)
- [The salt](#the-salt)
- [Adding a tenant](#adding-a-tenant)
- [Generated artifacts](#generated-artifacts)

---

## The `fields.yaml` schema

```yaml
# tenants/<tenant>/fields.yaml
tenant: customer-a
salt_env: KLAXON_ANONYMIZATION_SALT
mask_free_text_users: true

free_text_fields:
  - field: message

fields:
  - field: destination.ip
    family: IP
  - field: source.ip
    family: IP
  - field: source.address
    family: IP
  - field: user.name
    family: USER
  - field: user.id
    family: USER
  - field: user.effective.name
    family: USER
  - field: client.user.name
    family: USER
  - field: host.hostname
    family: HOST
  - field: source.domain
    family: HOST
  - field: url.domain
    family: HOST
  - field: event.dataset
    family: HOST
  - field: log.logger
    family: HOST
  - field: wazuh.agent.id
    family: AGENT
  - field: wazuh.agent.name
    family: HOST
  - field: wazuh.agent.host.hostname
    family: HOST
  # array: true masks each element of a list field (e.g. related.user)
  - field: related.user
    family: USER
    array: true
  - field: related.hosts
    family: HOST
    array: true
```

Validation (enforced by the loader, `load_tenant_config`):

- `tenant` must match the directory name.
- Field names are restricted to `[A-Za-z0-9_.@-]` (dotted ECS-style names).
- Families are one of `IP`, `USER`, `HOST`, `AGENT`.
- `related.hash` is **intentionally not maskable** (file hashes are security
  IOCs, not personal data) — the loader hard-refuses it.
- No duplicate fields; a field cannot be both a `field` and a
  `free_text_field`.

## The generator (`klaxon masking generate`)

`klaxon masking` is the **single generator** for the deployable artifacts. It
only outputs files/stdout — it never writes to the indexer (deploying is the
operator's/CI's job). The mandatory token-scheme self-test runs first; on ANY
failure generation aborts and emits no artifacts.

```bash
# build the 4 artifacts from tenants/<tenant>/fields.yaml
klaxon masking generate --tenant customer-a

# DEPLOYABLE form (real salt in params.salt) into a directory or stdout
klaxon masking generate --tenant customer-a --out /tmp/deploy
klaxon masking generate --tenant customer-a --stdout

# prove the generated Painless token scheme is byte-identical to derive_token
klaxon masking selftest [--tenant customer-a]

# compare the salt baked into the DEPLOYED pipeline with the current env salt
klaxon masking salt-check --tenant customer-a

# CI/pre-commit drift check: committed artifacts must match fields.yaml
klaxon masking generate --check
```

`klaxon-mcp` is a compatibility alias for `klaxon`. `--root` points at the repo
root when running outside the checkout; `--retention-days` sets the ISM
delete-after for the masked stream (default 30); `--salt`/`--salt-env` override
the salt for a single run.

## The salt

The salt comes from the same environment variable as the response layer
(`KLAXON_ANONYMIZATION_SALT`, or `salt_env` in `fields.yaml`); if it is unset a
random salt is generated **with a warning** — tokens rotate unless the salt is
stable, so previously written masked documents stop correlating. See
[security-model.md → Salt](security-model.md#salt).

Per-tenant salt override: set `salt_env` in that tenant's `fields.yaml` to a
different variable name, so each tenant can carry its own secret.

## Adding a tenant

```bash
# write tenants/<tenant>/fields.yaml (copy customer-a's as a template)
# then regenerate + deploy:
klaxon masking generate --tenant <tenant>
# deploy pipeline/ISM/template (see option-b-masked-stream.md), then sync
```

Tenant names are validated to `[a-z0-9._-]` (no `..`, max 64 chars) — the
single choke point before a tenant is used as a path component, a resource name
and an index-pattern component.

## Generated artifacts

`klaxon masking generate` emits seven files into `tenants/<tenant>/generated/`:

| File | Resource |
|---|---|
| `klaxon-config.yaml` | Klaxon config fragment (`anonymization.mask_fields` + `gdpr_checker.custom_patterns` + `masked_streams`) |
| `pipeline-klaxon-mask-<tenant>.json` | `PUT /_ingest/pipeline/klaxon-mask-<tenant>` |
| `ism-klaxon-masked-retention-<tenant>.json` | `PUT /_plugins/_ism/policies/klaxon-masked-retention-<tenant>` |
| `index-template-klaxon-masked-<tenant>.json` | `PUT /_index_template/klaxon-masked-<tenant>` |
| `ism-klaxon-quarantine-retention-<tenant>.json` | `PUT /_plugins/_ism/policies/klaxon-quarantine-retention-<tenant>` (quarantine, 90d) |
| `index-template-klaxon-quarantine-<tenant>.json` | `PUT /_index_template/klaxon-quarantine-<tenant>` (no `index.default_pipeline`) |
| `roles-klaxon-<tenant>.yaml` | OpenSearch security-plugin roles fragment (LLM/ops/sync) |

The committed (checked-in) form carries `params.salt = "__SALT__"` and is
secret-free; the deployable form (`--out`/`--stdout`) carries the real salt.
Every artifact is stamped with `generator_version` and a sha256 of the source
`fields.yaml` — see [drift-prevention.md](drift-prevention.md).
