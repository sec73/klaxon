# Klaxon

**The alarm tells you *that*. Klaxon tells you *what*.**

Klaxon is a read-only proxy in front of your Wazuh 5 indexer. A language model
asks questions in plain language; Klaxon queries the indexer, reads the schema,
tests decoders, and reports what it actually found — including when it found
nothing, and why. Works with Claude Desktop, Claude Code, local models through
Ollama, and Open WebUI.

Every query runs through Klaxon, and the response is masked before it reaches
an external LLM: a value under a configured field (`user.name`, `source.ip`, …)
always becomes the same deterministic token (`[USER_…]`, `[IP_…]`), aggregation
keys included. **This is pseudonymization, not anonymization** — tokens are
deterministic and reversible by anyone holding the salt (see
[LLM-safety guarantees](docs/llm-safety.md)).

---

## Quick start

### Requirements

- Wazuh 5.x indexer reachable over HTTPS (`search`/`schema` also work against 4.x)
- Python 3.11+ or Docker
- an MCP client — Claude Desktop, Claude Code, `ollmcp`, Open WebUI 0.6.31+

### 1. Install

```bash
python3 -m venv .venv
.venv/bin/pip install klaxon-mcp
```

Or build the Docker image (`klaxon-mcp` is the entry point):

```bash
docker build -t klaxon-mcp .
```

### 2. Point it at your indexer

```bash
export WAZUH_INDEXER_URL=https://indexer.example:9200
export WAZUH_INDEXER_USER=wazuh-readonly
export WAZUH_INDEXER_PASSWORD=...
```

`WAZUH_INDEXER_URL` is the only required variable. Add `WAZUH_MANAGER_URL` for
`manager`/`detectors` and `WAZUH_ENGINE_URL` for `tester_sessions`; set
`WAZUH_VERIFY_SSL=false` only for a self-signed lab cluster.

### 3. Enable masking (recommended for external LLMs)

Masking is **off by default** and opt-in:

```bash
export KLAXON_ANONYMIZE_EXTERNAL_LLM=true   # mask tool output for external models
export KLAXON_ANONYMIZATION_SALT=change-me-to-a-long-random-secret  # stable tokens
```

With the switch on, output is masked unless `KLAXON_LLM_BASE_URL` points at a
loopback address (`http://localhost:11434` for Ollama) — a local model keeps
receiving unchanged data. An optional `config.yaml` (`KLAXON_CONFIG`) holds only
what you change; environment variables always win:

```yaml
anonymization:
  mask_fields:                 # or KLAXON_ANONYMIZATION_MASK_FIELDS
    - "source.ip"
    - "user.name"
    - "host.hostname"
  mask_aggregation_keys: true  # ON by default; false disables agg-key masking
```

### 4. Start it

```bash
klaxon-mcp    # stdio — your MCP client spawns it (klaxon is an alias)
```

With Docker: `docker run --rm -i --env-file .env klaxon-mcp`.

### 5. First masked result

Ask your client: *"Show me the last login by `user.name=alice` in
`wazuh-events-v5-*`."* Klaxon runs `search(index="wazuh-events-v5-*",
body=…)` and returns the masked response:

```json
{
  "hits": { "hits": [ { "_source": {
      "user":    { "name": "[USER_9f2a1c467dd5e2b8]" },
      "source":  { "ip": "[IP_5c01e73f9a2b4c1d]" },
      "message": "user [USER_9f2a1c467dd5e2b8] logged in via ssh from [IP_5c01e73f9a2b4c1d]"
  } } ] }
}
```

The same value always maps to the same token. Masking is pseudonymization, not
anonymization, and it has documented blind spots — see
[`docs/llm-safety.md`](docs/llm-safety.md) (in particular the verified leaks in
"Known limitations") before pointing an external model at Klaxon.

---

## Basic usage

The handful of tools a normal user needs (full reference:
[`docs/TOOLS.md`](docs/TOOLS.md)):

| Tool | What it does | One-liner example |
|---|---|---|
| `search` | Any query against any index, raw JSON back | `search(index="wazuh-events-v5-*", body={"query": {"match_all": {}}})` |
| `schema` | Which fields exist — and which actually carry data | `schema(index="wazuh-events-v5-*", prefix="wazuh.agent.")` |
| `field_coverage` | How complete each field is, window vs all history | `field_coverage(index="wazuh-events-v5-*", prefix="event.")` |
| `findings_overview` | Findings by severity, agent, title, category | `findings_overview(hours=48)` |
| `logtest` | Push a raw line through the decoder chain | `logtest(event="<raw line>")` |
| `gdpr_check` | Find sensitive fields the mask list should cover | `gdpr_check(index="wazuh-events-v5-*")` |
| `klaxon_posture_check` | Read-only security posture: facts + gaps, no verdict | `klaxon_posture_check(tenant="customer-a")` |

On an unfamiliar cluster, start with `field_coverage`. Every thin result gets a
notice block before the data (empty aggregation, capped size, missing index —
all return `HTTP 200` with nothing).

---

## Configuration (essentials)

The keys a normal user changes day to day. Full reference: [`docs/configuration.md`](docs/configuration.md).

| Variable / key | What it does | Default |
|---|---|---|
| `WAZUH_INDEXER_URL` | Indexer endpoint | — (required) |
| `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` | Basic-auth credentials | empty |
| `KLAXON_ANONYMIZE_EXTERNAL_LLM` | Master masking switch | `false` |
| `KLAXON_ANONYMIZATION_SALT` | Secret for token derivation (stable tokens) | random+persisted |
| `KLAXON_ANONYMIZATION_MASK_FIELDS` | Fields masked wholesale (`user.name`, `source.ip`, …) | built-in list |
| `KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS` | Mask aggregation bucket keys too | `true` (fail-closed) |
| `KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS` | Mask usernames inside free text | `true` |
| `WAZUH_VERIFY_SSL` | TLS verification | `true` |
| `WAZUH_MCP_AUTH_TOKEN` | Required bearer token when serving over HTTP | empty |

---

## Advanced topics

The deep material lives in dedicated docs — linked, not duplicated:

- **GDPR plausibility checker** (classification layers, custom rules, sampling, reports) → [`docs/gdpr-checker.md`](docs/gdpr-checker.md)
- **Ingest masking / Option B masked stream** (pipeline, ISM, index templates, quarantine for masking failures, sync job) → [`docs/option-b-masked-stream.md`](docs/option-b-masked-stream.md)
- **Multi-tenant setup** (`fields.yaml`, `klaxon masking generate`, salt, namespacing) → [`docs/multi-tenant.md`](docs/multi-tenant.md)
- **Drift prevention & CI** (pre-commit drift hook, provenance fingerprints, fail-closed startup, sync preflight, `--verify-config`) → [`docs/drift-prevention.md`](docs/drift-prevention.md)
- **Token scheme & security model** (HMAC, salt, self-test, why 16 hex) → [`docs/security-model.md`](docs/security-model.md)
- **Security concept: brute-force re-identification risk** (pseudonymization vs anonymization, salt as secret) → [`docs/security-concept.md`](docs/security-concept.md)
- **Salt rotation runbook** (no scheduled rotation; only on suspicion; response-layer + masked-stream paths) → [`docs/salt-rotation-runbook.md`](docs/salt-rotation-runbook.md)
- **LLM-safety guarantees & limits** (pseudonymization caveat, residual gate) → [`docs/llm-safety.md`](docs/llm-safety.md)
- **Running it on another machine** (HTTP transport, auth, TLS, CORS) → [`docs/TOOLS.md`](docs/TOOLS.md#transport-options), [`ARCHITECTURE.md`](ARCHITECTURE.md)

---

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest        # full suite
.venv/bin/mypy          # strict type check
.venv/bin/ruff check src
```

Option B generator self-tests (see [`docs/drift-prevention.md`](docs/drift-prevention.md)):

```bash
klaxon masking selftest --tenant customer-a
klaxon masking generate --check   # CI/pre-commit drift check
```

Deploy the masking artifacts to the indexer in one idempotent, ordered,
self-verifying step (preflight + GET-back verification + a `_simulate` smoke
test; `--dry-run` / `--rollback`):

```bash
klaxon masking deploy --tenant customer-a --dry-run   # plan only, no writes
klaxon masking deploy --tenant customer-a             # needs KLAXON_INDEXER_*
```

Remove the Option B masking infrastructure from the indexer cleanly, leaving the
raw Wazuh streams untouched (destructive — preview with `--dry-run`; a
mandatory verification phase proves nothing `klaxon-*` is left and the raw
streams are intact):

```bash
klaxon masking teardown --tenant customer-a --dry-run       # plan only, no writes
klaxon masking teardown --tenant customer-a --yes           # needs KLAXON_INDEXER_*
klaxon masking teardown --tenant customer-a --yes --purge-sync-state
#   ^ also delete the sync checkpoint marker (default: keep it so a future
#     re-setup can resume from the last checkpoint)
```

The live integration test (`klaxon masking test`) needs real indexer credentials —
see [`docs/option-b-masked-stream.md`](docs/option-b-masked-stream.md#the-live-integration-test-klaxon-masking-test).
Release history: [`CHANGELOG.md`](CHANGELOG.md).

---

## Documentation

- [`docs/TOOLS.md`](docs/TOOLS.md) — full tool reference & parameters
- [`docs/configuration.md`](docs/configuration.md) — complete configuration reference
- [`docs/gdpr-checker.md`](docs/gdpr-checker.md) — the GDPR plausibility checker
- [`docs/option-b-masked-stream.md`](docs/option-b-masked-stream.md) — ingest-side masking
- [`docs/multi-tenant.md`](docs/multi-tenant.md) — multi-tenant setup
- [`docs/drift-prevention.md`](docs/drift-prevention.md) — drift prevention & CI
- [`docs/security-model.md`](docs/security-model.md) — token scheme & security model
- [`docs/security-concept.md`](docs/security-concept.md) — pseudonymization / brute-force re-identification risk
- [`docs/salt-rotation-runbook.md`](docs/salt-rotation-runbook.md) — salt rotation runbook (only on suspicion)
- [`docs/llm-safety.md`](docs/llm-safety.md) — masking guarantees & limits
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — design rationale
- [`CHANGELOG.md`](CHANGELOG.md) — release history

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

Built by [sec73 GmbH](https://sec73.io).

Wazuh is a registered trademark of Wazuh Inc. Klaxon is an independent project
and is not affiliated with, endorsed by, or sponsored by Wazuh Inc.
