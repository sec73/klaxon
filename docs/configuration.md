# Configuration reference

Everything Klaxon reads is environment variables. No credential is baked into
the Docker image. The one optional file is a YAML config (`KLAXON_CONFIG`,
default `./config.yaml`) holding the `anonymization:` and `gdpr_checker:`
blocks — a convenience for shipping masking rules. **Precedence is always
environment > YAML > default.**

> Essentials only? See [README → Configuration](../README.md#configuration-essentials).

---

## Contents

- [Indexer, manager, engine](#indexer-manager-engine)
- [HTTP serving (transport)](#http-serving-transport)
- [Anonymization](#anonymization)
- [DSGVO/GDPR checker](#dsgvogdpr-checker)
- [The YAML config file](#the-yaml-config-file)
- [Precedence and drift guard](#precedence-and-drift-guard)

---

## Indexer, manager, engine

| Variable | Default | Purpose |
|---|---|---|
| `WAZUH_INDEXER_URL` | — (required) | The Wazuh 5.x indexer (OpenSearch) endpoint |
| `WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASSWORD` | empty | Basic auth against the security index |
| `WAZUH_MANAGER_URL` | empty (disables `manager`) | Wazuh 5.x manager API (JWT auth) |
| `WAZUH_MANAGER_USER` / `WAZUH_MANAGER_PASSWORD` | empty | Credentials for manager JWT login |
| `WAZUH_ENGINE_URL` | empty (disables `tester_sessions`) | The engine's own HTTP server (a different port from the manager API) |
| `WAZUH_VERIFY_SSL` | `true` | TLS verification for all three endpoints; `false` logs a startup warning |
| `WAZUH_TIMEOUT` | `60` | HTTP timeout (s) for indexer + manager requests |
| `WAZUH_SEARCH_MAX_SIZE` | `100` | Hard cap on a search body's `size`; `0` disables the cap |
| `WAZUH_SCHEMA_FIELD_LIMIT` | `200` | Cap on an unfiltered `schema` listing (the schema has 2351 fields) |
| `WAZUH_SCHEMA_PROBE_BATCH` | `100` | Exists-aggregations packed into one request by `schema`/`field_coverage` |
| `WAZUH_LOGTEST_SPACE` | `custom` | Default logtest tester-session space |
| `WAZUH_LOGTEST_TRACE_LEVEL` | `ASSET_ONLY` | Default logtest trace level |

Those are three separate endpoints: the indexer, the manager API, and the
engine's own HTTP server — the last runs inside the manager container but on a
different port from the manager API.

---

## HTTP serving (transport)

Klaxon defaults to **stdio**, spawned by your MCP client as a child process. To
serve it over a network, set `WAZUH_MCP_TRANSPORT=http` (or `sse`) — see
[TOOLS.md → Transport options](TOOLS.md#transport-options) before doing so; a
listening socket holds SIEM credentials.

| Variable | Default | Purpose |
|---|---|---|
| `WAZUH_MCP_TRANSPORT` | `stdio` | One of `stdio`, `http`, `sse` |
| `WAZUH_MCP_HOST` | `127.0.0.1` | Bind address |
| `WAZUH_MCP_PORT` | `8000` | Listen port |
| `WAZUH_MCP_PATH` | `/mcp` | MCP endpoint path |
| `WAZUH_MCP_AUTH_TOKEN` | empty | Shared secret required as `Authorization: Bearer <token>` (constant-time compare). Without it the server logs `SERVING WITHOUT AUTHENTICATION` and serves anyone |
| `WAZUH_MCP_ALLOWED_HOSTS` | empty | DNS-rebinding protection allowlist (comma-separated) |
| `WAZUH_MCP_ALLOWED_ORIGINS` | empty | Origin allowlist for rebinding protection |
| `WAZUH_MCP_CORS_ORIGINS` | empty | CORS grant for browser-based MCP clients; `*` is refused |
| `WAZUH_MCP_JSON_RESPONSE` | `false` | JSON-RPC response mode |
| `WAZUH_MCP_STATELESS` | `false` | Stateless session mode |

The CLI flags `--transport`, `--host`, `--port`, `--path` and `--allowed-host`
override these for a single run.

`GET /healthz` is exempt from authentication (load-balancer probes).

---

## Anonymization

See [security-model.md](security-model.md) for how the tokens work and
[llm-safety.md](llm-safety.md) for what is guaranteed.

| Variable | Default | Purpose |
|---|---|---|
| `KLAXON_ANONYMIZE_EXTERNAL_LLM` | `false` | Master masking switch (opt-in). When `true`, tool output is masked unless the LLM is provably local |
| `KLAXON_LLM_BASE_URL` | empty | LLM endpoint. Loopback ⇒ local model, output unchanged. Unset ⇒ treated as external (GDPR-safe failure) |
| `KLAXON_ANONYMIZATION_SALT` | random + persisted | Secret for token derivation. Unset ⇒ a salt is generated and persisted next to the config file (`.salt`, 0600, gitignored) |
| `KLAXON_ANONYMIZATION_USE_HASH` | `true` | `false` ⇒ generic labels (`[USERNAME]`, `[IP_ADDRESS]`, …) instead of keyed tokens |
| `KLAXON_ANONYMIZATION_MASK_FIELDS` | built-in list | Fields masked wholesale (`source.ip`, `user.name`, `user.effective.name`, `host.hostname`, `wazuh.agent.*`, …). Comma-separated |
| `KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS` | `true` | Mask aggregation bucket keys (terms/composite/…) with the same tokens as `_source`. ON by default (fail-closed); `false` restores raw keys |
| `KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS` | `true` | Mask usernames inside free-text fields using known identities + context patterns |
| `KLAXON_ANONYMIZATION_MASK_FREE_TEXT_FIELDS` | empty | Extra free-text fields that get the free-text username pass (beyond the built-in hint pattern) |
| `KLAXON_ANONYMIZATION_MASKED_STREAMS` | empty | Data streams already masked at ingest (Option B); their values pass through unchanged (idempotent). A pattern that could match the quarantine stream (`klaxon-quarantine-<tenant>-v5-*`, RAW masking failures) is refused — Klaxon fails to start |
| `KLAXON_ANONYMIZATION_WHITELIST_ENABLED` | `true` | `true` ⇒ a residual IP/e-mail **blocks** the response; `false` ⇒ logs a warning and returns the masked response |
| `KLAXON_ANONYMIZATION_LOG` | `llm_prompts.log` | Prompt/audit log path (MASKED output only) |
| `KLAXON_ANONYMIZATION_LOG_RAW` | `false` | `true` ⇒ also persist RAW output (the log becomes a personal-data store; the server warns) |
| `KLAXON_ANONYMIZATION_LOG_MAX_LEN` | `20000` | Max logged line length (longer lines are truncated with a marker) |
| `KLAXON_CONFIG` | `config.yaml` | Optional YAML file with `anonymization:`/`gdpr_checker:` blocks |

In the Docker image the server runs as an unprivileged user and the working
directory is not writable, so point `KLAXON_ANONYMIZATION_LOG` at a writable
path (e.g. `/tmp/llm_prompts.log`). If the log cannot be written the masking
still applies — only the audit trail is lost.

---

## DSGVO/GDPR checker

| Variable | Default | Purpose |
|---|---|---|
| `KLAXON_GDPR_CHECK_LOG` | `gdpr_check.log` | Audit log for check/apply actions |
| `KLAXON_GDPR_REPORT` | `gdpr_compliance_report.json` | Compliance report written on apply |
| `KLAXON_GDPR_SAMPLE_SIZE` | `10` | Documents sampled for content analysis |
| `KLAXON_GDPR_CHECK_ON_SEARCH` | `false` | `true` ⇒ `search` appends a `[GDPR]` notice naming sensitive fields in the hits |
| `KLAXON_GDPR_INDEX` | — | Default index for the `--gdpr-check` CLI (falls back to `wazuh-events-v5-*`) |

---

## The YAML config file

Optional (`KLAXON_CONFIG`). Environment variables always take precedence over
it.

### `anonymization:` block

```yaml
anonymization:
  enabled: true                # KLAXON_ANONYMIZE_EXTERNAL_LLM
  llm_base_url: "https://api.deepseek.com/v1"
  use_hash: true               # KLAXON_ANONYMIZATION_USE_HASH
  mask_fields:                 # KLAXON_ANONYMIZATION_MASK_FIELDS
    - "source.ip"
    - "destination.ip"
    - "user.name"
    - "user.effective.name"
    - "host.hostname"
    - "wazuh.agent.name"
    - "wazuh.agent.id"
  mask_aggregation_keys: true  # KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS
  mask_free_text_users: true   # KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS
  mask_free_text_fields:       # KLAXON_ANONYMIZATION_MASK_FREE_TEXT_FIELDS
    - "message"
  masked_streams:              # KLAXON_ANONYMIZATION_MASKED_STREAMS
    - "klaxon-masked-customer-a-v5-*"
  whitelist_enabled: true      # KLAXON_ANONYMIZATION_WHITELIST_ENABLED
  log_path: "llm_prompts.log"  # KLAXON_ANONYMIZATION_LOG
  log_raw: false               # KLAXON_ANONYMIZATION_LOG_RAW
  log_max_len: 20000           # KLAXON_ANONYMIZATION_LOG_MAX_LEN
```

> **Note:** the salt is **not** a YAML key. It comes from
> `KLAXON_ANONYMIZATION_SALT` (env) or a persisted `<config>.salt` file — see
> [security-model.md → Salt](security-model.md#salt).

### `gdpr_checker:` block

```yaml
gdpr_checker:
  custom_patterns:
    - field: "user.effective.name"   # example built-in rule (always present)
      type: "USERNAME"
      priority: "high"
  sample_size: 10        # KLAXON_GDPR_SAMPLE_SIZE
  log_path: "gdpr_check.log"
  report_path: "gdpr_compliance_report.json"
  check_on_search: false # KLAXON_GDPR_CHECK_ON_SEARCH
```

`custom_patterns` rules support `field` (exact / suffix / `*` glob), `type`
(IP_ADDRESS, USERNAME, EMAIL, HOSTNAME, AGENT_ID, …), `priority`
(high/medium/low) and an optional `regex` content check. The built-in
`user.effective.name` rule is always present; YAML rules merge on top.

---

## Precedence and drift guard

Precedence is **environment > YAML > default**. One deliberate exception is
fail-closed: if both `KLAXON_ANONYMIZATION_MASK_FIELDS` and the YAML
`mask_fields` are set and **differ**, Klaxon refuses to start with a
`ConfigError` instead of silently letting the environment bypass the file —
the environment is the known silent-bypass vector against a generated Option B
config. See [drift-prevention.md](drift-prevention.md).
