# Tool reference

Parameters and behaviour for each tool. For what Klaxon is and how to set it up,
see [README.md](../README.md). For why it is built this way, see
[ARCHITECTURE.md](../ARCHITECTURE.md).

---

## `search`

Any OpenSearch query DSL against any index. `POST /{index}/_search`, raw JSON
response including `aggregations`.

| Parameter | Type | |
|---|---|---|
| `index` | string | required — pattern, e.g. `wazuh-events-v5-network-activity*` |
| `body` | string | required — query DSL as a JSON string |

Index names are validated before interpolation: charset `[a-z0-9-_.*,]` only,
no `..`, no leading `/` or `_`, max 255 characters.

`size` is capped at `WAZUH_SEARCH_MAX_SIZE` (default 100). A larger value is
lowered **before** the query is sent and reported as `[SIZE CAPPED]`, naming
both the requested and effective value. `"size": 0` is never touched; a body
without `size` is left to the OpenSearch default of 10. Set the variable to `0`
to disable the cap — the server logs a warning at startup when you do.

The same cap applies to the `size` of bucketed aggregations (`terms`,
`significant_terms`, `significant_text`, `multi_terms`, `composite`,
`top_hits`): an oversized aggregation `size` is lowered to
`WAZUH_SEARCH_MAX_SIZE` before the query is sent and reported as
`[AGG SIZE CAPPED]`, naming each affected aggregation and its requested size —
so a lowered bucket count is never read as the real one.

Diagnostics emitted: zero hits, total-hits cap, partial aggregation coverage,
empty aggregations, legacy 4.x index patterns, size cap, aggregation size cap.

---

## `schema`

Which fields exist and which of them carry data.

| Parameter | Type | |
|---|---|---|
| `index` | string | required |
| `prefix` | string | optional, e.g. `wazuh.` or `source.` |
| `only_populated` | bool | default `true` |

Calls `GET /{index}/_field_caps?fields={prefix}*`. Since `_field_caps` reports
only what is *mapped*, `only_populated=true` adds a second pass of `exists`
aggregations and returns only fields with `doc_count > 0`. Output is name, type
and document count per field.

Without a `prefix` and with `only_populated=false`, the listing is capped at
`WAZUH_SCHEMA_FIELD_LIMIT` (default 200) and says so.

---

## `field_coverage`

How much of the data each field actually carries — measured over a time window
*and* over the whole datastream.

| Parameter | Type | |
|---|---|---|
| `index` | string | required |
| `prefix` | string | optional, e.g. `source.` |
| `hours` | int | default `24` |
| `min_docs` | int | default `0` — hide fields below this count in the window |

```
FIELD           TYPE     DOCS_WINDOW  COVERAGE  DOCS_TOTAL  DATASTREAM    DRIFT  STATUS
event.action    keyword       255142     73.5%      833779        8.1%  +65.3pp  partial
source.ip       ip            348247    100.0%    10238000       99.9%   +0.0pp  complete
source.domain   keyword        12000      3.4%       51000        0.5%   +2.9pp  sparse
event.original  keyword            -         -           -           -        -  unmeasurable
```

**Status bands:** `complete` ≥ 99 %, `partial` 50–99 %, `sparse` below 50 %,
`never` = 0 %, `unmeasurable` = the mapping does not let `exists` answer.

**Drift.** A gap wider than 20 percentage points between window and datastream
raises `[COVERAGE DRIFT]`. That gap is the signature of a normalisation change
inside the datastream — a decoder fix, a new integration, a broken one.

**Unmeasurable fields.** Fields mapped `"index": false` return 0 on `exists`
regardless of content. The mapping is read first
(`GET /{index}/_mapping/field/{prefix}*`); those fields are never probed and
appear with dashes, plus a `_source` sample stating in how many sampled
documents the key is present:

```
NOT MEASURABLE  (the mapping does not let an exists aggregation answer for these)
FIELD           TYPE     REASON                      _SOURCE
event.original  keyword  index:false in the mapping  10 of 10 sampled
```

`doc_values: false` is decisive only in combination with a zero result. A field
declared `index: false` in *some* backing indices but not all — a mapping that
changed at a rollover — is measured, with coverage reported as the lower bound
it is. If the mapping check itself fails, every 0 % row is flagged as possibly
unindexed rather than empty.

**0 % rows are never filtered.** A mapped, indexed, never-populated field is the
most important result this measurement produces. `min_docs` above `0` does
remove them, so the output reports how many it dropped and how many were at
zero. Unmeasurable fields are exempt from that filter.

**Rounding.** `100.0%` is reserved for `docs == total`; 99.996 % prints as
`99.9%`. A non-zero count never prints as `0.0%` — it prints `<0.1%`, since
`0.0%` is this table's notation for *never populated*.

*Known limit:* Wazuh maps keyword fields with `ignore_above: 1024`. A longer
value is stored in `_source` but not indexed, so `exists` misses it. Coverage
for a field with occasional long values is a slight underestimate. Not currently
detected.

Cost scales with field count; the run is capped at `WAZUH_SCHEMA_FIELD_LIMIT`
and the cap is reported. Pass a `prefix` to measure a namespace instead of a
truncation.

---

## `findings_overview`

The findings breakdown every report starts with, without needing query DSL.

| Parameter | Type | |
|---|---|---|
| `hours` | int | default `24` — window ending now |
| `top_agents` | int | default `10` |
| `top_titles` | int | default `10` |

Fixed to `wazuh-findings-v5-*`, `track_total_hits: true`, one request. Output is
five tables — severity, findings per agent with percentage, the agent × severity
cross-tab, top `wazuh.rule.title`, `wazuh.integration.category` — plus the
request body in the footer, so the query can be re-run or extended through
`search`.

The full severity scale is always printed, including levels that did not occur:

```
LEVEL          COUNT    PCT
---------------------------
critical           0   0.0%
high               0   0.0%
medium          1252  57.8%
low              163   7.5%
informational    747  34.5%
```

Values outside the scale are added and marked `UNKNOWN` rather than dropped, and
compared exactly — a `Medium` bucket is reported as unknown next to `medium`,
not folded into it.

Severity in Wazuh 5 is `wazuh.rule.level`, a keyword holding a **string**, not a
4.x numeric level.

Truncation is never silent: the agent and title tables carry a `cardinality`
count, so a top-10 list out of 42 agents says so and reports the findings that
fall outside it.

---

## `logtest`

Push a raw log line through the decoder chain.
`POST /_plugins/_content_manager/logtest`.

| Parameter | Type | |
|---|---|---|
| `event` | string | required — the raw log line |
| `location` | string | required |
| `queue` | int | default `49` |
| `space` | string | `test`, `custom` or `standard`; default `custom` |
| `trace_level` | string | `NONE`, `ASSET_ONLY` or `ALL`; default `ASSET_ONLY` |
| `integration` | string | optional; without it the detection phase is skipped |

`ASSET_ONLY` is the level that populates `asset_traces` with the matched decoder
chain.

A valid space name does not mean the environment exists. The plugin answers
HTTP 200 with `message.normalization.status = "error"`; Klaxon raises that as
`[LOGTEST NORMALIZATION FAILED]` and points at `tester_sessions` for the list of
environments that do exist.

---

## `manager`

Read-only passthrough to the Wazuh manager API.

| Parameter | Type | |
|---|---|---|
| `path` | string | required, e.g. `/agents` |
| `params` | object | optional query parameters |

GET only, with a path allowlist against traversal. Non-2xx responses are passed
through unchanged, including 404 — a 404 on `/rules` is correct in Wazuh 5, not
an error to swallow.

Requires `WAZUH_MANAGER_URL` and credentials.

---

## `detectors`

Security Analytics detectors — what produces the documents in
`wazuh-findings-v5-*`.

| Parameter | Type | |
|---|---|---|
| `action` | string | `list` (default) or `get` |
| `detector_id` | string | required when `action="get"` |
| `size` | int | default `50`, for `list` |

- `get` → `GET /_plugins/_security_analytics/detectors/{id}`
- `list` → `POST /_plugins/_security_analytics/detectors/_search` with
  `match_all`; the plugin exposes no list-all endpoint. Detector documents are
  nested under the `detector` path.

---

## `tester_sessions`

Which logtest environments exist — the usual cause of a failing `logtest`.

| Parameter | Type | |
|---|---|---|
| `action` | string | `list` (default), and nothing else |

`POST /_internal/tester/table/get`, empty body. Tabulated as name, namespace,
`entry_status`, lifetime and last use.

**These routes are not on the indexer.** The engine runs its own HTTP server
inside the **manager** container, on its own port — neither `WAZUH_INDEXER_URL`
nor `WAZUH_MANAGER_URL`. Hence `WAZUH_ENGINE_URL`; without it the tool names the
variable instead of failing inside the HTTP client. Pointed at the wrong
endpoint, the route answers 404, which the tool reports with that cause named.

Diagnostics: an empty session list (nothing provisioned, so *every* logtest call
fails regardless of the space named), a session whose `entry_status` is
`DISABLED` (exists and still fails exactly like a missing one), and a non-`OK`
`ReturnStatus`, whose `error` field is passed through verbatim.

**Read-only, deliberately.** The engine registers five tester routes; only
`table/get` is wired up. Sessions are created automatically when a policy is
imported and replaced on the next import, so a hand-created session is gone the
next time someone imports a policy.

No credentials are sent: whether that server expects any could not be verified.
A 401 or 403 is reported as such, naming the reason.

Route list from `api/tester/include/api/tester/handlers.hpp:37-42`, payload
shape from `proto/src/tester.proto:23-32` and `:135-142` (v5.0.0-beta4).

---

## Anonymization (GDPR)

Applied to **every tool output** when enabled and the LLM client is not local.
Off by default. See the README section for the full story; this page records
the settings and what the gate does.

| Setting | Env var | YAML (`anonymization:`) | Default |
|---|---|---|---|
| master switch | `KLAXON_ANONYMIZE_EXTERNAL_LLM` | `enabled` | `false` |
| LLM endpoint (local detection) | `KLAXON_LLM_BASE_URL` | `llm_base_url` | unset → assumed external |
| deterministic placeholders | `KLAXON_ANONYMIZATION_USE_HASH` | `use_hash` | `true` |
| token salt (HMAC key) | `KLAXON_ANONYMIZATION_SALT` | `salt` | auto-generated + persisted (`*.salt`) |
| masked fields | `KLAXON_ANONYMIZATION_MASK_FIELDS` | `mask_fields` | see below |
| aggregation key masking | `KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS` | `mask_aggregation_keys` | `false` |
| free-text username masking | `KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS` | `mask_free_text_users` | `true` |
| extra free-text fields | `KLAXON_ANONYMIZATION_MASK_FREE_TEXT_FIELDS` | `mask_free_text_fields` | empty (hint pattern) |
| block on residual PII | `KLAXON_ANONYMIZATION_WHITELIST_ENABLED` | `whitelist_enabled` | `true` |
| audit log | `KLAXON_ANONYMIZATION_LOG` | `log_path` | `llm_prompts.log` |
| persist unmasked output | `KLAXON_ANONYMIZATION_LOG_RAW` | `log_raw` | `false` |
| per-line log cap | `KLAXON_ANONYMIZATION_LOG_MAX_LEN` | `log_max_len` | `20000` |
| YAML config path | `KLAXON_CONFIG` | — | `config.yaml` |

Precedence is always **env > YAML > default**. The YAML file is optional and
only the `anonymization:` block is read.

Default masked fields: `source.ip`, `destination.ip`, `client.ip`, `server.ip`,
`related.ip`, `source.domain`, `destination.domain`, `host.hostname`,
`host.name`, `user.name`, `user.id`, `user.effective.name`, `source.user.name`,
`destination.user.name`, `wazuh.agent.name`, `wazuh.agent.id`, `agent.name`,
`agent.id`. A field listed here has its value replaced wholesale; the
placeholder family follows the field name (`.ip` → `[IP_…]`, `user.name` →
`[USER_…]`, `agent.name`/`host.hostname` → `[HOST_…]`, `agent.id` → `[AGENT_…]`).
A custom field not in the built-in table falls back to `[USER_…]`.

**Aggregation keys.** Bucket keys are computed on indexed values, so without a
masking pass a `terms` agg on `related.hosts` returns raw hostnames even when
`_source` is clean. With `mask_aggregation_keys` on (off by default), the
`search` response walker tokenises the `key` of `terms` / `significant_terms` /
`significant_text` / `multi_terms` / `composite` buckets whose source field is
in `mask_fields`, using the same deterministic tokens as `_source`. `composite`
`after_key` is tokenised the same way so pagination stays consistent.
`date_histogram`, `histogram`, `range`, `filters` and metric aggs are never
touched; `doc_count` and aggregation metadata survive unchanged; `top_hits`
embedded documents go through the normal `_source` masking. Aggregations whose
request could not be mapped to fields (saved searches, scripted aggs) are left
alone.

**Free-text usernames.** A `message` line can name a user without the structured
`user.name` being present (`uid=marcomoenig,ou=users,dc=sec73,dc=io`,
`session opened for user root(uid=0)`, `Accepted publickey for root ...`). With
`mask_free_text_users` on (the default) the free-text pass masks those usernames
with the *same* tokens as the structured fields: it builds a registry of the
response's known identities (`user.name`, `related.user`, `user.effective.name`,
...) and replaces them at word boundaries, and it also matches precise context
patterns (`uid=...`, `for/by user ...`, `Accepted publickey for ...`,
`username=/user=...`, `login as/for ...`). Common English words (`root`,
`user`, `data`, ...) are never replaced by the registry on their own — only
inside username formulations — to avoid false positives, and numeric ids
(`uid=0`) are not usernames and are left alone.

**Token format.** Tokens are `[FAMILY_…]` with 16 hex chars (64 bits of
entropy), derived by keyed HMAC-SHA256 over `salt` with the family as context,
so `[USER_…]` and `[HOST_…]` never collide for the same value and dictionary
reversal of a token is infeasible. Set `KLAXON_ANONYMIZATION_SALT` for a stable
salt across restarts; when unset a random salt is generated once and persisted
next to the config file (`config.yaml.salt`, gitignored) with a warning. Tokens
are per-response and never stored, so changing the salt needs no reindex.

**Activation.** `active = enabled and not (llm_base_url on loopback)`. An unset
endpoint is treated as external, and the server logs a warning saying so.

**The gate.** After the structured and text passes, `verify` scans for residual
IP addresses and e-mails. With `whitelist_enabled` (default) a hit **blocks the
response** — the caller receives a `GDPR BLOCKED` notice instead of data, and
the exchange is logged. With it off, the masked response is returned and the
warning is logged only.

**Audit log format** (`llm_prompts.log`, one line per exchange):

```
2026-08-08T12:34:56+00:00 - [EXTERNAL_LLM] - search MASKED: {"hits": {...}}
2026-08-08T12:34:56+00:00 - [EXTERNAL_LLM] - manager BLOCKED: residual PII (IP) ...
```

RAW lines appear only with `KLAXON_ANONYMIZATION_LOG_RAW=true`.

**CLI commands** (none require the Wazuh environment, none serve):

```bash
klaxon-mcp --anonymization-status
klaxon-mcp --anonymization-report [OUTFILE]
klaxon-mcp --anonymization-export [OUTFILE]   # RAW lines dropped
```

---

## `gdpr_check`

The DSGVO plausibility checker: find the sensitive fields an index actually
carries and merge them into the anonymization list.

| Parameter | Type | |
|---|---|---|
| `index` | string | required — pattern, e.g. `wazuh-events-v5-*` |
| `prefix` | string | optional — restrict to a namespace, e.g. `user.` |
| `sample_docs` | int | optional — docs to sample (default `KLAXON_GDPR_SAMPLE_SIZE`, 10; 0 disables) |
| `apply` | bool | default `false` — merge suggestions into `config.yaml` |
| `exclude` | list[string] | optional — fields to skip |
| `as_json` | bool | default `false` — machine-readable report |

Reads `GET /{index}/_field_caps`, pulls a small `_source` sample, and classifies
each field by three layers: `gdpr_checker.custom_patterns` from config.yaml
(highest), field-name patterns (`source.ip` → IP, `user.name` → USERNAME,
`host.hostname` / `wazuh.agent.name` → HOSTNAME, `wazuh.agent.id` → AGENT_ID,
`user.email` → EMAIL), and sampled values (a field holding `192.168.1.100` is
an IP by content; a free-text field embedding IPs/e-mails/usernames is flagged
as FREETEXT). Priorities: IP/username/e-mail = high, hostname/agent-id/domain =
medium, free text = medium.

Output is a table (FIELD / TYPE / PRIORITY / EVIDENCE / MASK / COVERED) plus a
summary; `as_json=true` returns the shape scripts parse:

```json
{
  "index": "wazuh-events-v5-*",
  "checked_fields": 5,
  "sensitive_fields": [
    {"field": "source.ip", "type": "IP_ADDRESS", "priority": "high",
     "suggested_mask": "[IP_ADDRESS]", "already_configured": false,
     "evidence": "field-name pattern"}
  ],
  "action_required": true,
  "fields_to_add": ["source.ip"]
}
```

**Apply.** `apply=true` (or the CLI `--gdpr-auto-add`) merges `fields_to_add`
into `anonymization.mask_fields` of `KLAXON_CONFIG`, appends to
`KLAXON_GDPR_CHECK_LOG` (`gdpr_check.log`) and writes the compliance report
`KLAXON_GDPR_REPORT` (`gdpr_compliance_report.json`). If
`KLAXON_ANONYMIZATION_MASK_FIELDS` is set, the environment overrides the file
and the checker warns. A `mask_fields` update takes effect on server restart.
`apply=false` is a dry run: nothing is written.

**CLI / triggers.** `klaxon-mcp --gdpr-check [INDEX]` (flags: `--gdpr-prefix`,
`--gdpr-sample`, `--gdpr-auto-add`, `--gdpr-dry-run`, `--gdpr-exclude`,
`--gdpr-json`, `--gdpr-out`) and the standalone `klaxon_check_gdpr` script
(`--index`, `--auto-add`, `--dry-run`, `--json`, ...) run the same code.
`--check-gdpr-on-startup` runs a non-interactive check before serving.
`KLAXON_GDPR_CHECK_ON_SEARCH=true` makes `search` append a `[GDPR]` notice
naming sensitive fields present in the hits.

---

## `klaxon masking` (Option B generator)

Builds the deployable artifacts for the separate masked stream from
`tenants/<tenant>/fields.yaml` — **without writing to the indexer** (deploying
is the operator's/CI's job). `klaxon` and `klaxon-mcp` are the same binary.

| Command | Purpose |
|---|---|
| `masking generate --tenant X` | write the committed artifact set (config fragment + pipeline template + ISM + index template) into `tenants/X/generated/` |
| `masking generate --tenant X --out DIR` | write the DEPLOYABLE set (real salt in `params.salt`) into `DIR` |
| `masking generate --tenant X --stdout` | print the deployable set to stdout |
| `masking generate --check` | no writes — compare committed artifacts vs `fields.yaml` (CI/pre-commit drift gate) |
| `masking generate --tenant X --retention-days N` | ISM delete-after (default 30) |
| `masking selftest [--tenant X]` | prove the generated Painless token scheme == `derive_token` byte-for-byte AND that the script is structurally compilable (functions before statements, no `ctx['_source']`); runs inside every `generate`; a mismatch aborts and emits nothing |
| `masking test --tenant X` | LIVE integration test: Stage A verifies the ingest Painless allowlist has the APIs the script needs (`GET /_scripts/painless/_context`), Stage B simulates it via `POST /_ingest/pipeline/_simulate` (authoritative compile + behaviour) on the real indexer — no writes, nothing deployed (skips cleanly when credentials are missing) |
| `masking salt-check --tenant X` | compare the DEPLOYED pipeline's `params.salt` with the current env salt (needs the indexer) |

Flags: `--tenant`, `--out`, `--stdout`, `--check`, `--retention-days`, `--root`,
`--salt`, `--salt-env` (and `--env` for `masking test`). The salt is read from
`KLAXON_ANONYMIZATION_SALT` (or `salt_env` in `fields.yaml`); unset → random
salt + warning (tokens rotate unless the salt is stable). `related.hash` is
never masked. See `docs/option-b-masked-stream.md` for the full design.

`masking test` reads the indexer credentials ONLY from `KLAXON_INDEXER_URL` /
`KLAXON_INDEXER_USER` / `KLAXON_INDEXER_PASSWORD` (optionally via a gitignored
local `.env.live` or `tests/live/.env` file — see `tests/live/.env.example`).
If any of the three is unset the test skips with a clear message; the password
is never logged. The same live test runs as the pytest marked `integration`/
`live` (`tests/test_live_masking.py`), which also skips without credentials.
Optional, non-credential `KLAXON_INDEXER_VERIFY_SSL` (default `true`) disables
TLS verification for a self-signed lab cluster — the test prints a warning;
prefer trusting the cluster CA (`SSL_CERT_FILE`/system trust store) instead.

---

## Transport options

| Variable | Flag | Default |
|---|---|---|
| `WAZUH_MCP_TRANSPORT` | `--transport` | `stdio` (`http`, `sse`) |
| `WAZUH_MCP_HOST` | `--host` | `127.0.0.1` |
| `WAZUH_MCP_PORT` | `--port` | `8000` |
| `WAZUH_MCP_PATH` | `--path` | `/mcp` |
| `WAZUH_MCP_AUTH_TOKEN` | — | empty (no auth) |
| `WAZUH_MCP_ALLOWED_HOSTS` | `--allowed-host` | empty |
| `WAZUH_MCP_ALLOWED_ORIGINS` | — | empty |
| `WAZUH_MCP_CORS_ORIGINS` | — | empty (no CORS headers) |
| `WAZUH_MCP_JSON_RESPONSE` | — | `false` |
| `WAZUH_MCP_STATELESS` | — | `false` |

Flags override environment variables. `sse` is the legacy MCP HTTP transport and
warns on startup; prefer `http` unless a client requires SSE. Behind a load
balancer without session affinity, set `WAZUH_MCP_STATELESS=true`.

The two origin settings do different jobs. `WAZUH_MCP_ALLOWED_ORIGINS` is a
filter — which `Origin` values are not rejected. `WAZUH_MCP_CORS_ORIGINS` is a
grant — which browser origins may call the endpoint with `fetch` at all. Only
the latter emits `Access-Control-Allow-Origin`, and setting it also adds those
origins to the filter so the two cannot contradict each other. Leave it empty
for any client that is not a browser, including Open WebUI, which connects from
its backend. `*` is refused.

Origin filtering cannot be enabled on its own: it is part of the same DNS
rebinding protection as the `Host` check, and turning that on with an empty
`WAZUH_MCP_ALLOWED_HOSTS` would reject every request. Set the host allowlist too,
or the origin list is logged as unenforced.

See [README.md](../README.md#read-this-before-opening-the-port) before exposing
a network listener.
