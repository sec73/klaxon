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

Diagnostics emitted: zero hits, total-hits cap, partial aggregation coverage,
empty aggregations, legacy 4.x index patterns, size cap.

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
| placeholder hash | `KLAXON_ANONYMIZATION_HASH_ALGORITHM` | `hash_algorithm` | `md5` (`sha256`) |
| masked fields | `KLAXON_ANONYMIZATION_MASK_FIELDS` | `mask_fields` | see below |
| block on residual PII | `KLAXON_ANONYMIZATION_WHITELIST_ENABLED` | `whitelist_enabled` | `true` |
| audit log | `KLAXON_ANONYMIZATION_LOG` | `log_path` | `llm_prompts.log` |
| persist unmasked output | `KLAXON_ANONYMIZATION_LOG_RAW` | `log_raw` | `false` |
| per-line log cap | `KLAXON_ANONYMIZATION_LOG_MAX_LEN` | `log_max_len` | `20000` |
| YAML config path | `KLAXON_CONFIG` | — | `config.yaml` |

Precedence is always **env > YAML > default**. The YAML file is optional and
only the `anonymization:` block is read.

Default masked fields: `source.ip`, `destination.ip`, `client.ip`, `server.ip`,
`related.ip`, `source.domain`, `destination.domain`, `host.hostname`,
`host.name`, `user.name`, `user.id`, `source.user.name`,
`destination.user.name`, `wazuh.agent.name`, `wazuh.agent.id`, `agent.name`,
`agent.id`. A field listed here has its value replaced wholesale; the
placeholder family follows the field name (`.ip` → `[IP_…]`, `user.name` →
`[USER_…]`, `agent.name`/`host.hostname` → `[HOST_…]`, `agent.id` → `[AGENT_…]`).
A custom field not in the built-in table falls back to `[USER_…]`.

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
