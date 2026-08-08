# Architecture and design notes

Background for anyone modifying Klaxon, or wondering why it is shaped the way it
is. For installation and daily use, see [README.md](README.md).

Everything stated here about Wazuh 5 internals was verified against the tagged
source at `github.com/wazuh/wazuh` or measured on a running instance. Where a
claim rests on one observation rather than the source, it says so.

---

## Table of contents

- [Why generic instead of specific](#why-generic-instead-of-specific)
- [The design rule: HTTP 200 is not the same as an answer](#the-design-rule-http-200-is-not-the-same-as-an-answer)
- [The `agent.id` trap](#the-agentid-trap)
- [Wazuh 5 index layout](#wazuh-5-index-layout)
- [Field model reference](#field-model-reference)
- [The diagnostics layer](#the-diagnostics-layer)
- [Design notes per tool](#design-notes-per-tool)
- [Deliberately not built](#deliberately-not-built)
- [Version scope](#version-scope)

---

## Why generic instead of specific

Wazuh 4.x kept separate data models for alerts, rules and syscollector. The
existing MCP servers grew one narrow tool per domain, each with a hardcoded
index and field model. That was a reasonable shape: there was one alert index
with one schema, and a tool author could know what was in it.

Wazuh 5 dissolved that split:

- All events live under `wazuh-events-v5-*`, all detection results under
  `wazuh-findings-v5-*`.
- The WCS schema is global and enforced at decoder build time.
- Detection moved entirely into the indexer (OpenSearch Security Analytics
  plugin). The engine no longer has a `RULE` content type.

One generic search tool therefore covers events, findings and states at the same
time. The eight integration categories are *parameter values*, not tools.

The deeper reason is that the premise behind domain tools no longer holds. What
sits in `network-activity` depends on which decoders the operator wrote. No
fixed tool can model that, because it differs per installation.

**The trade-off is real.** Domain tools carry their own documentation in the
schema — `get_alerts(severity: str)` tells a model what is possible;
`search(index, body)` tells it nothing. Response size becomes unpredictable.
Reach is unbounded. Klaxon accepts those costs and pays them back through
`schema` (which replaces the knowledge that used to live in the tool signature)
and the diagnostics layer (which replaces the predictability given up with the
fixed response format). Without both, a generic search tool would be worse than
domain tools, not better.

**Architectural rule: thick on the indexer, thin on the manager API.** The
indexer side — datastream names, WCS schema — is anchored in engine source and
stable. The manager API is volatile; that is what both predecessor servers died
of, and more breakage lands at GA (`/var/ossec` → `/var/wazuh-manager`,
clustering by default, agent id `000` removed).

---

## The design rule: HTTP 200 is not the same as an answer

OpenSearch answers a query against a non-existent wildcard pattern with an empty
hit list and HTTP 200. It answers a terms aggregation on an unpopulated field
with zero buckets and HTTP 200. Neither is an error, and both look exactly like
*there is no data*.

Three real failures this causes:

- `gbrigandi/mcp-server-wazuh` hardcodes `/wazuh-alerts*/_search`
  (`wazuh-client-0.1.8/src/indexer_client.rs:101`). That pattern does not exist
  in Wazuh 5, so the server reports "no alerts" instead of "wrong index". The
  same query body assigns `sort` twice and effectively sorts on `timestamp`, a
  field that does not exist in 5.x either.
- `gensecaihq/Wazuh-MCP-Server` is built better — `_search()` takes the index as
  a parameter — but no tool schema exposes it, and the aggregations are wired to
  `rule.id`, `rule.level`, `rule.description`, `agent.name`.
- The instructive one: `rule.id` *does* exist in Wazuh 5 network events, where it
  holds the originating device's firewall rule hash — not a Wazuh detection rule
  id. Pointed at v5 data, that tool returns neither an error nor an empty list,
  but plausible-looking buckets of firewall hashes labelled "Top Rules", with
  `description: null`.

So: **a silently wrong answer is worse than a clean error.** When a field is
missing, an index does not exist, or an aggregation comes back empty, these
tools say so explicitly instead of formatting it away. Diagnostics are prepended
as a separate block; the raw JSON underneath is never rewritten.

A third project, `Sbharadwaj05/sb-siem-mcp`, targets 4.x as well but states its
version boundary in its own README. It is not broken — it is built for a
different Wazuh generation. Worth noting, because "the others are broken" is not
the argument; "the shape no longer fits the data model" is.

---

## The `agent.id` trap

The single most important finding in the 5.x schema, and the reason the `schema`
tool exists:

| Field | Mapped | Populated |
|---|---|---|
| `agent.id` | keyword | **never** |
| `wazuh.agent.id` | keyword | yes |

Both are `keyword` in the mapping, so `_field_caps` cannot tell them apart. A
terms aggregation on `agent.id` returns empty buckets and HTTP 200. Only the
`wazuh.*` branch is written. `schema` with `only_populated=true` runs a second
pass with `exists` aggregations and reports the document count per field, which
is what makes the difference visible.

The same shadowing applies to `rule.*` versus `wazuh.rule.*` in
`wazuh-findings-v5-*`: all 37 fields under `rule.` are mapped and none carry a
value.

---

## Wazuh 5 index layout

`src/engine/source/builder/src/builders/stage/indexerOutput.cpp:59` enforces:

```
^wazuh-events-v5-(?:[a-z0-9.-]+|\$\{[^}]+\})*$
```

`wazuh-alerts-#` is an explicit FAILURE test case in
`indexerOutput_test.cpp:63`. **`wazuh-alerts-*` does not exist in Wazuh 5.**

Two naming schemes are in use, depending on the integration's output stage:

| Scheme | Example |
|---|---|
| `wazuh-events-v5-${wazuh.integration.category}` | `wazuh-events-v5-network-activity` |
| `wazuh-events-v5-${category}-${name}` | `wazuh-events-v5-cloud-services-aws` |

These are **datastreams**. Backing indices are named
`.ds-wazuh-events-v5-network-activity-000001`. Always query the wildcard
pattern, never a backing index.

The eight categories
(`src/engine/source/cmstore/interface/cmstore/categories.hpp:25-32`, fixed set,
not extensible — the eighth entry is the `UNCLASSIFIED_CATEGORY` constant from
line 17, not a string literal): `access-management`, `applications`,
`cloud-services`, `network-activity`, `other`, `security`, `system-activity`,
`unclassified`.

---

## Field model reference

From `src/engine/ruleset/schemas/engine-schema.json` — **2,351 fields** total.
Namespace sizes: `wazuh`=492, `threat`=444, `process`=391, `file`=144, `tls`=77,
`host`=57, `observer`=53, `dll`=46, `user`=46, `client`=35, `destination`=35,
`server`=35.

| Field | Type | Note |
|---|---|---|
| `@timestamp` | date | the time field |
| `timestamp` | — | **does not exist**; 4.x servers sort on it and hit nothing |
| `wazuh.agent.id` | keyword | populated |
| `agent.id` | keyword | mapped, empty |
| `wazuh.rule.level` | keyword | severity as a **string**, not a 4.x numeric level |
| `rule.level` | keyword | mapped, empty |
| `source.ip` | ip | |
| `destination.port` | long | |
| `event.action` | keyword | |
| `network.protocol` | keyword | |

Two observations from a live instance that are easy to misread:

**`network.protocol` resolves port names.** The OPNsense decoder looks the
destination port up in a KVDB and falls back to the numeric port when there is
no entry. So port 23 yields `telnet` and port 59884 yields `"59884"`. Not a
field mix-up — a design choice with a numeric fallback. ECS expects an
application protocol there, so strict filters on this field are unreliable.

**`event.original` is `"index": false`.** It carries the full raw log line and
is returned in `_source`, but an `exists` aggregation returns 0 for it
regardless. Coverage measurement therefore has to be three-valued; see
[`field_coverage`](#field_coverage) below.

---

## The diagnostics layer

Every response gets a prepended block naming structural problems. The raw JSON
below it is never modified.

| Notice | Raised when |
|---|---|
| `[ZERO HITS]` | No hits — names the pattern queried so a typo stays visible |
| `[EMPTY AGGREGATION]` | Zero buckets with a non-empty scope — field mapped, never populated |
| `[PARTIAL AGGREGATION COVERAGE]` | Buckets cover only part of the scope — how decoder gaps surface |
| `[SIZE CAPPED]` | `size` lowered to `WAZUH_SEARCH_MAX_SIZE`, naming both values |
| `[TOTAL HITS CAPPED]` | `hits.total.relation == "gte"` — OpenSearch caps at 10,000 without `track_total_hits` |
| `[LEGACY INDEX PATTERN]` | Query against a 4.x index that does not exist in 5.x |
| `[LOGTEST NORMALIZATION FAILED]` | HTTP 200 with `normalization.status = "error"` nested in the body |
| `[COVERAGE DRIFT]` | Window and datastream coverage differ by more than 20 percentage points |

### Scope, not total

Coverage is measured against the number of documents the aggregation was
actually computed over — `hits.total` at the top level, the parent bucket's
`doc_count` inside a terms bucket, a single-bucket aggregation's own `doc_count`
inside a filter. A nested aggregation can never cover more documents than its
parent, so measuring it against `hits.total` reports a gap that does not exist.

An aggregation over an empty scope is empty by definition, not by fault: a
`filter` aggregation that matched nothing produces zero buckets correctly, and
that case is skipped rather than reported.

### Field-aware hints

The response carries no field names, so the aggregation path is resolved back
against the request body to find out which field an empty aggregation was
computed on. The shadowed-namespace hint (`agent.*` → `wazuh.agent.*`) fires
only when the field actually sits in a shadowed namespace. Appending it to every
empty aggregation makes the notice wrong more often than right, and a diagnostic
that cries wolf is worse than none.

---

## Design notes per tool

### `search`

Index names are validated before interpolation: charset `[a-z0-9-_.*,]` only, no
`..`, no leading `/` or `_`, max 255 characters — so the parameter cannot be
used to address a different endpoint.

`size` is capped at `WAZUH_SEARCH_MAX_SIZE` (default 100) **before** the query is
sent. A Wazuh 5 event carries around 40 fields, so `"size": 10000` returns more
document than any caller can hold. The cap is reported as `[SIZE CAPPED]` naming
both the requested and effective value — a shortened result the caller never
hears about is the same silent-wrong-answer failure the rest of this design
exists to prevent. `"size": 0`, the normal shape of an aggregation-only query,
is never touched.

### `schema`

`_field_caps` reports only what is *mapped*. `only_populated=true` adds a second
pass of `exists` aggregations, batched via `WAZUH_SCHEMA_PROBE_BATCH`, and
returns only fields with `doc_count > 0`.

With 2,351 fields in the schema, an unfiltered `fields=*` is unusable — without
a `prefix` and with `only_populated=false` the listing is hard-capped
(`WAZUH_SCHEMA_FIELD_LIMIT`, default 200) and says so.

### `logtest`

Both enums were read off a live 5.0 instance rather than documentation, which
does not cover them: an invalid trace level is answered with *"Only support:
NONE, ASSET_ONLY, ALL"* and an invalid space with *"Logtest is only supported
for the 'test', 'custom' and 'standard' spaces."* `ASSET_ONLY` is the level that
populates `asset_traces` with the matched decoder chain.

A valid space name does not mean the environment exists. The plugin answers
**HTTP 200** with `message.normalization.status = "error"` and *"The 'custom'
environment does not exist."* — a failure nested inside a success.

The cause is worth knowing: "environment" here is a **tester session**, not a
policy or a space. Sessions live in an in-memory table in
`src/engine/source/router/src/tester.cpp`, are persisted to the engine state
store under `router/tester/0` (`orchestrator.hpp:41`), and are created as a
side effect of importing a policy through the CM API
(`api/cmcrud/src/handlers.cpp:453`). They are not derived from decoder content.
A container rebuilt with fresh engine state has the sessions CMSync creates
automatically and nothing else — which is why `custom` can vanish after an
upgrade while the production pipeline keeps running.

### `manager`

GET only, with a path allowlist against traversal. Non-2xx responses are passed
through unchanged, **including 404** — a 404 on `/rules` is a correct and
informative answer, not an error to swallow.

Measured against a running 5.0 instance:

| Endpoint | Status |
|---|---|
| `/agents` | works |
| `/syscollector/{id}/...` | works |
| `/rules` | 404 — correct, there are no engine rules any more |
| `/manager/logs` | 404 |
| `/manager/stats/remoted` | 404 |
| `/cluster/healthcheck` | schema changed, `enabled` field gone |
| `/cluster/nodes` | schema changed, `node_type` field gone |

### `detectors`

`list` uses `POST /_plugins/_security_analytics/detectors/_search` with
`match_all`; the plugin exposes no list-all endpoint. Detector documents are
nested under the `detector` path.

### `tester_sessions`

Read-only by design. `session/post`, `session/delete` and `session/reload` are
deliberately not implemented: a hand-created session is replaced at the next
policy import, so exposing them would invite a workaround that does not hold.

The engine's HTTP routes live inside the **manager** container, not on the
indexer — hence the separate `WAZUH_ENGINE_URL`.

### `findings_overview`

**Why the full severity scale is printed.** A terms aggregation returns the
values it found and only those. When `critical` is missing from the response,
the buckets cannot distinguish *no critical findings occurred* from *this field
never carries that value* — both render as an absent row, and an absent row
reads as a zero nobody checked. So the tool prints the whole scale in canonical
order with an explicit `0`. A report claiming "no critical findings" can then
point at the row it read that from.

A value outside the scale is added and marked `UNKNOWN` rather than dropped —
the scale was measured on one instance, it is not a guarantee. Values are
compared exactly: a `Medium` bucket is reported as unknown next to `medium`, not
folded into it, because folding would hide a mapping change behind a number that
still looks plausible.

Before aggregating, the tool runs the same `exists` probe as `schema` against
`wazuh.rule.level`. Three distinct outcomes, never conflated:

| State | Response |
|---|---|
| Field empty index-wide | `[SEVERITY FIELD UNPOPULATED]`, no table — a scale of zeros would claim nothing was found when nothing was ever measured |
| Probe itself failed | `[PROBE FAILED]`, overview still produced, zeros flagged as unverified |
| Window empty | `[EMPTY WINDOW]`, naming the document count that *does* exist index-wide |

### `field_coverage`

**Why two measurements.** `schema` counts over the whole datastream, which is
the wrong denominator for this question — a datastream spans decoder
generations. Measured on a live instance for `event.action` in
`wazuh-events-v5-network-activity*`:

| Scope | Documents | Coverage |
|---|---:|---:|
| whole datastream | 10,238,381 | 8.1 % |
| last 24 hours | 348,247 | 71.0 % |
| last 12 hours | | 100.0 % |

A decoder fix had landed hours earlier. All three numbers are correct and they
describe different things: 8.1 % is the history of the index, 100 % is the state
of the pipeline. Reporting either one alone is true in the arithmetic and false
in the conclusion, so both are always shown — and a gap wider than 20 percentage
points raises `[COVERAGE DRIFT]`. That gap is the signature of a normalisation
change inside the datastream, which makes it the mechanism for detecting
configuration drift over time.

**Coverage is three-valued: populated, not populated, not measurable.** An
`exists` aggregation returns 0 for a field the mapping declares `"index": false`
no matter what the documents contain. Verified on a live instance:
`event.original` in `wazuh-events-v5-network-activity*` carries the full raw log
line in `_source` and returns 0 of 13,948 documents on `exists`.

The tool therefore reads `GET /{index}/_mapping` first. A non-indexed field is
reported as `unmeasurable`, **never** as 0 % or "never populated", and a
`_source` sample is taken to state whether the key is present. Reporting a
populated field as empty would be precisely the failure this project exists to
prevent — the tool committed it once during development before the mapping check
was added.

---

## The anonymization layer

Klaxon is a tool server, not an agent: it does not compose prompts or call an
LLM. Tool results go back to the MCP client, and the client feeds them to the
chat model. So the only point where personal data can leave the operator's
network is the **tool response boundary** — which is where the anonymization
layer sits. There is no prompt text to whitelist server-side; the equivalent
guarantee is that no tool response carrying unmasked PII is ever returned to an
external client.

Three mechanisms, in order (see `src/klaxon_mcp/anonymization.py`):

1. **Structured pass.** `mask_json` walks the parsed response with the dotted
   field path (`hits.hits._source.source.ip`) and replaces values under
   configured fields wholesale. This is the only pass that can mask a bare
   username: it knows `user.name` *means* a username, where no regex could
   tell. `findings_overview` gets its own variant (`mask_overview`) that masks
   agent names before the tables are rendered.
2. **Text pass.** `mask_text` runs over the fully rendered output — tables,
   summaries, footers — masking e-mails, IPv4/IPv6 addresses, and usernames in
   their log context (`user=…`, `login as/for/by …`). The username pass runs
   *after* the value-type passes so a source address can never be captured as a
   username. It is deliberately conservative: bare `from`/`with` connectors
   would eat ordinary prose ("Prevent access from external hosts"), so they are
   not in the connector set.
3. **The gate.** `verify` scans the masked output for residual IP addresses and
   e-mails — the value types the masker *guarantees*. A residual means a masking
   gap, and with the whitelist on (the default) the response is **blocked**:
   the caller gets a `GDPR BLOCKED` notice, never the data. This is the
   fail-closed reading of "no false negatives": where masking cannot be certain
   (a username in unrecognised free text), the gate still covers the classes
   that can be verified mechanically.

**Determinism and no-PII-by-default.** Placeholders are derived from the value
itself (MD5 or SHA-256, truncated to six hex digits), so the same value maps to
the same placeholder across requests without shared state. The audit log stores
MASKED output only; RAW output is written only when
`KLAXON_ANONYMIZATION_LOG_RAW=true`, which makes the log a personal-data store
and is warned about. The compliance report and the export command both emit
placeholders and counts, never the underlying values — the export drops RAW
lines, so the artifact for access requests contains no unmasked personal data.

**Activation.** `enabled and not llm_base_url on loopback`. An unset endpoint
is treated as external: in a GDPR context, failing to mask is the expensive
failure, so the unknown is assumed to leave the network. Local models (Ollama,
vLLM on localhost) are exempted by a loopback `KLAXON_LLM_BASE_URL`.

---

## Deliberately not built

- **No tool per data category.** The eight categories are parameter values.
- **No pretty-printing of `search` hits.** Raw JSON. The field model is the
  caller's business, and any fixed field assumption is how the "Top Rules" bug
  above happened. The convenience tools are the deliberate exception: they cover
  queries that recur in every report and are validated against the live field
  model before they run.
- **No alert-level or rule-level logic.** Neither exists in Wazuh 5.
- **No 4.x compatibility layer.** No translation of 4.x field names, no
  emulation of `wazuh-alerts-*`.
- **No write access.** Read-only throughout.
- **No caller identity.** Every request runs with the credentials from the
  environment. Authorisation belongs in the indexer — run Klaxon as
  `wazuh-readonly`, not `admin`.

---

## Version scope

Developed and verified against Wazuh 5.0.0-beta3 and beta4.

`search` and `schema` carry no field-model assumptions and work against a Wazuh
4.x indexer as well — useful for capturing a before-state ahead of a migration.
`logtest`, `manager`, `detectors` and `tester_sessions` are 5.x-specific.

The convenience tools (`findings_overview`, `field_coverage`) target the 5.x
field model. `field_coverage` will run against 4.x indices, but the field names
it reports will be 4.x ones.

Beta means the field model moves. `event.action` coverage on the reference
instance went from 13 % to 100 % in an afternoon because a decoder was fixed.
Treat any measurement as a snapshot, not a constant.
