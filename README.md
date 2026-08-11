# Klaxon

**The alarm tells you *that*. Klaxon tells you *what*.**

Klaxon connects a language model directly to your Wazuh 5 cluster. You ask
questions in plain language; it queries the indexer, reads the schema, tests
decoders, and reports what it actually found — including when it found nothing,
and why.

Works with Claude Desktop, Claude Code, and local models through Ollama. Klaxon itself runs beside your cluster and talks to it directly — no third party sits between the two. Where the query results go from there is your choice of model: with a local model through Ollama, nothing leaves your network at all.

---

## What you can use it for

**Understand what your SIEM is actually collecting.**
Which fields carry data and which are mapped but always empty. How complete your
normalisation is. Where a decoder is dropping information you assumed was there.

**Investigate without writing queries.**
"Show me blocked connections by source country in the last 24 hours." "Which
users logged in, and how many of those were over the network?" No query DSL, no
dashboard clicking.

**Debug decoders.**
Push a raw log line through the decoder chain and see which decoders matched,
what they produced, and where the chain stopped.

**Check before and after a change.**
Field coverage measured over a time window and over the whole datastream. When
those two numbers diverge, something in your normalisation changed — a decoder
fix, a new integration, a broken one.

**Produce recurring reports.**
Findings by severity and agent, coverage per index — as fixed tools that a small
local model can call reliably.

### What it will not do

Klaxon is read-only with respect to your environment. It never writes to the indexer, 
never modifies configuration, never deletes anything, and never promotes or installs a policy. 
The one endpoint that is not a plain read is logtest: it submits a line to the engine's tester, 
which evaluates it against an existing tester session. It does not touch stored data, 
and it does not create or alter the policies your cluster runs on.

It has **no concept of who is asking**. Every request runs with the credentials
in its environment, so anyone who can reach it can read everything those
credentials can. Run it as `wazuh-readonly`, not `admin`.

It does not replace your dashboards, and it will not tell you what to do about
what it finds.

---

## Requirements

- Wazuh 5.0 or later, indexer reachable over HTTPS
- Python 3.11+
- An MCP client — Claude Desktop, Claude Code, `ollmcp`, Open WebUI 0.6.31+, or
  any other

`search` and `schema` also work against a Wazuh 4.x indexer. The other tools are
5.x-specific.

---

## Setup

**1. Install**

```bash
python3 -m venv .venv
.venv/bin/pip install klaxon-mcp
```

**2. Configure**

Copy [`.env.example`](.env.example) to `.env` and fill in your endpoints:

```bash
WAZUH_INDEXER_URL=https://indexer.example:9200
WAZUH_INDEXER_USER=wazuh-readonly
WAZUH_INDEXER_PASSWORD=...
```

Only `WAZUH_INDEXER_URL` is required. Add `WAZUH_MANAGER_URL` for the `manager`
tool and `WAZUH_ENGINE_URL` for `tester_sessions` – see
[Configuration](#configuration).

**3. Wrap it** so the credentials stay in one place:

```bash
cat > run-klaxon.sh <<'EOF'
#!/usr/bin/env bash
set -a; . "$(dirname "$0")/.env"; set +a
exec "$(dirname "$0")/.venv/bin/klaxon-mcp"
EOF
chmod +x run-klaxon.sh
```

**4. Register with your client**

*Claude Desktop* — `~/.config/Claude/claude_desktop_config.json` on Linux,
`~/Library/Application Support/Claude/` on macOS:

```json
{
  "mcpServers": {
    "klaxon": {
      "command": "/path/to/klaxon/run-klaxon.sh"
    }
  }
}
```

Restart Claude Desktop completely afterwards.

*Claude Code:*

```bash
claude mcp add klaxon /path/to/klaxon/run-klaxon.sh
```

*Ollama* — via [`ollmcp`](https://github.com/jonigl/mcp-client-for-ollama):

```bash
uv tool install --upgrade ollmcp
ollmcp mcp add klaxon -- /path/to/klaxon/run-klaxon.sh
ollmcp -m qwen3:14b
```

---

## First questions to ask

Once connected, these work as plain prompts:

> Which fields under `wazuh.agent.` are populated in network-activity?

> How many events per category in the last 24 hours?

> Show me the field coverage for `event.*` in network-activity.

> Give me the findings overview for the last 48 hours.

> Run this log line through the decoder chain: *(paste a raw line)*

A useful first move on an unfamiliar cluster is asking for field coverage on the
index you care about. It tells you what is actually there before you build a
question around a field that turns out to be empty.

### Using a local model

Klaxon works with local models, but the two halves of the job are not equally
easy for them.

Measured with Qwen3 14B at 32k context: calling a tool with fixed parameters and
running simple aggregations is reliable. Writing nested query DSL by hand is
not — it tends to invent `.keyword` suffixes and misplace sub-aggregations.

Two things help:

**Use the fixed tools.** `findings_overview` and `field_coverage` need no query
DSL at all. `field_coverage(index=..., prefix="event.")` is a parameter fill,
not a construction task.

**Give it the field conventions.** A short system prompt prevents most failures:

```
You work with Klaxon against a Wazuh 5 indexer.
- Never guess field names. Call klaxon.schema first for an unfamiliar index.
- The .keyword suffix does not exist in Wazuh 5.
- Agent data is under wazuh.agent.*, rule data under wazuh.rule.*.
  The time field is @timestamp.
- For questions about a specific action, first query the available
  event.action values, then filter on them.
- Read the DIAGNOSTICS block. An empty aggregation usually means
  wrong field, not no data.
```

Open-ended exploration — *"find anything unusual"* — is where local models fall
short, because "unusual" needs a baseline they do not have. Ask specific
questions instead, or use a stronger model for that part.

---

## Tools

| Tool | What it does |
|---|---|
| `search` | Any OpenSearch query against any index. Raw JSON back, aggregations included. |
| `schema` | Which fields exist, and which of them actually carry data. |
| `field_coverage` | How complete each field is — in a time window and over all history. |
| `findings_overview` | Findings by severity, agent, rule title and category. |
| `logtest` | Push a log line through the decoder chain and see what matched. |
| `manager` | Read-only access to the Wazuh manager API. |
| `detectors` | List and inspect Security Analytics detectors. |
| `tester_sessions` | Which logtest environments exist — the usual cause of a failing `logtest`. |

Full parameter reference: [`docs/TOOLS.md`](docs/TOOLS.md).
Design rationale: [`ARCHITECTURE.md`](ARCHITECTURE.md).

### One thing worth knowing up front

Klaxon always tells you when a result is thinner than it looks. An empty
aggregation, a capped result set, a query against an index that does not exist —
each gets a note before the data, because in OpenSearch all three come back as a
perfectly successful `HTTP 200` with nothing in it.

The most common case: `agent.id` exists in the Wazuh 5 schema and is *never*
populated. The real field is `wazuh.agent.id`. Aggregate on the wrong one and
you get zero buckets, no error, no warning — a result that looks like "no data"
and means "wrong field". `schema` and `field_coverage` make that visible.

---

## Configuration

All configuration is environment variables, and no credential is baked into
the Docker image. The one optional exception is the `anonymization:` block of a
YAML file (`KLAXON_CONFIG`, default `./config.yaml`) — a convenience for
shipping masking rules; environment variables still take precedence over it.

| Variable | Default |
|---|---|
| `WAZUH_INDEXER_URL` | — (required) |
| `WAZUH_INDEXER_USER` / `_PASSWORD` | empty |
| `WAZUH_MANAGER_URL` | empty (disables `manager`) |
| `WAZUH_MANAGER_USER` / `_PASSWORD` | empty |
| `WAZUH_ENGINE_URL` | empty (disables `tester_sessions`) |
| `WAZUH_VERIFY_SSL` | `true` (setting it `false` logs a warning at startup) |
| `WAZUH_TIMEOUT` | `60` |
| `WAZUH_SEARCH_MAX_SIZE` | `100` (`0` disables the cap) |
| `WAZUH_SCHEMA_FIELD_LIMIT` | `200` |
| `WAZUH_SCHEMA_PROBE_BATCH` | `100` |
| `WAZUH_LOGTEST_SPACE` | `custom` |
| `WAZUH_LOGTEST_TRACE_LEVEL` | `ASSET_ONLY` |

Those are three separate endpoints: the indexer, the manager API, and the
engine's own HTTP server — the last runs inside the manager container but on a
different port from the manager API.

---

## Anonymization for external LLM clients (GDPR)

Klaxon returns tool results to the MCP client, and the client feeds them to the
chat model. When that model runs **outside your network** — DeepSeek cloud,
Mistral API, anything that is not `localhost` — the results physically leave
the building. The anonymization layer makes sure they leave without personal
data:

```
[Wazuh indexer] → (tool result) → (anonymization) → [masked result] → [external LLM]
```

It is **off by default** and opt-in:

```bash
KLAXON_ANONYMIZE_EXTERNAL_LLM=true klaxon-mcp
```

With the switch on, tool output is masked unless the LLM endpoint is provably
local. Set `KLAXON_LLM_BASE_URL` to a loopback address (e.g.
`http://localhost:11434` for Ollama) and a local model keeps receiving
**unchanged** data; an unset endpoint is treated as external, which is the
GDPR-safe failure.

**How masking works.** Two passes plus a gate:

1. *Structured pass* — values under configured fields (`source.ip`,
   `user.name`, `wazuh.agent.name`, `wazuh.agent.id`, `host.hostname`, ...) are
   replaced wholesale with **deterministic placeholders**: the same value
   always maps to the same placeholder. With hashing on (default) they look
   like `[IP_abc123]`, `[USER_def789]`, `[HOST_xyz456]`, `[AGENT_ghi012]`,
   `[EMAIL_jkl345]` (MD5 or SHA-256, first six hex digits); with hashing off
   they are generic labels (`[IP_ADDRESS]`, `[USERNAME]`, ...).
2. *Text pass* — IP addresses, e-mails and usernames in their log context
   (`user=admin`, `Failed login for admin from 192.168.1.100`) are masked
   anywhere in the rendered output, including free-text log lines.
3. *Gate* — the masked output is scanned for residuals. With the whitelist
   enabled (default), a response that still contains an IP or e-mail is
   **blocked**: you get a `GDPR BLOCKED` notice instead of the data, so no
   unmasked PII can reach an external model.

**What is and is not guaranteed.** Every value under a configured field is
masked — that is structural and exact. With `mask_aggregation_keys` on (off by
default), aggregation bucket keys whose source field is configured get the same
deterministic tokens as `_source` — `terms` on `related.hosts` returns
`[HOST_…]` tokens, and `composite` `after_key` stays consistent with the
tokenised keys, so pagination keeps working. With `mask_free_text_users` on (the
default), usernames inside free-text fields (`message`, `*.log`, `raw`, ...) are
masked too, with the same tokens as the structured fields — a `uid=marcomoenig`
inside a log line becomes the same `[USER_…]` token as `user.name` in the same
document. IP addresses, e-mails and the standard username formulations are
masked in free text. A username that appears in free text in an unrecognised
form is the one thing a regex cannot be certain about; treat the gate's residual
scan as the guarantee that matters for the reliably detectable classes (IPs and
e-mails). Review the rules by adding your own fields to
`KLAXON_ANONYMIZATION_MASK_FIELDS` or the `anonymization:` block of a YAML
config file (`KLAXON_CONFIG`, precedence env > YAML > default):

```yaml
anonymization:
  enabled: true
  llm_base_url: "https://api.deepseek.com/v1"
  use_hash: true
  salt: "change-me-to-a-long-random-secret"  # or KLAXON_ANONYMIZATION_SALT
  mask_fields:                 # or KLAXON_ANONYMIZATION_MASK_FIELDS
    - "source.ip"
    - "destination.ip"
    - "user.name"
    - "user.effective.name"
    - "host.hostname"
    - "wazuh.agent.name"
    - "wazuh.agent.id"
  mask_aggregation_keys: true  # or KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS
  mask_free_text_users: true   # or KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS
  mask_free_text_fields:       # or KLAXON_ANONYMIZATION_MASK_FREE_TEXT_FIELDS
    - "message"
  whitelist_enabled: true
  log_path: "llm_prompts.log"
  log_raw: false
```

**Audit trail.** Every masked exchange is logged with a UTC timestamp to
`KLAXON_ANONYMIZATION_LOG` (default `llm_prompts.log`), MASKED output only — no
raw PII is persisted unless you explicitly set `KLAXON_ANONYMIZATION_LOG_RAW=true`
(and then the log is itself a personal-data store; the server warns about that).

**Compliance tooling** (no Wazuh environment needed):

```bash
klaxon-mcp --anonymization-status            # enabled? for which LLM?
klaxon-mcp --anonymization-report            # GDPR compliance report (stdout)
klaxon-mcp --anonymization-report report.txt # ... or to a file
klaxon-mcp --anonymization-export export.log # anonymized log for access requests
```

The export drops RAW lines, so the artifact handed over for data-subject access
requests (Auskunftsanfragen) contains no unmasked personal data.

In the Docker image the server runs as an unprivileged user and the working
directory is not writable, so point `KLAXON_ANONYMIZATION_LOG` at a writable
path (e.g. `/tmp/llm_prompts.log`) when you enable anonymization there. If the
log cannot be written the masking still applies — only the audit trail is lost,
and the server logs that as an error.

---

## DSGVO plausibility checker

Anonymization masks what is *configured*; the checker is the other half — it
asks "what *should* be configured". It reads an index's mappings, samples a few
documents, classifies the fields, and proposes additions to the anonymization
list, so you discover personal data you did not know you were collecting.

Three classification layers, in decreasing certainty:

1. **Custom rules** from `gdpr_checker.custom_patterns` in config.yaml — the
   operator's knowledge always wins over heuristics.
2. **Field-name patterns**: `source.ip` is an IP by construction, `user.name` a
   username, `host.hostname` / `wazuh.agent.name` hostnames, `user.email` an
   e-mail. No documents needed.
3. **Sampled values**: a few `_source` documents are pulled and the actual
   values are checked — `custom.peer` holding `192.168.1.100` is an IP even
   though the name says nothing, and a free-text field like `event.original`
   embedding `Failed login for admin from 192.168.1.100` is flagged as
   free text carrying personal data.

Priorities follow the spec: IPs, usernames and e-mails are directly personal
(**high**); hostnames and agent ids are indirectly personal (**medium**); free
text embedding personal data is flagged too. Fields already in `mask_fields`
are reported as covered, not re-suggested.

```bash
# MCP tool (run through your client)
#   gdpr_check(index="wazuh-events-v5-*", apply=true)

# CLI — the same analysis, exits after running
klaxon-mcp --gdpr-check wazuh-events-v5-* --gdpr-dry-run
klaxon-mcp --gdpr-check wazuh-events-v5-* --gdpr-auto-add   # apply without prompting
klaxon-mcp --gdpr-check --gdpr-json --gdpr-out report.json  # machine-readable

# standalone entry point (same code, same flags)
klaxon_check_gdpr --index wazuh-events-v5-* --auto-add
```

Without `--gdpr-auto-add` (or `apply=true`) on a TTY, each field is confirmed
interactively:

```
Feld "user.name" (USERNAME, high) ist DSGVO-relevant. Zur Anonymisierungsliste hinzufügen? [Y/n]
```

`--gdpr-exclude` / the tool's `exclude` parameter skips fields (internal ones
without GDPR relevance). Applying merges the fields into
`anonymization.mask_fields` of config.yaml, appends to `gdpr_check.log`, and
writes `gdpr_compliance_report.json`:

```json
{
  "timestamp": "2026-08-08T12:59:29+00:00",
  "index": "wazuh-events-v5-*",
  "checked_fields": 42,
  "sensitive_fields_found": 3,
  "anonymization_updated": true,
  "fields_added": ["source.ip", "user.name"]
}
```

The report is the artifact to forward to a SIEM/log-management tool for central
compliance monitoring. Note the environment precedence: if
`KLAXON_ANONYMIZATION_MASK_FIELDS` is set it overrides the file, and the checker
warns about that. The running server picks up file changes on restart.

**Automatic triggers.** `KLAXON_GDPR_CHECK_ON_SEARCH=true` makes `search` append
a `[GDPR]` notice naming sensitive fields present in the hits (a cheap name
scan, no extra requests). `klaxon-mcp --check-gdpr-on-startup` runs one check
before serving — it applies only together with `--gdpr-auto-add`, and dry-runs
otherwise.

---

## Option B: the masked stream (`klaxon masking`)

Option B moves masking to the ingest side: a periodic sync job reindexes a
window of the raw Wazuh stream through a generated ingest pipeline into a
separate masked stream (`klaxon-masked-<tenant>-v5-*`). Full design and
operation: `docs/option-b-masked-stream.md`.

`klaxon masking` is the **single generator** for the deployable artifacts — it
only outputs files/stdout, never writes to the indexer (deploying is the
operator's/CI's job):

```bash
# build the 4 artifacts (config fragment, pipeline, ISM, index template) from
# tenants/<tenant>/fields.yaml; the mandatory self-test runs first
klaxon masking generate --tenant customer-a
klaxon masking generate --tenant customer-a --out /tmp/deploy   # real salt in params.salt
klaxon masking generate --tenant customer-a --stdout            # ... or to stdout

# prove the generated Painless token scheme is byte-identical to derive_token
klaxon masking selftest [--tenant customer-a]

# compare the salt baked into the DEPLOYED pipeline with the current env salt
klaxon masking salt-check --tenant customer-a

# CI/pre-commit drift check: committed artifacts must match fields.yaml
klaxon masking generate --check
```

`klaxon-mcp` is a compatibility alias for `klaxon`. The salt comes from the
same environment variable as the response layer
(`KLAXON_ANONYMIZATION_SALT`, or `salt_env` in `fields.yaml`); if it is unset a
random salt is generated with a warning (tokens rotate unless the salt is
stable). `related.hash` is never masked.

---

## Docker

```bash
docker build -t klaxon-mcp .
docker run --rm -i --env-file .env klaxon-mcp
```

`-i` is required: the server communicates over stdio.

If Wazuh runs on the Docker host itself, `localhost` inside the container is the
container. Either add `--add-host=host.docker.internal:host-gateway` and use that
hostname in `.env`, or run with `--network host`.

---

## Running it on another machine

By default Klaxon speaks stdio and is started by your MCP client as a child
process. To run it elsewhere — next to the Wazuh cluster, say – serve it over
HTTP:

```bash
export WAZUH_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
klaxon-mcp --transport http --host 0.0.0.0 --port 8000 \
           --allowed-host klaxon.example:8000
```

```bash
claude mcp add --transport http klaxon https://klaxon.example:8000/mcp \
  --header "Authorization: Bearer $WAZUH_MCP_AUTH_TOKEN"
```

### Read this before opening the port

**The tools have no concept of a caller identity.** Every request is executed
with the Wazuh credentials from the environment. Anyone who can open a TCP
connection to that port can read your entire SIEM. Over stdio this does not
arise, because the process is spawned by the client and inherits its trust
boundary; a listening socket is a different proposition entirely.

Three controls, in order of importance:

1. **`WAZUH_MCP_AUTH_TOKEN`** — a shared secret required as
   `Authorization: Bearer <token>`, compared in constant time. Without it the
   server logs `SERVING WITHOUT AUTHENTICATION` at startup and serves anyone.
2. **TLS** — the server speaks plain HTTP. A bearer token over cleartext is a
   token you have published. Terminate TLS in a reverse proxy in front of it.
3. **`--allowed-host`** — DNS rebinding protection. Locked to loopback names on
   a loopback bind; on a public bind it uses your allowlist or warns that the
   protection is off.

The most defensible setup is to bind loopback and let a proxy handle TLS and
authentication:

```bash
klaxon-mcp --transport http --host 127.0.0.1 --port 8000
```

`GET /healthz` is exempt from authentication for load-balancer probes.

**Also worth considering:** the tool output contains whatever your SIEM contains
— IP addresses, usernames, hostnames, login times. All of it reaches the model
you point at Klaxon. If that model is hosted elsewhere, so is the data. Under
GDPR that is a processing decision, not a technical detail.

Transport options are listed in [`docs/TOOLS.md`](docs/TOOLS.md).

---

## Open WebUI

Open WebUI talks to Klaxon over streamable HTTP and to a chat model over an
OpenAI-compatible API. The two are configured separately: Klaxon is a tool
server, the model is what decides to call it.

Requires **Open WebUI v0.6.31 or later** — that is the release that added native
MCP support. Earlier versions need the [`mcpo`](https://github.com/open-webui/mcpo)
proxy instead, which converts MCP to OpenAPI. You need an admin account; MCP
servers cannot be added by regular users.

**1. Serve Klaxon over HTTP**

```bash
export WAZUH_MCP_AUTH_TOKEN=$(openssl rand -hex 32)
klaxon-mcp --transport http --host 0.0.0.0 --port 8000 \
           --allowed-host klaxon.example:8000
```

Read [Read this before opening the port](#read-this-before-opening-the-port)
first if you have not — this is a listening socket with SIEM credentials behind
it.

**2. Add the model** — *Admin Settings → Connections → OpenAI API → +*

| Field | Value |
|---|---|
| API Base URL | `https://api.deepseek.com/v1` |
| API Key | your key from [platform.deepseek.com](https://platform.deepseek.com/api_keys) |

DeepSeek's API is OpenAI-compatible, so no adapter is needed. If the model list
comes back empty, try the base URL without `/v1`. Then pick
**`deepseek-v4-flash`** in the model selector — it supports tool calling, which
is the part that matters here; a model without it will simply answer from
nothing rather than call Klaxon.

**3. Register Klaxon** — *Admin Settings → External Tools → + (Add Server)*

| Field | Value |
|---|---|
| Type | **MCP (Streamable HTTP)** — not OpenAPI |
| URL | `https://klaxon.example:8000/mcp` (include the path) |
| Auth | **Bearer**, key = your `WAZUH_MCP_AUTH_TOKEN` |

Choosing OpenAPI here hangs on an infinite load rather than failing cleanly, and
selecting Bearer while leaving the key empty sends an empty header and gets a
flat 401 — both are easy to mistake for the server being down.

If Open WebUI runs in Docker and Klaxon is on the host, `localhost` inside the
container is the container. Use `http://host.docker.internal:8000/mcp` and add
`--add-host=host.docker.internal:host-gateway` to the Open WebUI container.

Klaxon's eight tools should now appear in the tool picker. Give the model the
field-convention prompt from [Using a local model](#using-a-local-model) as the
system prompt — it prevents the same failures there as it does with Ollama.

### CORS is not needed here

Open WebUI connects to MCP servers **from its backend, not from your browser**,
so no `Access-Control-Allow-Origin` is involved — the `host.docker.internal`
guidance above is the giveaway, since a browser could not resolve it. What the
Open WebUI docs say about enabling CORS applies to *OpenAPI* "Direct Tool
Servers", which are a different, browser-side feature.

Set `WAZUH_MCP_CORS_ORIGINS` only for a genuinely browser-based MCP client:

```bash
WAZUH_MCP_CORS_ORIGINS=https://webclient.example
```

Comma-separated, one entry per origin, no trailing slash. `*` is refused: every
tool runs with the Wazuh credentials, so a wildcard would let any page a browser
loads read your SIEM from that browser's network position. A granted origin is
also added to the DNS rebinding allowlist, so the two checks cannot disagree.

To tell which case you are in, watch Klaxon's log while the client connects. A
browser client sends an `OPTIONS` preflight and an `Origin` header; a backend
client sends neither.

### Where your data goes

The README says nothing leaves your network, and with Ollama or a local model
that holds. A hosted API is a different arrangement: tool output contains
whatever your SIEM contains — IP addresses, usernames, hostnames, login times —
and all of it is sent to DeepSeek's servers to be processed. Under GDPR that is
a processing decision that needs to be made deliberately, not a configuration
detail. If it cannot leave, keep the model local.

---

## Troubleshooting

**An aggregation returns nothing but there is clearly data.**
Almost always the wrong field. `agent.id` and `rule.level` are mapped in Wazuh 5
but never populated; the real fields are `wazuh.agent.id` and `wazuh.rule.level`.
Ask for the schema with the relevant prefix.

**`logtest` says the environment does not exist.**
The logtest "environment" is a tester session, and sessions are created when a
policy is imported — not derived from your decoders. They live in engine state,
so a rebuilt container loses them. Use `tester_sessions` to see which ones exist;
`test` usually works when `custom` does not.

**A field shows 0 % coverage but you can see values in the documents.**
Some fields are mapped `"index": false` — `event.original` is one. They are
stored and returned but not searchable, so `exists` finds nothing.
`field_coverage` reports these as `unmeasurable` rather than empty.

**`manager` returns 404 on `/rules`.**
That is correct. Wazuh 5 has no rule content type in the engine; detection moved
to the OpenSearch Security Analytics plugin. Use `detectors` instead.

**Counts stop at 10,000.**
OpenSearch caps `hits.total` unless the query sets `track_total_hits: true`.
Klaxon flags this, and the fixed tools set it themselves.

---

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/mypy
```

The suite covers the input guards, the diagnostics layer and the network
transport, plus the acceptance criteria that do not need a live cluster.

Release history: [`CHANGELOG.md`](CHANGELOG.md).

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

---

Built by [sec73 GmbH](https://sec73.io).

Wazuh is a registered trademark of Wazuh Inc. Klaxon is an independent project
and is not affiliated with, endorsed by, or sponsored by Wazuh Inc.
