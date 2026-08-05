# Klaxon

**The alarm tells you *that*. Klaxon tells you *what*.**

Klaxon connects a language model directly to your Wazuh 5 cluster. You ask
questions in plain language; it queries the indexer, reads the schema, tests
decoders, and reports what it actually found — including when it found nothing,
and why.

Works with Claude Desktop, Claude Code, Open WebUI, and local models through
Ollama. Klaxon itself runs beside your cluster and talks to it directly — point
it at a local model and nothing leaves your network.

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

Klaxon is **read-only**. It queries, it never writes, deletes or reconfigures.

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
tool and `WAZUH_ENGINE_URL` for `tester_sessions` — see
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

All configuration is environment variables. Nothing is read from a config file
and no credential is baked into the Docker image.

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
process. To run it elsewhere — next to the Wazuh cluster, say — serve it over
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
