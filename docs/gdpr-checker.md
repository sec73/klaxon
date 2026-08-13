# DSGVO/GDPR plausibility checker

Anonymization masks what is *configured*; the checker is the other half — it
asks "what *should* be configured". It reads an index's mappings, samples a few
documents, classifies the fields, and proposes additions to the anonymization
list, so you discover personal data you did not know you were collecting.

The same logic is shared by the MCP tool (`gdpr_check`), the CLI
(`klaxon-mcp --gdpr-check`) and the standalone `klaxon_check_gdpr` entry point.

> **Scope matters (events vs. findings).** The checker runs against **one
> `index` argument at a time**; coverage numbers are only meaningful with the
> scope attached. On `wazuh-events-v5-*` it currently reports **"0 to add"**
> for the leak fields — but that is a value-heuristic blind spot, not proof
> there is nothing to add: `wazuh.rule.title`, `url.original`, `file.path` and
> `file.owner` match no name pattern and their sampled values do not look like
> IPs/e-mails, so they are missed even though they carry raw usernames,
> hostnames and paths. On `wazuh-findings-v5-*` the checker reports ~120 open
> DSGVO fields. Run it per index and treat a "0 to add" result as
> scope-limited.

---

## Contents

- [Classification layers](#classification-layers)
- [Priorities](#priorities)
- [Run it — MCP tool and CLI](#run-it--mcp-tool-and-cli)
- [Applying the suggestions](#applying-the-suggestions)
- [The compliance report](#the-compliance-report)
- [Automatic triggers](#automatic-triggers)

---

## Classification layers

Three layers, in decreasing certainty:

1. **Custom rules** from `gdpr_checker.custom_patterns` in config.yaml — the
   operator's knowledge always wins over heuristics. Each rule has `field`
   (exact / suffix / `*` glob), `type`, `priority` and optionally `regex` (a
   content check against the sampled values).
2. **Field-name patterns**: `source.ip` is an IP by construction, `user.name` a
   username, `host.hostname` / `wazuh.agent.name` hostnames, `user.email` an
   e-mail. No documents needed.
3. **Sampled values**: a few `_source` documents are pulled and the actual
   values are checked — `custom.peer` holding `192.168.1.100` is an IP even
   though the name says nothing, and a free-text field like `event.original`
   embedding `Failed login for admin from 192.168.1.100` is flagged as free
   text carrying personal data.

## Priorities

Following the spec: IPs, usernames and e-mails are directly personal
(**high**); hostnames and agent ids are indirectly personal (**medium**); free
text embedding personal data is flagged too. Fields already in `mask_fields`
are reported as **covered**, not re-suggested.

---

## Run it — MCP tool and CLI

```bash
# MCP tool (through your client)
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

`--gdpr-prefix` / `prefix` restricts the analysis to a field namespace.
`--gdpr-sample` / `sample_docs` controls the sample size (0 disables sampling).
`--gdpr-exclude` / the tool's `exclude` parameter skips fields (internal ones
without GDPR relevance).

---

## Applying the suggestions

Applying merges the suggested fields into `anonymization.mask_fields` of
config.yaml, appends to `gdpr_check.log`, and writes
`gdpr_compliance_report.json` — all via the shared
`gdpr.apply_mask_fields()` helper, so the MCP tool and the CLI write the exact
same audit-log lines.

Note the environment precedence: if `KLAXON_ANONYMIZATION_MASK_FIELDS` is set it
overrides the file, and the checker warns about that. The running server picks
up file changes on restart.

## The compliance report

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
compliance monitoring.

---

## Automatic triggers

- `KLAXON_GDPR_CHECK_ON_SEARCH=true` makes `search` append a `[GDPR]` notice
  naming sensitive fields present in the hits — a cheap name scan, no extra
  requests.
- `klaxon-mcp --check-gdpr-on-startup` runs one check before serving. It
  applies only together with `--gdpr-auto-add`; otherwise it dry-runs. It never
  prompts and serves regardless of the result.
