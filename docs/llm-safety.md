# LLM-safety: using Klaxon safely with an LLM

Klaxon sits between the Wazuh indexer and the LLM. Personal data is masked in
**two layers** — Option B masks it **at rest** in a separate masked stream, and
the response layer masks it **in every answer** as the safety net. This page is
the operator's "how do I point an LLM/report consumer at Klaxon" guide: what is
guaranteed, the ready-to-copy system-prompt section, the routing rules, and the
ongoing operations that keep it safe.

Klaxon's masking is **pseudonymization, not anonymization**, and it is
per-response. Read this page before pointing an external model at Klaxon.

---

## Contents

- [1. What Klaxon guarantees for an LLM](#1-what-klaxon-guarantees-for-an-llm)
- [2. The system-prompt section (ready to copy)](#2-the-system-prompt-section-ready-to-copy)
- [3. Routing rules (for the operator building the integration)](#3-routing-rules-for-the-operator-building-the-integration)
- [4. Ongoing operations](#4-ongoing-operations)
- [5. The new-field cycle](#5-the-new-field-cycle)
- [What is NOT guaranteed](#what-is-not-guaranteed)
- [Known limitations](#known-limitations)
- [How to review the rules](#how-to-review-the-rules)

---

## 1. What Klaxon guarantees for an LLM

There are two kinds of stream. **Only the masked stream may be used for
LLM/report queries.**

| Stream | At rest | On a response | Use for |
| --- | --- | --- | --- |
| **masked** `klaxon-masked-<tenant>-v5*` | masked by the ingest pipeline (`klaxon-mask-<tenant>`) | already-tokenised values pass through unchanged (idempotent) + response-layer guard | **LLM / reports ONLY** |
| **raw** `wazuh-events-v5-*` / `wazuh-findings-v5-*` | raw | response-layer masked only | forensics, on explicit request |

- **The masked stream is the ONLY source for LLM/report queries.** The
  `masked_streams` allowlist (env `KLAXON_ANONYMIZATION_MASKED_STREAMS` or the
  `anonymization:` YAML block) is exactly `klaxon-masked-<tenant>-v5*`, and the
  server refuses to start on a broad or quarantine-overlapping pattern
  (fail-closed). The quarantine stream `klaxon-quarantine-<tenant>-v5*` is
  **never** an LLM source.
- **Token model.** Values become deterministic pseudonym tokens
  (`[USER_…]`, `[HOST_…]`, `[IP_…]`, `[AGENT_…]`, and `[EMAIL_…]` in free text)
  = HMAC-SHA256(key = `KLAXON_ANONYMIZATION_SALT`, message = `family:value`),
  first 16 hex chars. The same token always means the same entity, across
  queries and documents — so tokens can be used for correlation and
  aggregation. `related.hash` values are **real** file hashes (security IOCs)
  and are never masked.
- **Honest boundary: this is pseudonymization, not anonymization.** Raw values
  in the raw stream remain term-searchable, tokens are reversible by anyone who
  holds the salt, and **probing with known values is possible** (query the raw
  stream for a token's presumed raw value). That probing must **not** be done
  for LLM/report tasks — the masked stream is the only legitimate source for
  them. See [security-model.md](security-model.md) and
  [security-concept.md](security-concept.md) for the re-identification risk.

### The masking guarantees (both layers)

- **Structured fields are masked exactly.** Every value under a configured
  field (`source.ip`, `user.name`, `user.effective.name`, `wazuh.agent.*`, …)
  is replaced with a deterministic token — structural and exact, including
  numeric values and array elements, whether the field is nested
  (`user: {name: …}`) or a flat dotted key (`user.name`).
- **Aggregation keys are masked too (fail-closed).** Bucket keys of
  terms/composite aggregations on a configured field are tokenised with the
  same tokens as `_source`; `composite` `after_key` stays consistent, so
  pagination keeps working. **ON by default**; `KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS=false`
  turns it off (aggregation output can then carry raw values).
- **Free-text usernames reuse the structured tokens.** With
  `mask_free_text_users` on (default), usernames inside free-text fields are
  masked with the same tokens as the structured fields — `uid=alice` inside a
  log line becomes the same `[USER_…]` token as `user.name` in the same
  document. IPs, e-mails and the standard username formulations are always
  masked in free text.
- **Residual gate.** The masked response is scanned; with the whitelist enabled
  (default), a response that still contains an IP or e-mail is **blocked** —
  you get a `GDPR BLOCKED` notice instead of the data.
- **Automatic safety banner.** Every response that may carry personal data is
  prefixed with `[UNMASKED MODE]` and/or `[RAW STREAM QUERY]` — masking off, an
  external LLM without the response gate, or a query against a raw stream
  instead of a masked stream. It never contains values, tokens or the salt.

## 2. The system-prompt section (ready to copy)

Copy this block verbatim into the LLM's system prompt. Replace `<tenant>` with
the real tenant (e.g. `sec73`) or parameterize it for a multi-tenant setup so
the LLM always queries the right tenant's masked stream.

```markdown
# Klaxon data-access rules (LLM safety)

You query Wazuh security data through Klaxon. Follow these rules exactly.

1. Query ONLY the masked stream `klaxon-masked-<tenant>-v5*`. It is the only
   data source you may use for analysis and reporting.
2. NEVER query the raw streams `wazuh-events-v5-*` or `wazuh-findings-v5-*`
   unless the user explicitly asks for raw forensics. If you do, the Klaxon
   response is tagged `[RAW STREAM QUERY]` — never quote raw personal values
   from it and never include them in your answer.
3. Values are deterministic pseudonym tokens (`[USER_...]`, `[HOST_...]`,
   `[IP_...]`, `[AGENT_...]`, `[EMAIL_...]`). Treat them as opaque: the same
   token always means the same entity, and different tokens never mean the
   same entity. Never guess, reverse, or construct a token.
4. `related.hash` values are real file hashes (security IOCs), never masked.
   Treat them as opaque identifiers, not as personal data, and do not try to
   decode them.
5. Do not run indexer writes yourself — no reindex, no pipeline edits, no
   index-template / ISM / config changes. Use Klaxon's read tools only.
```

## 3. Routing rules (for the operator building the integration)

- **Default to the masked stream** for every LLM/report query. Only fall back
  to a raw stream on an **explicit user request** (forensics); there is no
  automatic raw fallback.
- **Never quote raw personal values from `[RAW STREAM QUERY]`-tagged
  responses.** A raw-stream response is masked by the response layer, but the
  boundary is thinner (no at-rest masking); if raw values are surfaced, they
  must stay in the answer only as needed for forensics and never be copied into
  reports.
- **Aggregations run on the masked stream**, and tokens are used consistently:
  because tokens are deterministic, `terms`/`composite` buckets over
  `klaxon-masked-<tenant>-v5*` still count distinct entities correctly, and the
  same entity's token is the same across queries (correlation).
- **Treat every token as opaque.** Never translate a token back to a value on
  the LLM side; reversal is the operator's (salt-holder's) job only.

## 4. Ongoing operations

Keep the masked stream correct and verified on a schedule. The pieces that make
up the ongoing loop (see [docs/option-b-masked-stream.md](option-b-masked-stream.md)
for the full detail):

- `klaxon --sync-masked --tenant X` — reindex the recent window through the
  pipeline into the masked stream. Preflights against drift and a missing
  quarantine `on_failure`, and is **fail-closed**: a masking failure in the
  window (quarantine > 0) fails the run and does **not** advance the
  checkpoint.
- `klaxon --verify-config --tenant X` — drift audit: `fields.yaml` vs committed
  config fragment vs effective Klaxon config vs the deployed pipeline. Exits
  non-zero on drift.
- `klaxon masking test --tenant X` — LIVE behaviour check of the generated
  pipeline: Stage A ingest allowlist, Stage B `_simulate` (compile + masking
  behaviour), Stage C quarantine routing. No writes.
- `klaxon masking salt-check --tenant X` — the deployed pipeline's
  `params.salt` matches the current env salt (tokens stay deterministic).
- `klaxon masking deploy --tenant X` — the self-verifying deploy: preflight,
  ordered PUTs with GET-back verification, final `_simulate` smoke test.

Hard rules:

- **No deploy without verification.** `klaxon masking deploy` self-verifies
  every PUT and its smoke test; `klaxon masking test` independently proves the
  masking behaviour on the live indexer before/after a deploy.
- **The masked stream is the only LLM/report source.** Raw-stream reads are
  forensics-only, on explicit request.
- **The salt changes only on a deliberate token rollover** (rotation on
  suspicion, never on a schedule) — a salt change re-tokens everything and
  breaks correlation with the response layer until both sides re-sync. See
  [salt-rotation-runbook.md](salt-rotation-runbook.md).

## 5. The new-field cycle

When a field scan on the raw stream reports personal data in a field that is
not yet masked (use the GDPR checker `klaxon --gdpr-check` / `klaxon_check_gdpr`
and `field_coverage`/`schema` on `wazuh-events-v5-*`), close the gap in one
cycle:

1. Add the field to `tenants/<tenant>/fields.yaml` (the single source of truth).
2. `klaxon masking generate --tenant X` — regenerates the pipeline + config
   fragment.
3. Merge the new `mask_fields` into the config (`klaxon-config.yaml` fragment or
   the `anonymization.mask_fields` block).
4. `klaxon masking deploy --tenant X` — deploys the new pipeline.
5. `klaxon --sync-masked --tenant X` — re-sync the next window through the new
   pipeline.
6. `klaxon --verify-config --tenant X` — confirm no drift.

Note: the sync reindexes new windows, so a mask-list change only masks documents
**synced after** the deploy — already-synced masked docs are not retroactively
re-masked. See [docs/option-b-masked-stream.md](option-b-masked-stream.md) (sync
window / token rollover) and [docs/gdpr-checker.md](gdpr-checker.md) for the
full procedure.

## What is NOT guaranteed

- **Reversibility.** Tokens are deterministic, so an entity is correlatable
  across responses, and anyone who holds `KLAXON_ANONYMIZATION_SALT` can
  reverse a token back to the value. Treat masked output as pseudonymous data,
  not as destroyed data. (See [security-model.md](security-model.md).)
- **No cross-request state.** Each response is masked independently; there is
  no session- or document-level context carried between calls.
- **No retroactive masking.** The masked stream is populated by periodic
  syncs; a field added later is only masked in documents synced after the
  deploy (see [the new-field cycle](#5-the-new-field-cycle)).

## Known limitations

- **The residual gate covers IPs and e-mails only.** `verify()` withholds a
  response when an IP or e-mail survives masking. A bare username in
  unrecognised free text — outside the known username formulations
  (`user=…`, `login as/for/by …`, `uid=…`) and outside a configured field —
  cannot be detected mechanically and is not a blocking residual. That is the
  acknowledged blind spot of the text pass; the structural + aggregation
  passes and the gate's residual scan are the guarantees that matter for the
  reliably detectable classes.
- **Verified leaks in fields outside the mask list (checked live).** The
  following fields are **neither** in the configured mask list **nor** covered
  by the free-text pass (`message` only) **nor** by the residual gate, so their
  raw values reach the LLM:
  - `wazuh.rule.title` (findings) — `findings_overview` masks titles with the
    value-type pass only (IPs/e-mails inside them), not a per-document
    identity registry; a bare username survives (e.g. `Sudo command executed -
    marco`) and Rootcheck titles carry raw `/root/...` paths.
  - `url.original` — raw hostnames, incl. the private domain `moenig.it`.
  - `file.path` — usernames in paths (e.g. `marco`).
  - `file.owner` — e.g. `root`.
  The GDPR checker reports **"0 to add"** for these on events (value-heuristic
  blind spot: the names match no pattern and the sampled values do not look
  like IPs/e-mails), while findings carry ~120 open GDPR fields. Remediation
  is operator-side: add fields to `mask_fields`/`free_text_fields` where
  appropriate, or deny report/LLM consumers read access via RBAC.
- **RAW logging is a personal-data store.** By default only MASKED output is
  persisted. `KLAXON_ANONYMIZATION_LOG_RAW=true` deliberately persists RAW tool
  output; the server warns at startup, and that log file must then be treated
  as data under the GDPR, not as disposable log output.
- **A local model is your own responsibility.** Output masking only activates
  when `KLAXON_ANONYMIZE_EXTERNAL_LLM=true` and the LLM is not provably local.
  With a local model, tool output reaches the model unchanged by design.

## How to review the rules

- Add fields to `KLAXON_ANONYMIZATION_MASK_FIELDS` or the `anonymization:`
  block of a YAML config (`KLAXON_CONFIG`; precedence env > YAML > default).
- Use the GDPR checker ([gdpr-checker.md](gdpr-checker.md)) to discover fields
  that should be configured.
- Watch the audit log (`llm_prompts.log`) for `BLOCKED` lines — each is a
  masking gap, not a prompt that can be reworded.
