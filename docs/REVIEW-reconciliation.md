# Documentation reconciliation — 2026-08-13

Reconciliation pass: documentation was checked against the CODE + effective
CONFIG + generated artifacts + test suite + live-verified behaviour (the source
of truth). Where a doc contradicted the code, the doc was corrected — code
behaviour was NOT changed.

Status vocabulary used below (and in the corrected docs):

- **implemented & verified** — in the code, exercised by the test suite and/or
  the live `klaxon masking test`.
- **implemented, not deployed** — in the code, but not yet rolled out to the
  indexer (e.g. Option B masked stream: `klaxon-masked-*` = 0 shards).
- **known limitation** — deliberate, documented gap (verified, not speculative).
- **planned / roadmap** — not implemented.
- **historical** — describes a past state that has since changed (kept in
  CHANGELOG as a record).

## Corrected claims

| # | Doc | Location | Claim (old) | Correct | Status | Commit |
|---|---|---|---|---|---|---|
| R1 | README.md | "First masked result" | `[USER_9f2a1c…]`, `[IP_5c01e7…]` (6 hex) | 16-hex token form `[USER_<16 hex>]` | implemented & verified | `docs(token)` |
| R2 | README.md | "First masked result" | "the personal data never appears" | over-claim → "Known limitations" (4 verified leaks) + link to llm-safety | known limitation | `docs(limits)` |
| R3 | ARCHITECTURE.md | "Determinism and no-PII-by-default" | "Placeholders are derived from the value itself (MD5 or SHA-256, truncated to six hex digits)" | `HMAC-SHA256(key = salt, message = "kind:value")` truncated to **16** hex; MD5 option removed in 0.1.9; `use_hash=false` → generic labels | implemented & verified | `docs(token)` |
| R4 | ARCHITECTURE.md | Option B section | "builds the config fragment, the ingest pipeline, the ISM policy and the index template" (4) | **seven** artifacts: config fragment + pipeline + masked ISM/template + quarantine ISM/template + roles fragment | implemented & verified | `docs(fields)` |
| R5 | docs/multi-tenant.md | generator example | "# build the 4 artifacts" | "the seven artifacts" | implemented & verified | `docs(fields)` |
| R6 | docs/multi-tenant.md | `fields.yaml` schema example | 17 fields (omits `event.original`, `related.ip`) | labelled "abridged example"; the real customer-a list has **19** fields (see `tenants/customer-a/fields.yaml`) | implemented & verified | `docs(fields)` |
| R7 | docs/TOOLS.md | Anonymization settings table | aggregation key masking default `false` | `true` (fail-closed; `config.py` default) | implemented & verified | `docs(agg)` |
| R8 | docs/TOOLS.md | "Aggregation keys" paragraph | "off by default" | "on by default (fail-closed); `false` restores raw keys" | implemented & verified | `docs(agg)` |
| R9 | docs/TOOLS.md | "Token format" | "keyed HMAC-SHA256 over `salt` with the family as context" | `HMAC-SHA256(key = salt, message = "family:value")` | implemented & verified | `docs(token)` |
| R10 | docs/security-model.md | intro | "HMAC-SHA256 over the salt, keyed by the placeholder family" (inverted key/msg) | `HMAC-SHA256(key = salt, message = "kind:value")` on both layers | implemented & verified | `docs(token)` |
| R11 | docs/security-model.md | response-layer token example | `[USER_9f2a1c…]`, `[IP_5c01e7…]` (6 hex) | 16-hex example | implemented & verified | `docs(token)` |
| R12 | src/klaxon_mcp/anonymization.py | `_token`/Anonymizer docstrings | "HMAC-SHA256 over the salt keyed by the placeholder family" | `HMAC-SHA256(key = salt, message = "kind:value")` (docstring wording only) | implemented & verified | `docs(token)` |
| R13 | docs/llm-safety.md | "Known limitations" | blind spot limited to unrecognised free-text usernames | add the four **verified** leaks (see below) | known limitation | `docs(limits)` |
| R14 | docs/gdpr-checker.md | scope | no events-vs-findings scope note | add scope + value-heuristic blind spot note | known limitation | `docs(limits)` |
| R15 | docs/option-b-masked-stream.md | title/intro | no explicit deployment status | status badge: **implemented & live-verified, NOT deployed** (0 shards) | implemented, not deployed | `docs(status)` |
| R16 | docs/security-model.md | pipeline HMAC section | pure-Painless HMAC described but not labelled as deliberate | explicit: a **documented design decision** (no `javax.crypto.Mac` in the ingest allowlist), not a workaround bug | implemented & verified | `docs(status)` |
| R17 | docs/TOOLS.md | "Default masked fields" | list presented without a count/scope | 18 = built-in default; the per-tenant effective list is generated from `fields.yaml` (customer-a: **19**) | implemented & verified | `docs(fields)` |
| R18 | docs/salt-rotation-runbook.md | — | schema-change case (token construction change with unchanged salt) not covered | new section "Token-scheme change with unchanged salt": same operational consequence as rotation for the masked stream (reindex-or-two-window, shared with Path 2, not duplicated), response layer = no reindex (tokens ephemeral), concrete 0.1.8 → 0.1.9 HMAC example, applies to ANY derivation change, status "must-fix before first productive deploy" (Option B not deployed) | implemented, not deployed | `docs(runbook)` |
| R19 | ARCHITECTURE.md | "Deliberately not built → No caller identity" | no per-tenant roles mentioned | caller identity still not modeled at the MCP layer, but role-based separation is enforced at the indexer level per tenant via the generated security-plugin roles: `klaxon_llm_report_<tenant>` (masked only), `klaxon_ops_<tenant>` (quarantine + raw), `klaxon_sync_<tenant>` (sync service account) — names verified against `build_roles_fragment` + `tenants/customer-a/generated/roles-customer-a.yaml`; links to option-b Access control | implemented & verified | `docs(roles)` |
| R20 | docs/option-b-masked-stream.md, docs/multi-tenant.md | roles fragment filename | `roles-klaxon-<tenant>.yaml` | the generator emits **`roles-<tenant>.yaml`** (`artifact_io.ROLES_FRAGMENT_FILE`); corrected in both docs | implemented & verified | `docs(roles)` |
| R21 | all docs | mixed-language documentation | some docs German / partly German | **Docs i18n — German → English translation, no content change.** Fully German files translated: `docs/security-concept.md` (`b36eb64`), `docs/salt-rotation-runbook.md` (`768022f`, internal anchors updated); `DSGVO` → `GDPR` normalized in prose across README/ARCHITECTURE/CHANGELOG/TOOLS/configuration/gdpr-checker/llm-safety + discrepancy table (`37bc5d1`). Allowed verbatim exceptions: the runbook's `console` code block (shell commands + comments, `<neues-salt>` placeholder) and the gdpr-checker interactive CLI prompt sample. Facts, statuses, links, structure and inline code unchanged | unchanged | `docs(i18n)` |

## Checked and found correct (no change)

| Checklist item | Where verified |
|---|---|
| Token scheme (HMAC-SHA256 key=salt, msg=family:value) | `tokens.py`, `anonymization._token`, generated pipeline, selftest — all byte-identical |
| Field count "18" | 18 is the built-in default (`field_kinds.py`); customer-a effective = 19 (generated `klaxon-config.yaml`) — no doc stated an explicit wrong count |
| EXACTLY ONE generator `klaxon masking generate` | all docs reference it; no `generate_masking.py` remains (removed in the 0.1.6/0.1.7 refactor) |
| `on_failure` / `klaxon.masking_error` | **fail-closed quarantine is implemented & live-verified** (0.1.8); docs describe it correctly; migration path for pre-quarantine docs documented. *Task brief assumed "planned" — corrected by code inspection* |
| Aggregation default | `true` (fail-closed) in code; README + configuration.md correct; TOOLS.md was wrong (R7/R8) |
| `mask_free_text_users`, `masked_streams` (idempotent) | configuration.md, TOOLS.md, llm-safety.md — correct |
| Salt: rotation only on suspicion + brute-force residual risk | `salt-rotation-runbook.md`, `security-concept.md` — present and correct |
| Retention numbers (masked 30d, quarantine 90d) | consistent across option-b, TOOLS.md, multi-tenant, drift-prevention |
| `ctx['_source']` / "functions after statements" as bugs | option-b describes these as **fixed** and verified by the self-test (no stale "known bug" claim remains) |
| `KLAXON_ANONYMIZATION_MASK_FIELDS` precedence + fail-closed | configuration.md + drift-prevention.md — correct (env > YAML; conflict → ConfigError) |
| Generic labels `use_hash=false` | security-model.md, TOOLS.md — correct |
| 6-hex CHANGELOG examples (`[IP_abc123]`) | historical release entries — left as-is (changelog is a record of past state) |

## Verified leaks — "Known limitations" (checked live, current indexer)

The following fields are **neither** in the configured mask list **nor** covered
by the free-text pass (`message` only) **nor** by the residual gate (IPs/e-mails
only). Raw values therefore reach the LLM for these:

| Field | Where it leaks | Example (verified) |
|---|---|---|
| `wazuh.rule.title` | findings (`findings_overview` masks titles with the value-type pass only — no identity registry) | "Sudo command executed - marco"; `/root/...` paths in Rootcheck titles |
| `url.original` | `_source` of events/findings | raw hostnames incl. the private domain `moenig.it` |
| `file.path` | `_source` | username `marco` in paths |
| `file.owner` | `_source` | `root` |

The GDPR checker reports **"0 to add"** for these on events despite the leak
(value-heuristic blind spot: `wazuh.rule.title`, `url.original`, `file.path`,
`file.owner` match no name pattern and their sampled values do not look like
IPs/e-mails); on **findings** it reports ~120 open GDPR fields. Numbers are
only meaningful with the scope (events vs. findings) attached.
## Observations (out of scope for docs-only)

- `tests/golden/capture.py` stores the roles fragment under the stale key
  `artifacts/roles-klaxon-customer-a.yaml`, while the generator emits
  `roles-<tenant>.yaml`. `tests/golden/verify.py` does not cross-check filenames
  against the generator, so the golden test stays green; the capture key should
  be renamed to `roles-customer-a.yaml` and the golden regenerated in a future
  test change (not a doc issue — recorded here for tracking).
