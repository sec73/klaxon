# LLM-safety guarantees & limits

Klaxon's masking is **pseudonymization, not anonymization**, and it is
per-response. This page states exactly what is guaranteed and where the
acknowledged blind spots are, so you can decide what is safe to point an
external model at.

---

## Contents

- [What is guaranteed](#what-is-guaranteed)
- [What is NOT guaranteed](#what-is-not-guaranteed)
- [Known limitations](#known-limitations)
- [How to review the rules](#how-to-review-the-rules)

---

## What is guaranteed

- **Structured fields are masked exactly.** Every value under a configured
  field (`source.ip`, `user.name`, `user.effective.name`, `wazuh.agent.*`, …)
  is replaced with a deterministic token — this is structural and exact,
  including numeric values and array elements.
- **Aggregation keys are masked too (fail-closed).** Bucket keys of
  terms/composite aggregations on a configured field are tokenised with the
  same tokens as `_source`; `composite` `after_key` stays consistent, so
  pagination keeps working. This is **ON by default** and can be turned off
  with `KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS=false`. If you turn it off,
  aggregation output can carry the raw values the `_source` pass masks.
- **Free-text usernames reuse the structured tokens.** With
  `mask_free_text_users` on (default), usernames inside free-text fields
  (`message`, `*.log`, `raw`, …) are masked with the same tokens as the
  structured fields — `uid=alice` inside a log line becomes the same
  `[USER_…]` token as `user.name` in the same document. IPs, e-mails and the
  standard username formulations are always masked in free text.
- **Already-masked streams pass through.** Values matching the token shape
  (`[IP|USER|HOST|AGENT]_<16 hex>`) are left unchanged (idempotent), so Option B
  masked streams are never double-masked.
- **Residual gate.** The masked output is scanned; with the whitelist enabled
  (default), a response that still contains an IP or e-mail is **blocked** —
  you get a `GDPR BLOCKED` notice instead of the data.

## What is NOT guaranteed

- **Reversibility.** Tokens are deterministic, so an entity is correlatable
  across responses, and anyone who holds `KLAXON_ANONYMIZATION_SALT` can
  reverse a token back to the value. Treat masked output as pseudonymous data,
  not as destroyed data. (See [security-model.md](security-model.md).)
- **No cross-request state.** Each response is masked independently; there is
  no session- or document-level context carried between calls.

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
