# Changelog

All notable changes to Klaxon are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## 0.1.7 – 2026-08-11

### Fixed (Option B masked-stream generator — verified against a live indexer)

- **Painless compile error: functions now precede every top-level statement.**
  The script started with `def` statements and only then declared the helper
  functions; Painless requires all function declarations before any statement,
  so the indexer rejected the pipeline with `unexpected token ['('] was
  expecting one of [{<EOF>, ';'}]`. Functions are emitted first.
- **Latent runtime NPE: `ctx` IS the document.** In an ingest script processor
  there is no nested `_source` object, so `ctx['_source'].keySet()`/`get`/
  `clear`/`putAll` were `null` and would NPE on the first document once the
  compile bug was fixed. Every occurrence is now `ctx` directly.
- **Only whitelisted APIs, verified live.** The cluster's ingest allowlist does
  not include `MessageDigest` or `Pattern.compile`. The hash now uses the
  ingest-context `String.sha256()` augmentation (`"family:value:salt".sha256()
  .substring(0, 16)` — byte-identical to `MessageDigest "SHA-256"`, so the
  token scheme is unchanged and `derive_token` still matches); Patterns are
  regex literals wrapped in `Pattern` functions; the known-identity registry
  does a manual word-boundary `indexOf` replacement (`String.replaceAll` is
  unusable there). Painless functions cannot read `params` or top-level defs,
  so the salt and field table are threaded in as parameters from the main logic.
- **Two more latent bugs surfaced by the live simulate and fixed:**
  `m.group(1)` on a group-less pattern (EMAIL/IPV6/IPV4) **throws** "No group 1"
  in Java — `maskPattern` now guards with `m.groupCount()`; and the greedy
  `[A-Za-z0-9._%+-]+` EMAIL local part backtracked past the cluster's
  `script.painless.regex.limit-factor` on dot/digit-heavy lines — the local part
  is now possessive (`++`, identical matches, linear scan). Hex integer literals
  (`0xff`/`0x0f`) also hit a Painless codegen bug and were removed with the
  byte-array hex encoder.
- **The mandatory self-test now also checks structural compilability**, not
  just token identity: `verify_script_structure` fails generation when a
  function appears after a statement, a function/declaration is missing, or any
  `ctx['_source']` remains.

### Added

- **`klaxon masking test --tenant X` — a LIVE integration test against the
  real indexer (write-free).** Stage A queries `GET /_scripts/painless/_context`
  (`context=ingest`) and verifies the ingest allowlist has every API the script
  needs (`_execute` cannot compile ingest scripts — its `painless_test` context
  lacks the ingest-only `sha256` augmentation). Stage B posts the pipeline
  **inline** to `POST /_ingest/pipeline/_simulate` — the authoritative compile
  + behaviour check — and asserts: no `klaxon.masking_error`; `user.name` and
  `uid=<same-username>` in `message` share one token; `user.effective.name`
  like `root(uid=0)` masked; `related.user`/`related.hosts` arrays element-wise;
  `event.original` → a single token; `related.hash` untouched; already-tokenised
  values unchanged (idempotency); dot/digit-heavy free text stays under the
  regex limit. A `klaxon.masking_error` that says "Regular expression considered
  too many characters" is reported with the exact remediation (raise
  `script.painless.regex.limit-factor`). Nothing is deployed or persisted. The
  same assertions run as the pytest marked `integration`/`live`
  (`tests/test_live_masking.py`), which **skips cleanly** when credentials are
  missing.
- **Live-test credentials are environment-only.** `KLAXON_INDEXER_URL`,
  `KLAXON_INDEXER_USER`, `KLAXON_INDEXER_PASSWORD` (optionally loaded from a
  gitignored local `.env.live` or `tests/live/.env` file). `tests/live/.env.example`
  documents the shape with placeholders; the password is never logged, a URL
  with embedded credentials is sanitised, optional `KLAXON_INDEXER_VERIFY_SSL`
  (default `true`) covers self-signed lab clusters, and `.gitignore` now covers
  the local credentials files plus deployable artifact directories that embed
  the salt.

### Changed

- `klaxon masking selftest --tenant X` now reports the structural compile
  checks alongside the token-scheme check.
- Committed artifacts regenerated under `generator_version 0.1.7` (run
  `klaxon masking generate --tenant customer-a` after any pyproject bump).
- Deployment prerequisite documented: for long free-text messages the indexer's
  `script.painless.regex.limit-factor` (default 6) may need raising (see
  `docs/option-b-masked-stream.md`).


## 0.1.6 – 2026-08-11

### Security (feature-freeze review)

- **Aggregation-key masking is now ON by default (fail-closed).** A
  `terms`/`composite` on a masked field (`related.user`, `related.hosts`, ...)
  returned raw bucket keys and composite `after_key` while `_source` was
  tokenised. Set `KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS=false` to restore
  the pre-feature behaviour. **This changes tokens for ad-hoc `search`
  aggregations that were previously returned raw.**
- **Non-string values under configured mask fields are masked too.** A numeric
  `user.id` / `agent.id` (and a numeric terms key / composite `after_key`) is
  now tokenised like its string twin; `None` and non-configured scalars are
  untouched.
- **`gdpr_check` `as_json=true` now runs through the masking guard** (text pass
  + residual gate), like every other tool return.
- **Invalid values for the security-critical boolean switches are refused.**
  `KLAXON_ANONYMIZE_EXTERNAL_LLM`, `KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS`,
  `KLAXON_ANONYMIZATION_MASK_FREE_TEXT_USERS`,
  `KLAXON_ANONYMIZATION_WHITELIST_ENABLED` and `KLAXON_ANONYMIZATION_LOG_RAW`
  raise a configuration error on an unrecognised value instead of silently
  disabling masking (a typo can no longer fail open).
- **Tenant and field names are validated** (`klaxon masking ...` and
  `fields.yaml`): tenant names are restricted to `[a-z0-9._-]` and field names
  to `[A-Za-z0-9_.@-]`, so no tenant/field can inject a resource name, an index
  pattern, a path or the generated YAML fragment.
- **Oversized aggregation `size` values are capped.** `terms`/`composite`/
  `top_hits` sizes above `WAZUH_SEARCH_MAX_SIZE` are lowered before the query is
  sent and reported as `[AGG SIZE CAPPED]` (naming each aggregation and its
  requested size), so a huge bucket response cannot force an unbounded masking
  pass.
- **Option B pipeline fix:** the generated Painless script now emits the
  free-text `Pattern` declarations it references — previously the deployed
  pipeline would fail to compile at ingest and flag every document with
  `klaxon.masking_error` while leaving `_source` raw. The committed pipeline
  template was regenerated; the token scheme is unchanged.
- **Dependency hygiene:** Dependabot (pip + github-actions) and upper bounds on
  `mcp`/`httpx`/`pyyaml`; every bump is gated by the full-suite + mypy CI job
  (which now runs the complete test suite and strict type-checking on every
  push/PR).

### Added

- `field_kinds.py` — the single home for the field-classification tables
  (placeholder families, GDPR name patterns, default mask list) shared by the
  anonymizer, the GDPR checker and the config loader (pure refactor, behaviour
  unchanged).
- README "Known limitations": masking is deterministic **pseudonymization**
  (reversible with the salt), the residual gate covers IPs/e-mails only, and
  aggregation-key masking is on by default.

### Fixed

- Whitespace-padded whole values now map to the stripped value's token.
- The prompt-log export drops only real `RAW` lines (a MASKED body containing
  the substring ` RAW:` is kept).
- Full fix log: `docs/REVIEW_FIX_LOG.md`.


## 0.1.5 – 2026-08-10

### Added

- **`klaxon masking` — the single Option B generator (Option A).**
  `klaxon masking generate --tenant X` builds all four deployable artifacts
  from `tenants/<tenant>/fields.yaml` without writing to the indexer: the config
  fragment, the ingest pipeline, the ISM retention policy and the index
  template (priority 200, `data_stream: {}`, `index.default_pipeline` +
  `index.lifecycle.name`). The salt moves into the script processor's
  `params.salt` (the committed pipeline template keeps a `__SALT__` placeholder
  so the secret never enters git), and the pipeline carries `generator_version`
  in `_meta`. A MANDATORY self-test proves the generated Painless token scheme
  is byte-identical to `derive_token(value, family, salt)` and aborts with no
  artifacts on any mismatch — also available as `klaxon masking selftest`.
  `klaxon masking salt-check --tenant X` compares the salt baked into the
  deployed pipeline with the current env salt and fails on a mismatch. The
  legacy `generate_masking.py` was removed; the old `--generate-masking*` flags
  remain as deprecated aliases. `klaxon` is now a console-script alias for
  `klaxon-mcp`.

- **Free-text username masking (Gap 1).** When anonymization is enabled and
  `mask_free_text_users` is on (the default), usernames inside free-text fields
  (`message`, `*.log`, `raw`, ...) are masked with the same deterministic tokens
  as the structured fields: a per-response registry of known identities is built
  from `user.name` / `related.user` / `user.effective.name` / ... and reused by
  the free-text pass, which also covers precise context formulations (`uid=...`,
  `for/by user ...`, `session opened for user ...`, `Accepted publickey for ...`,
  `username=/user=...`, `login as/for ...`). Common English words are never
  replaced by the registry on their own, and numeric ids (`uid=0`) are left
  alone. `mask_free_text_users: false` restores the previous behaviour.
  `user.effective.name` was added to the default mask list, and the GDPR checker
  now pins it as a high-priority username via a built-in custom rule.

- **Keyed HMAC tokens (Gap 2).** Tokens are now HMAC-SHA256 over
  `KLAXON_ANONYMIZATION_SALT` with the placeholder family as context, truncated
  to 64 bits of output (`[USER_…]`, 16 hex chars) — replacing the 24-bit
  dictionary-reversible MD5 prefixes. When the salt is not set, a random one is
  generated once and persisted next to the config file (`*.salt`, gitignored)
  with a warning, so tokens stay deterministic across restarts. The display
  shape is unchanged; tokens are computed per response and never stored, so no
  reindex is needed.


## 0.1.4 – 2026-08-10

### Added

- **Opt-in masking of aggregation bucket keys.** When anonymization is enabled
  and `mask_aggregation_keys` is on (`KLAXON_ANONYMIZATION_MASK_AGGREGATION_KEYS`,
  default off), the `search` tool tokenises the `key` values of `terms` /
  `significant_terms` / `significant_text` / `multi_terms` / `composite` buckets
  whose source field is in `mask_fields`, using the same deterministic tokens as
  the `_source` pass — so one entity maps to one token in both places. `composite`
  `after_key` is tokenised the same way so pagination keeps working;
  `date_histogram`, `histogram`, `range`, `filters` and metric aggs are never
  touched, `doc_count` and aggregation metadata are preserved, and `top_hits`
  embedded documents go through the normal `_source` masking path. Off by
  default, so responses are byte-identical to before until the option is
  enabled. `related.hosts` now maps to the `HOST_` token family (it previously
  fell back to `USER_`).


## ## 0.1.3 — 2026-08-08

### Added

- **CORS support for browser-based MCP clients**, via `WAZUH_MCP_CORS_ORIGINS`
  (comma-separated origins, no trailing slash). Unset — the default — emits no
  CORS headers at all, so a deployment that does not need this gains no new
  surface.

  The middleware is installed *outside* the bearer check, because a CORS
  preflight is an unauthenticated `OPTIONS` that browsers never attach
  `Authorization` to. Reaching the bearer check, it would take a 401 carrying no
  `Access-Control-Allow-Origin`, and the browser would report an opaque CORS
  failure that never mentions the token. Requests other than the preflight
  authenticate exactly as before.

  Granted origins are also added to the DNS rebinding allowlist. Without that,
  an origin cleared by the browser preflight was then rejected `403` by the
  SDK's own `Origin` check — two allowlists disagreeing, with only the one the
  operator had *not* set named in the error.

  `mcp-session-id` is named in both `Access-Control-Allow-Headers` and
  `Access-Control-Expose-Headers`. It is not CORS-safelisted in either
  direction, so omitting it loses the session the moment `initialize` returns —
  a failure that reads as the server forgetting the session rather than as a
  CORS problem. `GET`, `POST` and `DELETE` are all granted: streamable HTTP uses
  `POST` for JSON-RPC, `GET` for the server-to-client stream and `DELETE` for
  teardown, so a `POST`-only grant works until the client disconnects.

  `WAZUH_MCP_CORS_ORIGINS=*` is refused at startup. Every tool runs with the
  configured Wazuh credentials, so a wildcard would let any page a browser loads
  read the SIEM from that browser's network position.

- Open WebUI setup guide in the README, covering v0.6.31+ native MCP
  registration and connecting DeepSeek V4 Flash as the chat model.

### Added

- **PII anonymization for external LLM clients (GDPR).** A new layer masks
  personal data in every tool output before it is returned to the MCP client,
  so no unmasked PII reaches a cloud model (DeepSeek, Mistral, ...). Off by
  default; enabled with `KLAXON_ANONYMIZE_EXTERNAL_LLM=true` and active unless
  `KLAXON_LLM_BASE_URL` points at loopback (a local model keeps receiving
  unchanged data; an unset endpoint is treated as external).

  Two masking passes plus a gate: a structured pass replaces values under
  configured fields (`source.ip`, `user.name`, `wazuh.agent.name`, ...) with
  **deterministic placeholders** (`[IP_abc123]`, `[USER_def789]`, ...; MD5 or
  SHA-256 via `KLAXON_ANONYMIZATION_HASH_ALGORITHM`), a text pass masks
  e-mails, IP addresses and usernames in their log context anywhere in the
  rendered output, and the gate blocks a response that still carries residual
  IPs/e-mails (`KLAXON_ANONYMIZATION_WHITELIST_ENABLED`, on by default) instead
  of sending it.

  Every exchange is logged with a UTC timestamp to `llm_prompts.log` (MASKED
  output only; `KLAXON_ANONYMIZATION_LOG_RAW=true` persists raw output and
  warns that the log is then a personal-data store). New one-shot CLI commands
  — `--anonymization-status`, `--anonymization-report [OUTFILE]`,
  `--anonymization-export [OUTFILE]` (RAW lines dropped) — need no Wazuh
  environment and serve the compliance report and access requests.

  The `anonymization:` block can also be configured in an optional YAML file
  (`KLAXON_CONFIG`, default `./config.yaml`; precedence env > YAML > default),
  which adds `pyyaml` as a runtime dependency and `types-PyYAML` to the dev
  extras. Custom rules are added by extending `mask_fields`.

- **DSGVO plausibility checker.** A new `gdpr_check` tool (plus
  `klaxon-mcp --gdpr-check`, `--check-gdpr-on-startup` and the standalone
  `klaxon_check_gdpr` script) finds sensitive fields in an index and merges
  them into the anonymization list. Classification is three-layered: custom
  rules from `gdpr_checker.custom_patterns` in config.yaml (field glob, type,
  priority, optional content regex) beat field-name patterns (`source.ip`,
  `user.name`, `host.hostname`, `user.email`, ...), which beat sampled values
  (a custom field holding `192.168.1.100` is an IP by content; a free-text
  field embedding IPs/e-mails/usernames is flagged as FREETEXT).

  Priorities follow the spec (IPs/usernames/e-mails high, hostnames/agent-ids
  medium); fields already in `mask_fields` are reported as covered, not
  re-suggested. `apply=true` / `--gdpr-auto-add` merges the suggestions into
  `anonymization.mask_fields` of config.yaml, appends to `gdpr_check.log` and
  writes `gdpr_compliance_report.json` (the artifact to forward to a SIEM for
  central compliance monitoring). Without it the check dry-runs, or confirms
  per field on a TTY. `KLAXON_GDPR_CHECK_ON_SEARCH=true` makes `search` append
  a `[GDPR]` notice naming sensitive fields present in the hits.

### Fixed

- **DNS rebinding protection rejected every request when only
  `WAZUH_MCP_ALLOWED_ORIGINS` was set.** Protection was enabled whenever either
  allowlist was non-empty, but the SDK validates `Host` before `Origin`, so an
  empty `WAZUH_MCP_ALLOWED_HOSTS` failed every request with `421` before the
  origin check was ever reached. Enabling it is now keyed on the host allowlist
  alone, and a configured origin list with no host allowlist is logged as
  unenforced rather than silently bricking the listener.

### Changed

- `preflight()` logs the granted CORS origins at startup, and warns when origins
  are granted with no `WAZUH_MCP_AUTH_TOKEN` set — a page from a granted origin
  can then read the SIEM with no credential of its own, which is true even on a
  loopback bind, since the browser is itself on the loopback interface.

### Documentation

- Corrected the claim that Open WebUI needs CORS. Its native MCP integration
  connects from its **backend**, not from the page, so no
  `Access-Control-Allow-Origin` is involved. The CORS guidance in the Open WebUI
  documentation applies to OpenAPI "Direct Tool Servers", a separate
  browser-side feature. `WAZUH_MCP_CORS_ORIGINS` is for genuinely browser-based
  MCP clients only.
- `docs/TOOLS.md` documents `WAZUH_MCP_CORS_ORIGINS` and spells out how it
  differs from `WAZUH_MCP_ALLOWED_ORIGINS`: the latter is a filter over which
  `Origin` values are not rejected, the former is a grant of browser access.

## [0.1.0] — 2026-08-03

Initial public release: eight read-only tools over stdio or HTTP, bearer
authentication, and DNS rebinding protection.

## 0.0.2 — 2026-07-31

Pre-release, published before this repository's history begins. The first commit
here postdates it, so there is no tag and no diff to link — the artefact on PyPI
is the only record.

[Unreleased]: https://github.com/sec73/klaxon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sec73/klaxon/releases/tag/v0.1.0
