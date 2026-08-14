# Changelog

All notable changes to Klaxon are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## released

## Unreleased

### Added

- **`klaxon masking teardown --tenant <tenant>` — cleanly remove the Option B
  masked-stream infrastructure from the indexer, leaving the raw Wazuh streams
  untouched.** New module `src/klaxon_mcp/teardown.py`, wired into the
  `masking` subcommand. Removes, in dependency order: the masked data stream
  `klaxon-masked-<tenant>-v5` (plus any orphaned `.ds-klaxon-masked-<tenant>
  -v5-*` backing indices), the sync checkpoint marker
  (`klaxon-sync-state/_doc/klaxon-sync-<tenant>`, only with
  `--purge-sync-state` — the default keeps it so a future re-setup can resume),
  the index template `klaxon-masked-<tenant>`, the ISM policy
  `klaxon-masked-retention-<tenant>` and the ingest pipeline
  `klaxon-mask-<tenant>`. A mandatory verification phase then proves no
  `klaxon-*` index/template/policy/pipeline is left (including hidden
  `.ds-klaxon-*` backing indices) and that `wazuh-events-v5-*` /
  `wazuh-findings-v5-*` still exist with unchanged doc counts; any leftover is
  reported and the command exits non-zero, so a partial teardown is never
  reported as success. Hard safety: only `klaxon-*`-namespaced resources are
  ever deleted (a guard refuses anything else, e.g. `wazuh-*`), a missing
  resource (404) is treated as already-removed (idempotent), credentials come
  only from `KLAXON_INDEXER_URL/USER/PASSWORD` (or a local `.env`), and the
  log contains only resource names and statuses — never the password, salt,
  tokens or raw data. `--dry-run` prints the plan offline (no credentials
  needed); without `--yes` the command prompts with the full list and aborts
  with no changes on non-interactive input. The response-layer masking config
  and `tenants/<tenant>/fields.yaml` are not touched. New unit tests
  (`tests/test_teardown.py`, 23) cover dependency order, the backing-index
  sweep, idempotency, dry-run no-op, confirmation gating, sync-state
  keep-vs-purge, verification-failure non-zero, no-secret output and the
  never-touches-`wazuh-*` guarantee.

### Fixed

- **`klaxon masking deploy` no longer fails verifying a correctly-deployed ISM
  policy ("deployed resource does not match what was sent (verify) — fingerprint
  differs").** The real ISM GET returns the policy DOUBLE-nested —
  `response["policy"]["policy"]` — next to the `_id`/`_version`/`_seq_no`/
  `_primary_term` metadata, but the deploy fingerprinted the raw response, so
  the envelope wrapper always differed from the bare policy that was sent (and
  the metadata changes on every PUT). In `deploy.py`: new
  `_ism_policy_from_envelope` extracts the innermost policy (accepting both the
  double-nested live shape and the single-nested shape of older versions / test
  doubles); `_extract_resource("ism", ...)` and `_get_ism_policy` both use it,
  so the verify AND the skip-if-identical re-run compare see the real policy
  (also fixes the `--rollback` snapshot, which previously saved the wrapper).
  ISM durations (`min_index_age` / `min_rollover_age`) are canonicalized on
  BOTH sides of the fingerprint (`_normalize_ism_durations`) so the indexer
  re-serving e.g. `30d` as `43200m` still verifies, while a genuinely different
  duration still differs; size/count fields are untouched. A fingerprint
  mismatch now prints the differing JSON paths (`_json_diff`, e.g.
  `$.states[0].transitions[0].conditions.min_index_age: '30d' != '90d'`) instead
  of a bare "fingerprint differs". Pipeline and template verify are unchanged
  (regression tests). New tests in `tests/test_deploy.py`
  (`TestIsmEnvelope`/`TestVerifyRegression`, 11) + a skippable live test
  `tests/test_live_deploy.py` that checks the real envelope on a live indexer.

### Changed

- **Breaking: `WAZUH_*` env vars and the deprecated `--generate-masking` flags
  are removed; use `KLAXON_*` and `masking generate`.** Klaxon is configured by
  its own name: the infrastructure layer (indexer/manager/engine connections,
  TLS, tuning and the MCP transport) now reads ONLY the canonical `KLAXON_*`
  namespace — `KLAXON_INDEXER_URL/USER/PASSWORD`,
  `KLAXON_MANAGER_URL/USER/PASSWORD`, `KLAXON_ENGINE_URL`, `KLAXON_VERIFY_SSL`,
  `KLAXON_TIMEOUT`, `KLAXON_SEARCH_MAX_SIZE`, `KLAXON_SCHEMA_FIELD_LIMIT`,
  `KLAXON_SCHEMA_PROBE_BATCH`, `KLAXON_LOGTEST_SPACE`,
  `KLAXON_LOGTEST_TRACE_LEVEL`, and the `KLAXON_MCP_*` transport family
  (`TRANSPORT/HOST/PORT/PATH/AUTH_TOKEN/ALLOWED_HOSTS/ALLOWED_ORIGINS/
  CORS_ORIGINS/JSON_RESPONSE/STATELESS`). All reads go through one loader
  (`envutil._get_env`); the legacy `WAZUH_*` fallback, its one-time deprecation
  warning and the deprecated `--generate-masking` / `--generate-masking-check`
  CLI flags (superseded by `masking generate` / `masking generate --check`)
  are DELETED, not just deprecated — a missing `KLAXON_*` var raises the
  standard missing-env error even when the old `WAZUH_*` name is set.
  `KLAXON_ANONYMIZATION_*` / `KLAXON_GDPR_*` / `KLAXON_ANONYMIZATION_SALT` are
  unchanged. `.env.example`, README, `docs/configuration.md`, `docs/TOOLS.md`
  and CLI help show only `KLAXON_*`. Tests: `tests/test_envutil.py` pins the
  loader and adds a grep-based CI guard that FAILS the build if `WAZUH_LEGACY`,
  `WAZUH_INDEXER`, `WAZUH_MCP`, `--generate-masking` or a `deprecated` marker
  reappears in `src/`; `tests/test_config.py` asserts a missing
  `KLAXON_INDEXER_URL` raises even when `WAZUH_INDEXER_URL` is set (no
  fallback). The pre-commit hook (`klaxon-env-namespace`) runs the guard.

### Fixed

- **`masking deploy` no longer reports OpenSearch ISM's own defaults/metadata
  as drift when verifying a correctly-deployed ISM policy.** Beyond the
  double-nested envelope, ISM re-serves a policy with resolved values the PUT
  body omitted — a `retry: {count: 3, backoff: "exponential", delay: "1m"}`
  block on every action, `rollover.copy_alias: false`, a
  `last_updated_time` timestamp on every `ism_template[]` entry, and
  `ism_template` itself re-served as a LIST (the artifact uses a single dict).
  The verify was reporting all of these as `[fail] ... fingerprint differs`.
  In `deploy.py`: a new data-driven `ISM_SERVER_DEFAULTS` constant (the single
  place to add future ISM defaults) plus `_normalize_ism_server_defaults`
  applied to BOTH sides of the ISM verify and the skip-if-identical compare:
  pure metadata (`last_updated_time`) is stripped everywhere, the
  `ism_template` dict/list shape is canonicalized, and a default-valued key
  (`retry`, `copy_alias`) that is ABSENT in the sent body is dropped from the
  deployed side — while an EXPLICIT value in the sent body is never touched,
  so genuine drift (a changed `min_index_age`, a removed state, a different
  `index_patterns`) still fails with a field-level diff. Envelope extraction
  and canonicalization are unchanged. New tests
  (`tests/test_deploy.py::TestIsmServerDefaults`, 12) cover defaults-injected
  pass, metadata ignored, explicit values respected, explicit-vs-default drift
  fails, changed duration/removed state still fail, and the end-to-end deploy +
  re-run-no-op with injected defaults; the live test
  (`tests/test_live_deploy.py`) now routes the comparison through the full
  defaults normalization.

## 0.2.0 – 2026-08-13

### Fixed

- **The masked-stream pattern is now consistent everywhere
  (`klaxon-masked-<tenant>-v5*`), fixing queries that silently returned 0
  documents against a deployed Option B data stream.** The data stream is named
  `klaxon-masked-<tenant>-v5` (no trailing dash), but every query/config path
  used `klaxon-masked-<tenant>-v5-*`, which matches neither the stream name nor
  its `...-v5-000001` backing indices — so `masked_streams`, the report-role
  allowlist, the sync backstop counts and LLM queries all matched nothing
  (live: 1.23M correctly-masked docs invisible to consumers). The single source
  `TenantConfig.masked_stream_pattern` is now `...-v5*`; the generated config
  fragment (`masked_streams`), the ISM `ism_template`, the roles fragment
  (`klaxon_llm_report_<tenant>`) and the Painless comments all flow from it.
  The `[RAW STREAM QUERY]` banner now decides raw-vs-masked against the
  EFFECTIVE `masked_streams` value (an index covered by a configured masked
  stream is never flagged raw). The posture check's `mode` now also WARNs when a
  deployed masked data stream is NOT covered by the configured `masked_streams`
  (the divergence guard), instead of reporting OK. No reindex, no checkpoint
  change, no masking/pipeline/quarantine change — only the naming scheme, plus
  the committed/golden artifacts regenerated from it. New unit test asserts the
  effective `masked_streams` value glob-matches the actual data stream name
  (an index pattern ending in `-*` must not be used for a stream without the
  trailing `-`).

- **`klaxon masking deploy` no longer fails with HTTP 409 when an ISM policy
  already exists.** ISM policies are versioned documents: updating an existing
  one requires `?if_seq_no=<seq>&if_primary_term=<term>` taken from a prior
  GET, and a plain PUT returns 409 "version conflict, document already exists".
  The ISM deploy step now GETs the policy first (ONE GET, reused): missing
  (404) -> plain PUT (create); identical (server-managed keys `policy_id` /
  `last_updated_time` / `schema_version` / `error_notification` are ignored in
  the fingerprint, so the no-op works against a live cluster) -> `[skip] ISM
  <id> unchanged`; different -> versioned PUT with the GET's seq/term. A 409
  (a concurrent change landing between GET and PUT) is retried once with a
  fresh GET + PUT, then fails with a clear message. The pipeline step now also
  GET-compares and skips when identical, so a re-run is a full no-op for the
  pipeline and both ISM policies. The security roles API is verified as
  200-overwrite (no optimistic concurrency), so roles keep their plain PUT +
  GET-back verify. In `deploy.py`: `_put_ism_policy`, `_get_ism_policy`,
  `_verify_after_put`, `_ISM_SERVER_KEYS` / `_normalized_for_compare`; new unit
  tests simulate missing / identical / different / 409-once / 409-twice against
  a mocked indexer (`tests/test_deploy.py`). Pipeline/ISM re-run output
  contract unchanged except the `[skip] ... unchanged` lines for the two
  idempotent steps.

- **`klaxon masking deploy --rollback` no longer fails with HTTP 409 on the
  ISM step.** The rollback path re-deployed ISM policies with a plain PUT, which
  a versioned ISM document rejects with 409 "version conflict, document already
  exists". Rollback now goes through the SAME shared helper as deploy —
  `_put_ism_policy` (formerly `_put_ism_verified`) — for both the masked and
  the quarantine policy: GET-first compare/skip (an unchanged policy is a
  no-op, so a second `--rollback` writes nothing), versioned PUT
  (`?if_seq_no&if_primary_term` from a fresh GET, never a stale seq), and one
  409 retry before failing with a clear message. The duplicated plain-PUT in
  the rollback path is gone; the rollback output contract is unchanged except
  the `[skip] rollback ism-* <id> unchanged` no-op line. Unit tests cover all
  five cases (missing / identical / different / 409-once / 409-twice) for BOTH
  the deploy and the rollback path, plus the ISM GET `_seq_no`/`_primary_term`
  shape and an end-to-end rollback/no-op second rollback
  (`tests/test_deploy.py`).

- `klaxon_mcp.__version__` again matches the packaged version (`0.1.7`) after
  it had drifted from `pyproject.toml`. It is the fallback used when the
  installed-distribution metadata is unavailable (`generator_version()` in
  `masked_stream.py`), so generated artifacts' `generator_version` could have
  been stamped wrong in that path.

- **`klaxon-mcp --sync-masked` no longer dies on a transport-level reindex
  timeout for a large window.** The reindex is now submitted as an async task
  (`POST /_reindex?wait_for_completion=false` returns a task id immediately)
  and polled via `GET /_tasks/<id>`, so a proxy/LB closing a long synchronous
  connection cannot abort the run. The reindex POST and each task-poll GET use
  a generous per-request timeout (`KLAXON_SYNC_REINDEX_TIMEOUT`, default 30
  min) instead of the default short `WAZUH_TIMEOUT`, with an overall task
  deadline `KLAXON_SYNC_TASK_TIMEOUT` (default 60 min). Transport-level
  failures (the `httpx.TransportError` family) are retried with exponential
  backoff for the SAME window (3 attempts: 5s, 15s, 45s) then fail with a clear
  message; HTTP 4xx/5xx are reported with status + body and never retried
  blindly. Checkpoint semantics are unchanged and stay fail-closed: the
  checkpoint advances only after the task completes without failures, the
  quarantine backstop is empty and (when enabled) the reconcile matches.
  `IndexerClient.request`/`get`/`post` gained a per-request `timeout` override;
  new unit tests mock the client for read-timeout-retried, exhausted-retries,
  HTTP-not-retried, task-completes and task-times-out (no real cluster). See
  `docs/option-b-masked-stream.md` "Reindex transport".

### Changed

- `starlette` is now a declared direct dependency (upper-bounded `<2`).
  `transport.py` imports `CORSMiddleware` directly for the HTTP transport and
  previously relied on starlette arriving transitively via `mcp`.

### Added

- **`klaxon masking deploy` — operator-friendly Option B deployment.** Deploys
the masking artifacts to the indexer in ONE idempotent, ordered,
self-verifying step: pipeline → both ISM policies → both index templates →
masked data stream (created only if absent; "already exists" is success) →
security roles (roles `-<tenant>.yaml` converted to JSON in code — no `yq`
dependency) → role-mapping reminder. Preflight aborts on drift (names the
file), missing `KLAXON_INDEXER_*` credentials, a salt mismatch between the
deployed pipeline and the env salt, or a running sync (a documented heuristic;
`--force` overrides). Every PUT is verified with a GET-back fingerprint check,
and a final `_simulate` smoke test asserts `user.name` and a free-text `uid=`
share one token with no `klaxon.masking_error`. `--dry-run` prints the full
plan with no writes; the previous deployed state is snapshotted under
`tenants/<tenant>/generated/backup/<ts>/` (gitignored) and `--rollback`
re-deploys it via the same ordered path. Reuses the live-test indexer client
and the verify-config drift logic; the running server stays write-incapable
(this is an explicit operator/CI CLI path). The password, salt, tokens and raw
data are never logged. New `src/klaxon_mcp/deploy.py`; wired into
`klaxon masking deploy`. See `docs/option-b-masked-stream.md` (operator
section) and `docs/TOOLS.md`.

- **`klaxon_posture_check` — on-demand security/DSGVO posture check (facts +
  gaps, never a verdict).** Read-only MCP tool returning one `check: status —
  fact` line per item with source attribution: masking, response gate +
  loopback, mode (response-layer vs Option B masked stream, derived from
  `masked_streams` config vs which data streams actually exist on the indexer),
  pipeline drift vs `fields.yaml` (reuses verify-config), salt strength
  (length-only, via `weak_salt()`), quarantine backlog (count over the last
  `hours`, default 24), RBAC tenant roles (`klaxon_llm_report_<tenant>` /
  `klaxon_ops_<tenant>` / `klaxon_sync_<tenant>`, fragment vs the OpenSearch
  security roles API), retention (masked 30d / quarantine 90d), and the
  startup fail-closed check. Statuses are OK / WARN / unknown only — no overall
  compliance verdict, no legal judgment. The salt is never emitted (not even
  partially, not hashed); no PII, raw values, tokens, hostnames, usernames, IPs
  or sampled values appear in the output; an unreachable indexer yields
  "unknown — reason" per check. New `src/klaxon_mcp/posture.py`; tool wired
  into the MCP server. Read-only: nothing written, nothing deployed.

- **Automatic safety banner in the diagnostics layer** (`[UNMASKED MODE]` /
  `[RAW STREAM QUERY]`). Every search response is prefixed — before any other
  diagnostics line — with a one-line banner per active condition whenever the
  response may carry personal data: anonymization is disabled (feature off or
  no fields configured), the LLM endpoint is not local (no loopback) and the
  response gate (`whitelist_enabled`) is inactive, or the query targeted a raw
  stream (`wazuh-events-v5-*` / `wazuh-findings-v5-*`) instead of a masked
  stream (`klaxon-masked-<tenant>-v5*`). Automatic (no opt-in, no separate
  tool), fires on every response including zero-hit/error/aggregation-only
  ones, and never contains values, tokens or the salt. New
  `diagnostics.safety_banner`; wired into `search` and `findings_overview`
  (which always queries the raw findings stream). Existing diagnostics
  unchanged.

- **HMAC edge-case vector suite** in the generator self-test (`klaxon masking
  generate` / `selftest`): the pure-Painless HMAC (hand-rolled SHA-256;
  `javax.crypto.Mac` is not in the ingest allowlist) is now pinned against
  authoritative vectors — RFC 4231 TC1–7, the key-length boundaries
  64/65/63/0/1/32 bytes, and Klaxon-format vectors covering UTF-8
  (umlaut/CJK/emoji), `:`-containing and empty values, spaces, and the
  first-16-hex truncation — plus structural checks on the rendered script
  (ipad/opad, two distinct SHA-256 steps, the `key.length > 64` hash-first
  branch). On ANY mismatch generation aborts and emits NO artifacts. New
  `src/klaxon_mcp/hmac_vectors.py` (single shared vector table) and
  `pure_painless_hmac`/`run_hmac_vector_selftest`/`verify_hmac_structural` in
  `selftest.py`; the live `klaxon masking test` gained a "Stage B — HMAC
  edge-case vectors" `_simulate` stage that feeds one doc per vector through the
  deployed pipeline. No artifact/token output changed (self-test only), so no
  version bump or artifact regeneration.

### Docs

- Documentation reconciled against the code/config (see
  `docs/REVIEW-reconciliation.md`): token construction phrased as
  `HMAC-SHA256(key = salt, message = "family:value")` everywhere (no inverted
  "over the salt" wording, no six-hex token examples, no stale "MD5 or
  SHA-256, six hex digits"); aggregation-key masking default corrected to
  `true` (fail-closed) in the `docs/TOOLS.md` reference; the four live-verified
  leak fields (`wazuh.rule.title` in findings, `url.original`, `file.path`,
  `file.owner`) documented as Known limitations in `docs/llm-safety.md`; the
  GDPR-checker coverage is now index-scoped (events "0 to add" is a
  value-heuristic blind spot; findings ~120 open GDPR fields); Option B
  carries an explicit "implemented, not deployed" status badge; the
  pure-Painless HMAC is marked as a deliberate design decision, not a
  workaround; generator artifact count fixed to seven everywhere. No code or
  behaviour change.


## 0.1.9 – 2026-08-13

### Changed (BEHAVIOR-CHANGING: ALL token values changed)

The Option-B masked-stream token was a **concatenation hash**
`SHA-256("family:value:salt")[:16]` — not a keyed MAC. It is now a **keyed
HMAC-SHA256** `HMAC-SHA256(key = salt, message = "family:value")[:16]`,
matching the response layer (which already used HMAC) and the documented
design intent. **Every token value changes** (same raw value → different
token). Acceptable: no masked stream is deployed yet (0 shards), so this is
response-layer + generator only — **no reindex needed**. The salt is NOT
rotated as part of this change.

- **`tokens.py`** (`derive_token`/`token`/`token_hex`): HMAC-SHA256 keyed by the
  salt over `family:value`, truncated to 16 hex. `weak_salt()` flags a
  configured salt shorter than 32 hex chars (16 bytes / 128 bits) with a
  startup warning.
- **Generated Painless** (`painless.py`): the same HMAC implemented in **pure
  Painless** — the restricted ingest allowlist has no `javax.crypto.Mac`
  (verified against OpenSearch 3.6.0: `cannot resolve symbol`), and
  `String.sha256()` can only hash UTF-8 text (not the raw inner digest bytes of
  HMAC), so SHA-256 is reimplemented over an `int[]` byte sequence. Byte-
  identical to Python's `hmac` (verified live: short keys, unicode values,
  long-key pre-hash). The self-test scheme markers + function table now pin the
  HMAC construction (ipad 0x36 / opad 0x5c, key pre-hash, 16-hex truncation);
  the live test gained a unicode doc (umlaut) proving UTF-8 HMAC + free-text
  registry consistency on the cluster.
- **`selftest.py`**: `painless_token_reference` is the independent HMAC
  transcription; `verify_script_scheme`/`verify_script_structure` pin the HMAC
  markers and the new function set.
- **`live_test.py`**: Stage A no longer requires `String.sha256()` (the scheme
  needs no crypto allowlist member); Stage B now covers a unicode doc.
- **Salt hardening**: startup warnings for short salts (config, masked_stream
  resolve, Anonymizer); minimum-entropy recommendation
  (`secrets.token_hex(32)`, ≥ 256 bits) documented in `.env.example`,
  `docs/security-model.md`.
- **Docs**: new `docs/salt-rotation-runbook.md` (no scheduled rotation; only on
  suspicion; response-layer + masked-stream paths incl. reindex vs two-salt
  window; correlation-break stated) and `docs/security-concept.md`
  (pseudonymization risk: brute-force re-identification — risk,
  mitigations, residual risk). `docs/security-model.md`,  `docs/option-b-masked-stream.md`, README updated (both layers now use the
  same keyed HMAC).
- Version bumped 0.1.8 → 0.1.9; artifacts + golden regenerated.

### Verified

- Full suite 768 tests green (incl. 3 live), mypy strict clean, golden
  byte-identical, `generate --check` OK.
- Live (OpenSearch 3.6.0): `klaxon masking test --tenant customer-a` — Stages
  A/B/C ok; Stage B 5 docs (incl. unicode) mask byte-identical to Python;
  Stage C quarantine routing intact.


## 0.1.8 – 2026-08-13

### Added (Option B — quarantine index for masking errors, FAIL-CLOSED)

The generated pipeline's `on_failure` was FAIL-OPEN: it flagged
`klaxon.masking_error` and left the (unmasked) raw document **in the masked
stream**, so protection depended on every consumer filtering
`NOT exists klaxon.masking_error` — an organizational guarantee, not a
technical one. Masking-failure documents are now routed to a **quarantine
stream** `klaxon-quarantine-<tenant>-v5-*` (deliberately not `klaxon-masked-*`,
so it can never overlap the LLM allowlist) and never stay in the masked stream.
Verified against a live OpenSearch 3.6.0 indexer.

- **Generator: FAIL-CLOSED `on_failure`** (commit: "generator: fail-closed
  quarantine on_failure"). The emitted `klaxon-mask-<tenant>` `on_failure` now
  preserves `klaxon.quarantine.original_index` (before rerouting) and
  `klaxon.quarantine.reason` (from `{{ _ingest.on_failure_message }}`, the only
  way OpenSearch 3.x exposes it — `_ingest` is not a script variable; falls
  back to `'unknown'` via an `ignore_failure` `set` + script), flags
  `klaxon.masking_error`, and reroutes `_index` to
  `klaxon-quarantine-<tenant>-v5-raw`. Same `ctx`-context pattern as the
  Teil-6 fix (no `ctx['_source']`).
- **Generator: three new artifacts** (quarantine ISM `...-quarantine-retention-
  <tenant>` with 90d retention, quarantine index template with NO
  `index.default_pipeline`, and a security-plugin roles fragment), with the
  same provenance fingerprint (`sha256` + source + `generator_version`) and
  drift checks; `generate --check` / `verify-config` / the pre-commit hook now
  compare **seven** artifacts. The mandatory self-test rejects a fail-open
  `on_failure`.
- **Sync backstop (fail-closed)** (commit: "sync: fail-closed backstop"). After
  each reindex window, `--sync-masked` counts quarantine docs; `> 0` FAILS the
  run — checkpoint NOT advanced, window + count logged, non-zero exit (alert).
  Optional reconcile `source == masked + quarantine` via
  `KLAXON_SYNC_RECONCILE` (warn) / `KLAXON_SYNC_RECONCILE_FAIL` (fail). The
  preflight additionally aborts on a deployed pipeline lacking the quarantine
  `on_failure`.
- **Startup fail-closed check** (commit: "config: refuse quarantine in
  masked_streams"). If any `masked_streams` pattern could match
  `klaxon-quarantine-<tenant>-v5-*`, `Config.from_env()` raises `ConfigError` —
  the LLM allowlist can never read quarantine (raw) data. The generated config
  fragment never adds the quarantine stream.
- **Access control** (roles fragment): LLM/report role reads
  `klaxon-masked-<tenant>-v5*` ONLY; ops role reads quarantine + raw events;
  the sync service user additionally WRITES the quarantine stream (without it,
  the security plugin rejects the on_failure reroute — a fail-closed backstop).
- **Live test Stage C** (`klaxon masking test`): a forced masking failure is
  asserted to reroute to `klaxon-quarantine-<tenant>-v5-raw` with
  `original_index` + `reason` + `masking_error`; normal docs still mask, no
  masking_error doc remains in the masked-stream simulate result. `--apply-
  masked-infra` now also deploys the quarantine template + ISM.
- **One-time migration** (`klaxon masking migrate --tenant X`, destructive,
  never automated, idempotent): reindex legacy `klaxon.masking_error` docs from
  the masked stream into the quarantine stream (op_type create, conflicts
  proceed, no masking pipeline) and delete them from the masked stream; logs
  the count and refuses to delete when the reindex reports failures.
- Docs: `docs/option-b-masked-stream.md` (quarantine purpose, retention,
  on_failure semantics, access control, alerting, migration, defense-in-depth
  filter note), `docs/drift-prevention.md`, `docs/multi-tenant.md`,
  `.env.example`. Version bumped to 0.1.8 (`generator_version` forces artifact
  regeneration).

### Changed

- `masked_stream.py` / `painless.py` / `artifact_io.py` / `selftest.py` /
  `masking.py` / `sync_masked.py` / `live_test.py` / `config.py` /
  `tenants.py` / `__main__.py` — see the commit log for the atomic breakdown.
  Full suite 764 tests green (incl. 3 live), mypy strict clean, golden master
  byte-identical, `generate --check` OK.


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

- **GDPR plausibility checker.** A new `gdpr_check` tool (plus
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
