# Teil 13 — Full security review + fixes: findings report (2026-08-22)

Context: Klaxon is an OpenSearch proxy that anonymizes personal data (Wazuh 5
indexer → external LLM) in the response layer (field-name based, `mask_fields`;
deterministic HMAC tokens). Every finding below was proven with a live
before/after probe against the RAW streams (`wazuh-events-v5-*`,
`wazuh-findings-v5-*`) on the lab cluster (10.20.30.3:9200), fixed, covered by a
regression test, deployed, and re-verified.

Status per item: **probe → root cause → fix → re-probe**.

---

## F1 — `runtime_mappings` (request) can alias a masked field under a NEW name

- **Probe (before):** a request with
  `runtime_mappings: {rt_user: {script: emit(doc['user.name'].value)}}` plus a
  `terms` agg on `rt_user` returns raw usernames as bucket keys: the walker only
  tokenises keys whose source field is in `mask_fields`, and `rt_user` is not.
  (Offline proof: `"key": "marco"` raw. Live: OpenSearch 3.6.0 itself rejects
  `runtime_mappings` with a 400 `parsing_exception`, so it is not exploitable on
  this cluster — the fix makes the guard portable.)
- **Root cause:** no request-side gate on the top-level `runtime_mappings`
  section; arbitrary script-computed output under unmapped field names.
- **Fix:** new fail-closed gate `anonymization.block_unmappable_features`
  (default `block`); `find_unmappable_features` detects the top-level key and
  `server.search` rejects the request naming it.
- **Re-probe (after):** `ToolError: search blocked: ... runtime_mappings ...` —
  rejected before the indexer (offline test
  `test_runtime_mappings_rejected_by_default` + `find_unmappable_features`).

## F2 — `script_fields` (request) is arbitrary code returning raw values under unmapped names

- **Probe (before, LIVE):** a search with
  `script_fields: {who: {script: params._source.user.name;}}` against
  `wazuh-events-v5-*` returned hits whose `_source.user.name` was masked
  (`[USER_…]`) but whose `fields.who` leaked the raw username `root` — the exact
  same value, masked in one place and raw in another.
- **Root cause:** the response walker masks `fields.<name>` only when the name
  matches a mask field; a script-field alias name is unmapped and its value
  reaches the consumer raw. Same threat class as `scripted_metric`.
- **Fix:** blocked by `block_unmappable_features` (default). Defense-in-depth:
  the `fields` subtree of each hit is served through the deep value pass with
  the DOCUMENT's own registry, so even in the explicit `off` mode a script-field
  echo reuses the exact `_source` token.
- **Re-probe (after):** default → `ToolError ... script_fields ...`. With
  `block_unmappable_features=off` (data-protection exception) → LIVE:
  `fields.who` now shows `[USER_…]`, raw `root` absent.

## F3 — `suggest` (request/response) returns raw field text

- **Probe (before, LIVE):** a `term` suggester on `user.name` returned
  `suggest.u[0].text = "root"` (raw echo of the query term) and shard failures
  leaked `no mapping found for field [user.name]`; a completion suggester would
  emit indexed values verbatim.
- **Root cause:** the response walker has no field mapping for the `suggest`
  subtree; bare usernames in its `text`/`options` are not caught by a value
  pattern.
- **Fix:** blocked by `block_unmappable_features`. Defense-in-depth: the
  top-level `suggest` subtree is served through the deep value pass with a
  response-wide registry (only collected when a `suggest` key is present).
- **Re-probe (after):** default → `ToolError ... suggest ...`. Offline test
  `test_suggest_uses_response_wide_registry` proves the deep pass reuses
  `_source` tokens.

## F4 — `highlight` snippets embed raw source text (bare usernames)

- **Probe (before):** a highlight on a free-text `message` returned a snippet
  with a bare username inside highlight tags. The `<em>` tags break the username
  context pattern (`login as <em>marco</em>` does not match `login as <name>`),
  and the per-document identity registry is scoped to the `_source` subtree, so
  the snippet's `marco` reached the consumer raw. (Offline proof; live LDAP
  messages `uid=…` are caught by the `uid=` context pattern, so the leak needs a
  bare/unformatted username — still a confirmed structural leak.)
- **Root cause:** highlight snippets are source text under unmapped keys, with
  no per-document identity registry at the highlight path.
- **Fix:** blocked by `block_unmappable_features`. Defense-in-depth: each hit's
  `highlight` subtree is served through the deep value pass with the DOCUMENT's
  registry — `<em>marco</em>` is caught by word-boundary identity replacement.
- **Re-probe (after):** default → `ToolError ... highlight ...`. Offline test
  `test_highlight_bare_username_in_snippet_masked` proves the `<em>`-wrapped
  username is masked.

## F5 — Fail-closed gate proven for `scripted_metric` + unknown + pipeline aggs

- **Probe (before):** `scripted_metric`, `bucket_script` (pipeline), an unknown
  agg type all served opaque output raw (Teil 12.3 finding; re-verified live for
  `scripted_metric`).
- **Root cause:** opaque agg output the walker cannot map (Teil 12.3).
- **Fix (already present, re-proven + regression-locked):**
  `block_unmappable_aggs` (default `block`) rejects `scripted_metric`,
  `bucket_script`/`bucket_selector`/`bucket_sort`, `ip_range` (keys are IP
  ranges = personal), `geohash`/`geotile` (coordinates) and any unknown type.
  `rare_terms` was ADDED to the mapped families (key AND `key_as_string`
  tokenised like `terms`).
- **Re-probe (after, LIVE):** `scripted_metric` → `ToolError ...
  scripted_metric ...`; `bucket_script` → `ToolError ... bucket_script ...`.
  Offline: `TestSearchFailClosedUnmappableAggs` + `TestRareTermsAggregationMasking`.

## F6 — Error bodies and shard failures echoed the raw query

- **Probe (before, LIVE):** a 400 `x_content_parse_exception` error body (raw
  query echo) and a 200 response carrying a `_shards.failures` array (the
  script source `params._source.user.name;`, field names) were rendered verbatim
  to the consumer.
- **Root cause:** non-2xx bodies and the `_shards.failures` array are opaque;
  the value-type pass cannot catch arbitrary query echoes (bare usernames, field
  names, script source).
- **Fix:** with anonymization active, `server._render` serves an error response
  as the notices + a `[BODY WITHHELD]` marker (`diagnostics.render` gained
  `include_body=`); `mask_response` strips the `_shards.failures` array (the
  `failed` count stays) and `search_notices` emits a `[SHARD FAILURES]` notice.
  The raw render still reaches the audit log when RAW logging is on.
- **Re-probe (after, LIVE):** the 400 now returns `[HTTP 400] … [BODY WITHHELD]`
  with no raw query echo; the 200-with-failed-shard returns `[SHARD FAILURES] 1
  shard(s) failed` and no `failures` array / no script source.

## F7 — Posture `rbac` check reported "unknown" with roles deployed

- **Probe (before, LIVE):** `klaxon_posture_check` returned `rbac: unknown —
  roles API response has no roles map` even though the klaxon roles ARE
  deployed.
- **Root cause:** the OpenSearch Security roles API
  (`GET /_plugins/_security/api/roles`) serves the roles map as TOP-LEVEL keys
  (`{role_name: spec, …}`), not wrapped under a `roles` key.
- **Fix:** `_rbac_line` now parses both shapes.
- **Re-probe (after, LIVE):** `rbac: OK — klaxon_llm_report_customer-a present
  (grants: klaxon-masked-customer-a-v5*); klaxon_ops_customer-a present (grants:
  klaxon-quarantine-customer-a-v5-*, wazuh-events-v5-*); klaxon_sync_customer-a
  present …`. **The Teil-13 RBAC guarantee is live-verified: the LLM-facing
  role reads ONLY the masked stream — no consumer role grants direct read on
  `wazuh-events-v5-*`/`wazuh-findings-v5-*`.** Regression-locked by
  `test_roles_fragment_least_privilege` (llm_report block contains no raw
  patterns) + `test_rbac_parses_real_top_level_roles_shape`.

## F8 — Posture `pipeline_drift` hid config-vs-fields.yaml drift when not deployed

- **Probe (before):** with the Option B pipeline not deployed, the
  `pipeline_drift` check returned only "not deployed"; an env override of
  `mask_fields` drifting from `fields.yaml` was not reported.
- **Root cause:** the config-vs-fields.yaml comparison lived inside
  `preflight_report`, which returns early when the pipeline is absent.
- **Fix:** new `_config_fields_drift` in posture.py runs regardless of
  deployment state.
- **Re-probe:** `test_config_vs_fields_yaml_drift_reported_even_when_not_deployed`
  proves the drift line now appears alongside "not deployed".

---

## Audit checklist coverage (Teil 13)

1. **Response masking — all answer paths:** `_source` ✓; top_hits ✓; terms /
   significant_terms / significant_text / **rare_terms** (newly mapped) key +
   key_as_string ✓; multi_terms key + key_as_string ✓; composite key + after_key
   ✓; filters/filter named keys raw + sub-aggs masked ✓ (NEGATIVE); histogram /
   date_histogram / range labels raw + sub-aggs masked ✓ (NEGATIVE); ip_range /
   geohash / geotile **fail-closed blocked** (their keys are personal — IP
   ranges, coordinates; deliberately NOT "labels stay raw"); scripted_metric /
   bucket_script / bucket_selector / bucket_sort / unknown **blocked** ✓;
   suggesters **blocked** ✓; highlight **blocked** + deep-masked ✓; fields /
   docvalue_fields masked, script_fields **blocked** ✓; runtime_mappings
   **blocked** ✓; suggest/profile/meta — suggest blocked, profile = timing,
   meta = operator-supplied ✓; shard-failure/error bodies **withheld** ✓.
2. **Fail-closed gate:** `block_unmappable_aggs` + `block_unmappable_features`
   enforced in code, default `block`, live-proven for scripted_metric, unknown,
   bucket_script, script_fields, runtime_mappings, suggest, highlight; explicit
   documented opt-out (`drop`/`off`).
3. **Deep value pass:** covers e-mail, IPv4/IPv6, username, HOSTNAME, UUID,
   domain; recurses into ALL leaves of opaque/arbitrary containers; idempotent
   (existing tokens pass through); now also serves suggest/highlight/fields
   subtrees.
4. **Config/tenants/drift:** `fields.yaml` for customer-a, copied into the
   image; env-vs-YAML drift → ConfigError; config-vs-fields.yaml drift reported
   by posture even when not deployed; `mask_aggregation_keys=true`,
   `block_unmappable_aggs=true`, `block_unmappable_features=true` defaults; salt
   stable & never logged.
5. **RBAC:** roles fragment grants llm_report ONLY the masked stream
   (regression-locked); live-verified via the fixed posture rbac check; tenant
   isolation via per-tenant role names.
6. **Operational robustness:** `klaxon_posture_check` green end-to-end (all 9
   checks OK live); no raw values in logs/error messages; stability cap on heavy
   aggregations (`_cap_agg_sizes`) + scripted aggs blocked; retention /
   quarantine-backlog reported.
7. **Regression:** Teil 11 (nested sub-agg keys), Teil 12 (multi_terms
   key_as_string), Teil 12.3 (scripted_metric/unknown block + deep value pass)
   all stay green.

## Final gate

- 1079 offline + 10 live = **1089 tests passed** (was 1028 offline baseline;
  +51 offline, +2 live).
- mypy strict clean (32 files); ruff at the 35 baseline (zero new).
- golden master byte-identical (18 outputs); `masking generate --check` OK.
- `klaxon_posture_check` end-to-end: all 9 checks OK against the live cluster.

## Deliberate decisions

- `ip_range` / `geohash` / `geotile` stay **blocked** (fail-closed), not "labels
  stay raw": their keys are personal (IP ranges / coordinates) and the audit's
  standard is "no raw personal value reachable".
- `rare_terms` is **mapped** (key + key_as_string tokenised), matching the
  checklist's "terms / … / rare_terms" group.
- `block_unmappable_features=off` is an explicit, documented data-protection
  exception; the response-side deep value pass remains active as a safety net.
- Error bodies are withheld only when anonymization is active (external LLM);
  with a local/disabled anonymizer the operator sees the raw body as before.
