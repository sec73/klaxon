# Modularity refactor log (2026-08-12)

Behavior-preserving modularity refactor of `src/klaxon_mcp`, executed one
atomic split per commit. **Every commit was verified**: full suite green
without test edits, `mypy --strict` clean, ruff at/below the pre-existing
baseline (37), and the golden master byte-identical.

Baseline before the refactor: **729 passed + 2 live** (with
`KLAXON_INDEXER_VERIFY_SSL=false`), mypy clean (20 files), ruff 37 pre-existing
style lints (the project's CI gate is pytest + mypy, so those were left alone).

## Golden master

Frozen **before** the first split, from the pre-refactor code, under
`tests/golden/` (checked in, wired into `pytest` via `tests/test_golden.py`):

* `tokens.json` — `derive_token` / `token` canary
* `masked-response-freetext.json` / `masked-response-nofreetext.json` —
  `Anonymizer.mask_response` (aggregation keys, composite `after_key`, free
  text, `event.original`, `related.hash`)
* `twin-masked-doc.json` — `pipeline_mask_doc`
* `artifacts/*` — deployable pipeline/ISM/template/config fragment
* `artifacts-committed/*` — `render_artifacts` (salt-free committed set)

Fixed deterministic salt `golden-master-salt-0123456789abcdef`, tenant
`customer-a`, fully offline.

| Commit | Description |
|---|---|
| `5518c81` | `test(golden): freeze pre-refactor output as byte-identical golden master` |

## Refactor commits

| Audit item | Commit | Modules moved → | New public API | Callers updated | Golden diff | Tests |
|---|---|---|---|---|---|---|
| P1 (D1) | `bc904ef` | `anonymization.py`+`gdpr.py` → `patterns.py` (`_ipv4`, `_IPV4_RE`, `_IPV6_RE`, `_EMAIL_RE`, `_FQDN_RE`) | same names, leaf | anonymization, gdpr | OK | 731 |
| P2 (D4/D5) | `296078e` | `config.py` → `envutil.py` (`ConfigError`, `LOOPBACK_HOSTS`, `_env_bool*`, `_env_int/str/list/float`, `_is_loopback_url`, `_yaml_get`, `_load_yaml_file`, `_section`) | same names + `__all__` re-export | config; external `from .config import ConfigError` unchanged | OK | 731 |
| P4 | `d05e756` | `masked_stream.py` → `tokens.py` (`TOKEN_RE`, `token_hex`, `token`, `derive_token`) | same names, facade re-export | masked_stream, masking, live_test, tests | OK | 731 |
| P5a | `2f1531b` | `masking.py` → `selftest.py` (pure predicates: `TokenSchemeError`, `SELF_TEST_VALUES`, `painless_token_reference`, `verify_script_scheme`, `verify_script_structure`, `_selftest_salt`) | same names + `__all__` | masking (re-export), live_test, tests | OK | 731 |
| P5b | `c7c38b5` | `masking.py` → `artifact_io.py` (filename constants + `_artifact_contents`, `generated_dir/paths`, `render_artifacts`, `render_deployable`, `write_artifacts`, `write_deployable`, `check_artifacts`, `tenants_in_repo`) | same names + `__all__` | masking, sync_masked, tests | OK | 731 |
| P6 | `3e22e4d` | `live_test.py` → `live_config.py` (`LIVE_ENV_*`, `LiveIndexerConfig`, `LiveTestError`, `load_dotenv_file`, `find_env_file`, `_env_bool`, `safe_url`, `resolve_live_config`, `live_salt`) | same names + `__all__` | live_test, tests | OK | 731 |
| P7 | `66ff41a` | `masked_stream.py` → `tenants.py` (`FieldSpec`, `TenantConfig`, `find_repo_root`, `find_tenant_dir`, `_validate_field_name`, `load_tenant_config`, `fields_yaml_sha256`, `build_config_fragment`, `_gdpr_kind`, `_gdpr_priority`) | same names + `__all__` | masked_stream, masking, sync_masked, artifact_io, tests | OK | 731 |
| P8 | `c127904` | `masked_stream.py` → `painless.py` (`_painless_script`, `_painless_regex`, `_PATTERNS`, `_FREETEXT_PATTERN_ORDER`, `_FREETEXT_ALWAYS_ON`, `_active_free_text_patterns`, `_MASK_FAMILY`) | same names + `__all__` | masked_stream, masking, selftest | OK | 731 |
| P11 (D2) | `55bce25` | `server.py`+`__main__.py` → `gdpr.py::apply_mask_fields` (shared update+audit-log core) | new `apply_mask_fields(config_file, log_path, index, to_add)` | server.gdpr_check, __main__._gdpr_check_once | OK | 731 |

Every split was a **move**: function bodies relocated verbatim, public names and
signatures unchanged, imports updated in the same commit, and the moved names
re-exported (`__all__` / facade) where callers (including tests, which were NOT
edited) import them from the old module.

## Deliberately NOT merged (would change behavior)

| Finding | Reason |
|---|---|
| D3 — `server._shadow_hint` vs `diagnostics._shadow_hint` | Different signatures, return contracts (`str|None` full-hint vs `str` suffix) and **different output wording**. Unifying would change rendered tool output. |
| D4 — `live_test._env_bool` vs `config._env_bool` | Different contracts: unrecognised non-empty value → `default` (live_test) vs `False` (config). A merge would change `KLAXON_INDEXER_VERIFY_SSL=bogus` handling. Relocated to `live_config.py` with its contract documented. |
| D5 — `gdpr.load_config_doc` vs `config._load_yaml_file` | Different contracts: `{}` for missing/non-dict vs `None`. A merge would change behavior. |
| D7 — salt resolution (`_resolve_salt`, `_process_salt`, `resolve_salt`, `live_salt`) | Four functions with different, test-pinned semantics; a blind merge is behavior-changing. Noted for a future documented priority table. |

## Skipped structural splits (with reason)

| Audit item | Reason |
|---|---|
| P9 — `coverage.measure()` from `server.field_coverage` | The 340-line tool is one cohesive 6-step pipeline with ~8 early-return render branches that route through the anonymizer guard. Extracting it needs a result-object/abort-marker rewrite — a rewrite, not a move, which violates the byte-identity constraint. `server.py` stays the tool layer (per the audit's own "do NOT split server.py as a whole" reasoning). |
| P10 — `cli_args.py` from `__main__._parse_args` | A single flat 60-flag parser; splitting into per-subcommand parsers is an argparse-structure change with flag-drift risk and no behavioral benefit. The CLI/MCP shared-logic boundary (the process's real question) is already resolved by P11 + the pre-existing `run_check` sharing. |

## Result

* New cohesive leaf modules: `patterns.py`, `envutil.py`, `tokens.py`,
  `selftest.py`, `artifact_io.py`, `live_config.py`, `tenants.py`, `painless.py`
* Slimmed: `masked_stream.py` 914 → 398, `masking.py` 732 → 457, `live_test.py`
  747 → 644, `config.py` 661 → 570
* `server.py` (1751) and `anonymization.py` (1103) intentionally unchanged —
  both are the audit's "do NOT split" cohesive cores.

## Final verification

```
pytest (KLAXON_INDEXER_VERIFY_SSL=false):  731 passed          (baseline 731)
mypy --strict src/klaxon_mcp:              Success, 28 files   (baseline 20)
ruff check src/klaxon_mcp:                 36 errors           (baseline 37)
golden master:                              byte-identical      (12 outputs)
```

The masked output of every query, every token and every pipeline artifact is
byte-identical to the pre-refactor baseline, as proven by the golden master at
every commit and at the end. The full suite passed unchanged (no test edits)
throughout.
