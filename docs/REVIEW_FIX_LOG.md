# Feature-freeze review — fix log (2026-08-11)

Every review finding is mapped to its commit, the change and the verification.
Each finding was fixed as its own atomic commit; the full suite, mypy strict and
the no-regression checks were run after every commit.

## Fixes

| Finding | Severity | Commit(s) | Change | Verification |
|---|---|---|---|---|
| H1 — aggregation keys raw by default | High | `c3a5a89` | `mask_aggregation_keys` now defaults to ON (fail-closed) in `config.py`; the opt-out restores the pre-feature behaviour (tested explicitly) | 658 → 658; config + aggregation-masking tests updated to the new default |
| M1 — non-string leaves under configured fields unmasked | Medium | `a7d1892` | `_mask_json` and `_mask_key_value` now tokenise `str(value)` for non-string scalars (int/float/bool) under configured fields; `None` and non-configured scalars untouched | 664 (6 new tests); mypy clean |
| M2 — `gdpr_check as_json` bypassed the guard | Medium | `b19e77c` | JSON report now routed through `_guarded_text` (text pass + verify/block); regression test injects a raw IP and asserts it is masked | 665 (1 new test); mypy clean |
| M3 — invalid boolean silently disabled masking | Medium | `4e31d1f` | `_env_bool_strict` raises `ConfigError` on unrecognised values for the five security-critical anonymization switches; lenient parser kept for non-security flags | 679 (14 parametrized tests); mypy clean |
| M4 — tenant names not validated | Medium | `983c00e` | `validate_tenant` (`[a-z0-9._-]`, no `..`, max 64) enforced in `find_tenant_dir` — the single choke point for every CLI caller | 695 (17 tests); mypy clean |
| H2 — anonymizer tests not in CI | High | `ce59101` | Added a `unit-tests` CI job running the full `pytest` suite + `mypy src` on push/PR | workflow YAML validated; local `pytest -q` + `mypy` green |
| L4 — whitespace-padded value got a different token | Low | `7a13090` | Whole-value type matches register the stripped value, so `" 10.0.0.1 "` and `"10.0.0.1"` share a token | 696 (1 test); mypy clean |
| L7 — export dropped MASKED lines containing ` RAW:` | Low | `63e0a3e` | `export_masked_log` matches the `[EXTERNAL_LLM] - <tool> RAW:` header instead of the substring | 697 (1 test); mypy clean |
| L9 — field names could inject the generated YAML | Low | `3b554e4`, `f079226` | Field/free-text names validated (`[A-Za-z0-9_.@-]`) in `load_tenant_config`; mypy arg-type follow-up | 699 (2 tests); mypy clean |
| L3 — unpinned deps / no dependency updates | Low | `c4c2766` | Dependabot for pip + github-actions (gated by the new CI job); upper bounds on `mcp`/`httpx`/`pyyaml` | dependabot YAML validated; suite green |
| L6 — missing known-limitations docs | Info | `ec2cdd8` | README "Known limitations": pseudonymization (reversible with salt), `verify()` covers IP/email only, per-response masking, agg-key masking default | docs-only |
| M6 — unbounded aggregation sizes / masking cost | Medium | `c53a3ca` | Recursive `_cap_agg_sizes` lowers oversized `terms`/`composite`/`top_hits` `size` to `search_max_size` with an `[AGG SIZE CAPPED]` notice; limit 0/negative still disables | 704 (5 tests); mypy clean; drift check green |
| M5 — three hand-maintained field-classification tables | Medium | `f083c69`, `94b66c1` | New `field_kinds.py` is the single home for `FIELD_KIND`/`NAME_PATTERNS`/`DEFAULT_ANONYMIZATION_MASK_FIELDS`; anonymization, gdpr and config import from it. Pure move — behaviour unchanged | 704 passed with NO test edits; mypy clean; selftest + drift check green |
| ADDITIONAL — Painless free-text `Pattern` declarations never emitted | (bug) | `fa67242` | The f-string interpolated the `maskPattern(...)` calls but not the `Pattern <NAME> = Pattern.compile(...)` declarations — the deployed pipeline would fail to compile and flag every document with `klaxon.masking_error` while leaving `_source` raw. Insert the `{patterns}` block; committed pipeline artifact regenerated (token scheme unchanged) | 705 (1 new regression test); selftest + drift check green |

## No-regression verification (after every commit and at the end)

- Full suite: **705 passed** (`pytest -q`).
- Type check: **mypy strict clean** (19 source files).
- Anonymizer determinism / aggregation-key / free-text / idempotency suites:
  `test_anonymization.py`, `test_aggregation_masking.py`, `test_idempotent_masking.py` — green.
- Generator self-test: `klaxon masking selftest --tenant customer-a` — ok
  (14 value/family pairs, Painless == `derive_token` byte-for-byte; token scheme
  **unchanged**).
- Drift detection: `klaxon masking generate --check` — ok (committed artifacts
  match a fresh regeneration).
- `mask_free_text_users: false` behaviour — pinned in `test_sync_masked.py` — green.
- `event.original` → single token, `related.hash` never masked — pinned in tests — green.

## Deliberately not fixed (accepted / deferred)

| Item | Reason |
|---|---|
| L1 — `verify()` blocks IP/e-mail residuals only (bare usernames/hostnames in unrecognised free text, `script_fields`) | Acknowledged design limitation, now **documented** in README. Mechanical detection of arbitrary usernames is not possible; masking `script_fields` specifically is deferred (needs a decision on semantics, not a one-line fix). |
| L5 — httpx clients never `aclose()`d on shutdown | Negligible: connections are process-lifetime and the OS reclaims them on exit; a correct fix needs uvicorn lifespan wiring. Deferred to the next cycle. |
| L8 — `server.py` (1685 lines) god-module | No behaviour risk to justify a split at freeze. Deferred. |
| Full dependency lockfile (L3) | Dependabot + upper bounds added; a checked-in lockfile (pip-tools/uv) changes the install workflow and is deferred to the next cycle. |
| M5 — unify the two field vocabularies (placeholder families vs GDPR kinds) | The move to `field_kinds.py` is behaviour-preserving; merging the two vocabularies is a semantic change, deferred. |
