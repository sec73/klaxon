# Golden master — Klaxon modularity refactor

Frozen byte streams from the **pre-refactor** code. Every refactor commit
re-captures and must stay **byte-identical**; a diff here means the refactor
changed output (a failed refactor).

## What is captured

| File | Code path exercised |
|---|---|
| `tokens.json` | `masked_stream.derive_token` / `token` (token scheme canary) |
| `masked-response-freetext.json` | `Anonymizer.mask_response` (`mask_free_text_users=true`) — `_source`, aggregation keys, composite `after_key`, free text |
| `masked-response-nofreetext.json` | same with `mask_free_text_users=false` |
| `twin-masked-doc.json` | `masked_stream.pipeline_mask_doc` (Python twin of the Painless pipeline) |
| `artifacts/*` | `build_pipeline` / `build_ism_policy` / `build_index_template` / `build_config_fragment` (deployable form, real salt) |
| `artifacts-committed/*` | `masking.render_artifacts` (salt-free `__SALT__` committed set) |

Inputs are fixed and fully offline (no indexer needed): the response layer and
the builders are driven with a deterministic salt
(`golden-master-salt-0123456789abcdef`) and tenant `customer-a`'s `fields.yaml`.

## Usage

```sh
# (re)write the frozen files — run only to ADOPT new output, never to hide drift
.venv/bin/python tests/golden/capture.py

# diff-only check (CI / pre-commit friendly)
.venv/bin/python tests/golden/verify.py

# wired into pytest
.venv/bin/python -m pytest tests/test_golden.py -q
```

## Rules

- Never edit a frozen file to make a test pass.
- If the refactor changes output, **revert the refactor commit** and rethink —
  this is the proof that the move was not behavior-preserving.
- `capture.py`/`verify.py`/`capture_main.py`/`README.md` are tooling, not
  golden outputs.
