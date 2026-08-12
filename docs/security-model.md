# Token scheme & security model

Two token schemes exist, deliberately:

- **Response layer** (what an LLM client receives): `Anonymizer._token` —
  **HMAC-SHA256** over the salt, keyed by the placeholder family.
- **Pipeline / masked stream** (Option B, ingest side): `tokens.token` —
  **SHA-256** over `family:value:salt`, first 16 hex chars.

They are different schemes on different layers on purpose; a masked-stream
value is already a token, so the response layer passes it through unchanged
(idempotent) rather than re-tokenising it.

---

## Contents

- [The response-layer token (HMAC)](#the-response-layer-token-hmac)
- [The pipeline token (SHA-256)](#the-pipeline-token-sha-256)
- [Why 16 hex (64 bits)](#why-16-hex-64-bits)
- [Salt](#salt)
- [The mandatory self-test](#the-mandatory-self-test)
- [Generic labels (`use_hash: false`)](#generic-labels-use_hash-false)
- [Deployment note: the salt is visible in the cluster](#deployment-note-the-salt-is-visible-in-the-cluster)

---

## The response-layer token (HMAC)

`Anonymizer._token(kind, value)` computes

```
[KIND_ <first 16 hex of HMAC-SHA256(salt, "kind:value")>]
```

e.g. `[USER_9f2a1c…]`, `[IP_5c01e7…]`. Properties:

- **Deterministic**: the same value always maps to the same token, so one
  entity is correlatable across responses (that is the point — and the
  pseudonymization caveat).
- **Keyed by family**: the same value in different families gets different
  tokens (`user.name="alice"` → `[USER_…]`, a host named "alice" → `[HOST_…]`).
- **Reversible only with the salt**: dictionary-reversing a single 64-bit token
  is infeasible without it, but anyone holding `KLAXON_ANONYMIZATION_SALT` can
  reproduce the token for a candidate value (and thereby confirm it).

## The pipeline token (SHA-256)

`tokens.derive_token(value, family, salt)` = the pipeline scheme:

```
[FAMILY_ <first 16 hex of SHA-256("family:value:salt")>]
```

The generated Painless script implements the same scheme with the ingest
`String.sha256()` augmentation (byte-identical to hashlib SHA-256), idempotent
on already-tokenised values. `tokens.py` is the single canonical Python source
for this scheme.

## Why 16 hex (64 bits)

16 hex chars = 64 bits of digest output. That is enough to make reversal
infeasible for a single token (2⁶⁴ guesses) while keeping tokens short enough
to be readable inside log lines and free text. The earlier 6-hex scheme was
replaced by the HMAC/64-bit scheme precisely because 24 bits was reversible.

## Salt

The salt is what makes the tokens non-reversible. Resolution order:

1. `KLAXON_ANONYMIZATION_SALT` (env) — authoritative when set.
2. Otherwise a salt persisted next to the config file (`<config>.salt`, mode
   `0600`, gitignored via `*.salt`) is reused, so tokens stay deterministic
   across restarts.
3. Otherwise a random per-process salt is used (only for direct construction;
   `Anonymizer` warns).

For Option B the salt is also baked into the **deployed** pipeline at
generate/apply time (ingest pipelines cannot read process env) — see the
deployment note below.

## The mandatory self-test

`klaxon masking selftest` (and automatically inside every `generate`) proves
the generated Painless scheme is **byte-identical** to `derive_token`:
`painless_token_reference` — an independent Python transcription of the
Painless `token()`/`sha256hex()` — is compared against `derive_token` over a
fixed set of value/family pairs (including non-ASCII, empty and already-token
values). On any mismatch generation aborts and emits no artifacts. `masking
salt-check --tenant X` additionally compares the salt baked into the deployed
pipeline against the current environment salt.

## Generic labels (`use_hash: false`)

With `KLAXON_ANONYMIZATION_USE_HASH=false` the keyed tokens are replaced by
generic labels: `[IP_ADDRESS]`, `[HOSTNAME]`, `[USERNAME]`, `[AGENT_ID]`,
`[EMAIL]`. The same value is no longer correlatable across responses — at the
cost of losing the "same entity, same token" property.

## Deployment note: the salt is visible in the cluster

The deployed ingest pipeline embeds the real salt in `params.salt` (visible via
`GET /_ingest/pipeline/klaxon-mask-<tenant>`). Anyone with pipeline-read
permission can extract it and reverse tokens. Restrict pipeline read access to
administrators and do **not** give report/LLM consumers that permission. The
committed pipeline *template* carries `__SALT__`, so the secret never enters
version control.
