# Security Concept — pseudonymization & salt

This document describes the security model of tokenization in Klaxon: the
construction of the tokens (keyed HMAC-SHA256), the role of the salt and — at
the core of this document — the **pseudonymization risk: brute-force
re-identification** (enumerable values with a known salt), its mitigations and
the accepted residual risk.

See also:
- [`security-model.md`](security-model.md) — token scheme, 16 hex, salt resolution
- [`salt-rotation-runbook.md`](salt-rotation-runbook.md) — salt-rotation runbook
  (no scheduled rotation; only on suspicion)
- [`option-b-masked-stream.md`](option-b-masked-stream.md) — masked/quarantine stream

---

## Token construction

- Token display: `[FAMILY_16hex]` (e.g. `[USER_3cc5982657e33301]`).
- Construction (response layer AND masked stream identical):
  `HMAC-SHA256(key = salt, message = "<family>:<value>")`, truncated to 16 hex
  chars (64 bits).
- A **keyed MAC** (not a concatenation hash): the salt is the key, the family
  the context — the same value in different families yields different tokens;
  the construction is not susceptible to length-extension-style misuse.
- Deterministic: same value + same family + same salt → same token, across
  calls and restarts, in `_source`, aggregation bucket keys and
  `composite after_key`.
- Byte-identity between Python (`tokens.derive_token`) and the generated
  Painless script is enforced by the generator self-test (and checked live
  against the indexer by `klaxon masking test`). The Painless part implements
  HMAC-SHA256 in pure Painless (the ingest allowlist lacks `javax.crypto.Mac`),
  byte-identical to Python's `hmac`.

---

## Pseudonymization risk: brute-force re-identification

### Risk

Pseudonymization is **not anonymization**. A token does have 64 bits of digest
entropy (16 hex), but the **value space** is often small and enumerable:

- Usernames, internal IP addresses, hostnames, agent IDs — typically a few
  thousand to millions of candidates.
- With a **known salt** an attacker can compute the token for every candidate
  (HMAC is public) and match it against the observed token. A dictionary or
  brute-force attack then succeeds practically immediately.

The salt is the only barrier. If it is compromised (leak in logs, backups,
repos; `params.salt` of the pipeline read by unauthorized parties; access to
the deployment host), **all** tokenized values are re-identifiable — regardless
of the token construction (under salt compromise, keyed HMAC has the same
brute-force exposure as a concatenation hash; HMAC is nevertheless the
standardized, more robust key construction and matches the design intent).

### Mitigations

| Mitigation | Effect |
|---|---|
| **Keyed HMAC** (salt as key, family as context) | Standard construction, resistant to length-extension-style misuse; the family separates equal values in different contexts. |
| **Salt as a high-entropy secret** (≥ 256 bits recommended; `secrets.token_hex(32)`); startup warning below 32 hex | Makes *guessing the salt* infeasible (the attack stays limited to "salt known"). |
| **Restrict access to the salt** (secrets manager / env on the deployment host, `0600` for `.salt`, pipeline read for admins only) | Reduces the probability of salt compromise. |
| **Rotation only on suspicion** (never scheduled) | Limits the duration of a compromise; but deliberately breaks correlation (see runbook). |
| **Response-layer-only construction** (no raw values stored; only the masked stream holds tokens) | Shrinks the attack surface to the streams where tokens reside permanently. |

### Residual risk (accepted)

A motivated attacker **with the salt** and a good dictionary can break specific
enumerable values. This is inherent to the pseudonymization model and cannot be
fully removed without giving up the deterministic tokenization (which is
needed for correlatable aggregations and two-layer idempotency). Accepted by
design; documented so operators treat the residual risks (salt handling,
access to the masked/quarantine stream) accordingly.

### Operational consequences

1. **Never log/commit/export the salt** — not in error messages, config dumps,
   health endpoints or committed artifacts. Deployable pipeline files with a
   real salt are gitignored.
2. **The quarantine stream is raw data** — ops role only; never in the LLM
   allowlist.
3. **Rotation per the runbook** (only on suspicion) — never scheduled.
4. On suspected salt compromise: **not only** rotate, but also check whether
   tokens have already leaked (incident response; rotation does not
   re-anonymize anything already leaked).
