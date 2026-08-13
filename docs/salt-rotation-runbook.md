# Salt-rotation runbook (token salt)

**Short version: there is NO scheduled/periodic salt rotation.** Rotation
breaks the correlation between pre- and post-rotation tokens (same raw value →
different token) — that is an accepted trade-off. Rotate ONLY on well-founded
suspicion of salt compromise.

> A **token-scheme change with unchanged salt** (e.g. 0.1.8 → 0.1.9) is NOT a
> rotation, but has **the same operational consequence** for the masked stream
> and uses the same playbook — see
> [Token-scheme change with unchanged salt](#token-scheme-change-with-unchanged-salt).

---

## Principle

The salt (`KLAXON_ANONYMIZATION_SALT`) is the HMAC key with which values are
tokenized. As long as it stays secret and unchanged, tokens are deterministic
over time and across the response layer and the masked stream. If the salt is
changed, the same raw value produces a **different** token — documents/queries
from before the rotation can no longer be correlated with those from after the
rotation. That is exactly why:

> **Do not rotate the salt on a schedule.** Rotation is an emergency measure,
> not a routine. It is documented here as a runbook for the suspicion case.

When to rotate? Only when there is reason to believe the salt is or was
compromised (leak in logs/backups/repos, access to the deployment host by
unauthorized parties, the pipeline's `params.salt` read by unauthorized
parties, ...).

## What rotation does NOT do

- It does **not** re-anonymize **already leaked raw data/tokens**. A value that
  was already tokenized and leaked under the compromised salt stays
  re-identifiable.
- It does not remove the brute-force re-identification risk for values that
  were already tokenized under the compromised salt.
- It is **no substitute** for the other controls (restrict salt access, lock
  down pipeline read, quarantine/backstop). See
  [security-concept.md](security-concept.md).

## Path 1 — response layer (cheap, no reindex)

The response layer tokenizes per query; it does not store tokens permanently.

1. Rotate the salt on all hosts in the environment
   (`KLAXON_ANONYMIZATION_SALT`, e.g. `secrets.token_hex(32)`; see
   [§ Entropy](#entropy-of-the-salt)).
2. Restart all Klaxon processes.
3. Check determinism over two queries: the same value yields the same token in
   both answers (and a different one than before the rotation).
4. Re-run the generator self-test (`klaxon masking selftest --tenant X`).
5. **No reindex needed.** Historical queries (if stored at all) no longer
   correlate with the new tokens — deliberately.

## Path 2 — Option-B masked stream (reindex OR two-salt window)

The masked stream stores tokens **permanently** (with the salt that was baked
into the pipeline at deploy time). After a salt rotation:

- **New syncs** tokenize with the new salt (the pipeline must be redeployed,
  see below).
- **Old documents** in the stream are tokenized with the old salt. There are
  two acceptable strategies:

> For a **token-scheme change with unchanged salt**, Strategy A and B apply the
> same way (only the salt stays the same; the pipeline is deployed with the
> newly generated artifacts of the new scheme) — see
> [Token-scheme change with unchanged salt](#token-scheme-change-with-unchanged-salt).

### Strategy A — reindex the retention window

Reindex the retention window of the raw data (`wazuh-events-v5-*`) through the
newly built pipeline into the masked stream. Afterwards the whole stream is
consistent with the new salt.

```console
# 1. Salt rotieren (Env) + Artifakte neu generieren
KLAXON_ANONYMIZATION_SALT=<neues-salt> klaxon masking generate --tenant X
# 2. Pipeline + Infra neu deployen (Backstop/Quarantäne bleiben)
klaxon-mcp --apply-masked-infra --tenant X
# 3. Salt im deployed Pipeline prüfen
klaxon masking salt-check --tenant X
# 4. Fenster reindizieren (Checkpoint zurücksetzen → kompletter Lookback)
#    ODER ein Teilfenster über einen manuellen Reindex mit der neuen Pipeline
klaxon-mcp --sync-masked --tenant X --initial-lookback-hours <retention>
```

Note: the sync job prevents duplicates via `op_type: create` + `conflicts:
proceed`; a partial window is not created twice. Old tokens (with the old salt)
stay in the quarantine/masked stream until the ISM delete and do not correlate
with the new ones — document the window.

### Strategy B — accept a two-salt history

Old documents keep their tokens (old salt), new ones get new tokens.
Correlation between old and new is **broken** (deliberately accepted); old
documents only disappear with the ISM delete (masked 30d, quarantine 90d by
default). No reindex, no downtime — but aggregations over the whole period
count old and new entities separately.

## Token-scheme change with unchanged salt

A change to the **token construction** — hash function, key/message build-up,
truncation, family/UTF-8 encoding — is **not a salt rotation**, but has **the
same operational consequence** for the masked stream: existing documents in the
stream were tokenized under the old scheme, so the old ↔ new correlation is
broken.

Concrete example: **0.1.8 → 0.1.9** — the masked-stream token changed from
concatenation `SHA-256("family:value:salt")[:16]` to
`HMAC-SHA256(key = salt, message = "family:value")[:16]`, with **unchanged
salt**. The same raw value produces different tokens even though the salt
stayed the same.

- **Response layer: no reindex, no history.** Response tokens are ephemeral —
  generated per query and **never stored**. With the next query they simply use
  the new construction; there is no migration window.
- **Option-B masked stream: like a salt rotation.** The stream stores tokens
  **permanently** (with the scheme that was baked into the pipeline at deploy
  time). The procedure is **identical to Path 2** — **Strategy A (reindex the
  retention window)** or **Strategy B (accept a two-salt history)** above —
  with the only difference that the salt **stays the same** and instead the
  **newly generated artifacts** (new scheme) are deployed:
  `klaxon masking generate --tenant X`, then
  `klaxon-mcp --apply-masked-infra --tenant X`, then
  `klaxon masking selftest --tenant X` (byte-identity of Painless ↔
  `derive_token` under the new scheme), then Strategy A or B. Correlation is
  broken in both cases — document the window.

**When does this apply?** On ANY change to token derivation — not only
HMAC-vs-SHA: hash function, key/message construction, truncation (e.g. a
different hex length), family or UTF-8 encoding. The generator self-test
(`klaxon masking generate` / `klaxon masking selftest`) does **not** fail on a
scheme change — it only checks that the generated Painless is byte-identical to
`derive_token`; the operational migration is the operator's job.

**Status: settle before the first productive deploy.** Option B is currently
**not deployed** (`klaxon-masked-*-v5*` = 0 shards) — so there is **no
production data** to migrate today. This is not an urgent incident, but a
**must-fix before the first productive deploy / migration window**: the scheme
change 0.1.8 → 0.1.9 has already happened, so the operator must decide before
the stream is first filled productively whether Strategy A or B applies.

## Common steps (both paths)

1. **Rotate the salt** — env on all hosts (secrets manager / deployment env;
   never commit, never log).
2. **Verify token determinism**: two queries / two syncs, same value → same
   token; new token ≠ old token.
3. **Re-run the generator self-test**: `klaxon masking selftest --tenant X`
   (byte-identity of Painless ↔ `derive_token`).
4. **Redeploy the pipeline** (path 2): `klaxon-mcp --apply-masked-infra
   --tenant X`, then `klaxon masking salt-check --tenant X` (deployed salt ==
   current env salt).
5. **Masked stream**: Strategy A (reindex) or B (two-salt window) — and
   document the correlation break explicitly.
6. **Docs/log**: record the rotation with date + reason (WITHOUT the salt
   itself) in the operations handbook/incident log.

## Entropy of the salt

- Recommended: `python -c "import secrets; print(secrets.token_hex(32))"`
  (64 hex chars = 32 bytes = 256 bits).
- Minimum that the startup warning accepts: 32 hex chars (16 bytes = 128
  bits). Anything shorter triggers a startup warning (`weak_salt`) — the salt
  is the HMAC key; a weak salt makes enumerable values easy to brute-force.
- The salt is a **secret**: restrict access (secrets manager / env on the
  deployment host, `0600` for `.salt` files, pipeline read
  (`GET /_ingest/pipeline`) for admins only).

## Relationship to the brute-force risk

Rotation mitigates the *duration* of a compromise (after the rotation the old
salt no longer applies to new values), but does **not** eliminate the
brute-force re-identification of already-tokenized values. The risk and the
mitigations are documented in [security-concept.md](security-concept.md).
