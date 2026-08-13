# Security Concept — Pseudonymisierung & Salt

Dieses Dokument beschreibt das Sicherheitsmodell der Tokenisierung in Klaxon:
die Konstruktion der Tokens (keyed HMAC-SHA256), die Rolle des Salts und — im
Kern dieses Dokuments — das **Pseudonymisierungs-Risiko: Brute-Force-
Re-Identifikation** (aufzählbare Werte mit bekanntem Salt), seine Mitigationen
und das akzeptierte Restrisiko.

Siehe auch:
- [`security-model.md`](security-model.md) — Token-Schema, 16 Hex, Salt-Auflösung
- [`salt-rotation-runbook.md`](salt-rotation-runbook.md) — Rotations-Runbook
  (keine geplante Rotation; nur bei Verdacht)
- [`option-b-masked-stream.md`](option-b-masked-stream.md) — Masked/Quarantäne-Stream

---

## Konstruktion der Tokens

- Token-Display: `[FAMILIE_16hex]` (z.B. `[USER_3cc5982657e33301]`).
- Konstruktion (Response-Layer UND Masked-Stream identisch):
  `HMAC-SHA256(key = Salt, message = "<familie>:<wert>")`, auf 16 Hex-Zeichen
  (64 Bit) gekürzt.
- Eine **keyed MAC** (kein Konkatenations-Hash): Das Salt ist der Schlüssel, die
  Familie der Kontext — derselbe Wert in verschiedenen Familien ergibt
  verschiedene Tokens; die Konstruktion ist nicht anfällig für
  Length-Extension-artigen Missbrauch.
- Deterministisch: gleicher Wert + gleiche Familie + gleiches Salt → gleiches
  Token, über Aufrufe und Neustarts hinweg, in `_source`, Aggregations-Bucket-Keys
  und `composite after_key`.
- Byte-Identität zwischen Python (`tokens.derive_token`) und dem generierten
  Painless-Script wird vom Generator-Selbsttest erzwungen (und von
  `klaxon masking test` live gegen den Indexer geprüft). Der Painless-Teil
  implementiert HMAC-SHA256 in reinem Painless (der Ingest-Allowlist fehlt
  `javax.crypto.Mac`), byte-identisch zu Pythons `hmac`.

---

## Pseudonymisierungs-Risiko: Brute-Force-Re-Identifikation

### Risiko

Pseudonymisierung ist **keine Anonymisierung**. Ein Token hat zwar 64 Bit
Digest-Entropie (16 Hex), aber die **Werte-Raum** ist oft klein und aufzählbar:

- Benutzernamen, interne IP-Adressen, Hostnamen, Agent-IDs — typischerweise
  einige Tausend bis Millionen Kandidaten.
- Mit **bekanntem Salt** kann ein Angreifer für jeden Kandidaten das Token
  berechnen (HMAC ist öffentlich) und mit dem beobachteten Token abgleichen.
  Ein Dictionary- oder Brute-Force-Angriff ist dann praktisch sofort erfolgreich.

Das Salt ist die einzige Barriere. Wird es kompromittiert (Leak in Logs,
Backups, Repos; `params.salt` der Pipeline von Unbefugten gelesen; Zugriff auf
den Deployment-Host), sind **alle** tokenisierten Werte re-identifizierbar —
unabhängig von der Token-Konstruktion (keyed HMAC hat unter Salt-Kompromiss
dieselbe Brute-Force-Exposition wie ein Konkatenations-Hash; HMAC ist dennoch
die standardisierte, robustere Schlüssel-Konstruktion und entspricht der
Designabsicht).

### Mitigationen

| Mitigation | Wirkung |
|---|---|
| **Keyed HMAC** (Salt als Schlüssel, Familie als Kontext) | Standard-Konstruktion, resistent gegen Length-Extension-artigen Missbrauch; Familie trennt gleiche Werte in verschiedenen Kontexten. |
| **Salt als hoch-entropiges Secret** (≥ 256 Bit empfohlen; `secrets.token_hex(32)`); Startup-Warnung bei < 32 Hex | Macht das *Erraten des Salts* infeasible (der Angriff bleibt auf „Salt bekannt" beschränkt). |
| **Zugriff auf das Salt beschränken** (Secrets Manager / Env auf dem Deployment-Host, `0600` für `.salt`, Pipeline-Read nur für Admins) | Reduziert die Wahrscheinlichkeit einer Salt-Kompromittierung. |
| **Rotation nur bei Verdacht** (nie planmäßig) | Begrenzt die Dauer einer Kompromittierung; bricht aber bewusst die Korrelation (siehe Runbook). |
| **Response-Layer-only-Konstruktion** (keine Rohwerte gespeichert; nur der Masked-Stream hält Tokens) | Verkleinert die Angriffsfläche auf die Streams, in denen Tokens dauerhaft liegen. |

### Restrisiko (akzeptiert)

Ein motivierter Angreifer **mit dem Salt** und einem guten Dictionary kann
spezifische aufzählbare Werte brechen. Das ist dem Pseudonymisierungs-Modell
inhärent und lässt sich nicht vollständig entfernen, ohne die deterministische
Tokenisierung (die für korrelierbare Aggregationen und die
Zwei-Schichten-Idempotenz nötig ist) aufzugeben. Akzeptiert by design;
dokumentiert, damit Betreiber die Restrisiken (Salt-Handling, Zugriff auf den
Masked/Quarantäne-Stream) entsprechend behandeln.

### Operative Konsequenzen

1. **Salt niemals loggen/committen/exportieren** — nicht in Fehlermeldungen,
   Config-Dumps, Health-Endpoints oder committete Artifakte. Deploybare
   Pipeline-Dateien mit echtem Salt sind gitignored.
2. **Quarantäne-Stream ist Rohdaten** — nur Ops-Rolle; nie im LLM-Allowlist.
3. **Rotation gemäß Runbook** (nur bei Verdacht) — nicht planmäßig.
4. Bei Salt-Verdacht: **nicht** nur rotieren, sondern auch prüfen, ob bereits
   Tokens abgeflossen sind (Incident-Response; Rotation re-anonymisiert nichts
   bereits Geleaktes).
