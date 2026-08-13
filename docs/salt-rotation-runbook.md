# Salt-Rotations-Runbook (Token-Salt)

**Kurzfassung: Es gibt KEINE geplante/periodische Salt-Rotation.** Rotation
bricht die Korrelation zwischen vor- und nach-rotations-Tokens (gleicher
Rohwert → anderes Token) — das ist ein akzeptierter Trade-off. Rotiere NUR bei
begründetem Verdacht auf Salt-Kompromittierung.

> Ein **Token-Schema-Wechsel bei unverändertem Salt** (z.B. 0.1.8 → 0.1.9) ist
> KEINE Rotation, hat aber für den Masked Stream **dieselbe operative
> Konsequenz** und nutzt dasselbe Playbook — siehe
> [Token-Schema-Wechsel bei unverändertem Salt](#token-schema-wechsel-bei-unverändertem-salt).

---

## Grundsatz

Das Salt (`KLAXON_ANONYMIZATION_SALT`) ist der HMAC-Schlüssel, mit dem Werte
tokenisiert werden. Solange es geheim und unverändert bleibt, sind Tokens über
Zeit und über den Response-Layer und den Masked-Stream hinweg deterministisch.
Wird das Salt gewechselt, produziert derselbe Rohwert ein **anderes** Token —
Dokumente/Abfragen von vor der Rotation lassen sich nicht mehr mit solchen von
nach der Rotation korrelieren. Genau deshalb:

> **Rotiere das Salt nicht planmäßig.** Rotation ist ein Notfall-Eingriff,
> keine Routine. Dokumentiert ist sie hier als Runbook für den Verdachtsfall.

Wann rotieren? Nur wenn Grund zur Annahme besteht, dass das Salt kompromittiert
ist oder war (Leak in Logs/Backups/Repos, Zugriff auf den Deployment-Host durch
Unbefugte, Pipeline-`params.salt` von Unbefugten gelesen, ...).

## Was Rotation NICHT tut

- Sie re-anonymisiert **keine bereits geleakten Rohdaten/Tokens**. Ein Wert,
  der unter dem kompromittierten Salt schon tokenisiert und abgeflossen ist,
  bleibt re-identifizierbar.
- Sie entfernt die Brute-Force-Re-Identifikationsgefahr für Werte, die bereits
  unter dem kompromittierten Salt tokenisiert wurden.
- Sie ist **kein Ersatz** für die übrigen Kontrollen (Salt-Zugriff beschränken,
  Pipeline-Read sperren, Quarantäne/Backstop). Siehe
  [security-concept.md](security-concept.md).

## Pfad 1 — Response-Layer (billig, kein Reindex)

Der Response-Layer tokenisiert pro Query; er speichert keine Tokens dauerhaft.

1. Salt auf allen Hosts in der Umgebung rotieren
   (`KLAXON_ANONYMIZATION_SALT`, z.B. `secrets.token_hex(32)`; siehe
   [§ Entropie](#entropie-des-salts)).
2. Alle Klaxon-Prozesse neu starten.
3. Determinsmus über zwei Queries prüfen: derselbe Wert liefert in beiden
   Antworten dasselbe Token (und ein anderes als vor der Rotation).
4. Generator-Selbsttest erneut ausführen (`klaxon masking selftest
   --tenant X`).
5. **Kein Reindex nötig.** Historische Abfragen (falls überhaupt gespeichert)
   korrelieren nicht mehr mit neuen Tokens — bewusst.

## Pfad 2 — Option-B Masked Stream (reindex ODER Zwei-Salt-Fenster)

Der Masked Stream speichert Tokens **dauerhaft** (mit dem Salt, das zum
Deploy-Zeitpunkt in die Pipeline eingebacken war). Nach einer Salt-Rotation
gilt:

- **Neue Syncs** tokenisieren mit dem neuen Salt (Pipeline muss neu deployed
  werden, siehe unten).
- **Alte Dokumente** im Stream sind mit dem alten Salt tokenisiert. Es gibt
  zwei akzeptable Strategien:

> Für einen **Token-Schema-Wechsel bei unverändertem Salt** gelten Strategie A
> und B genauso (dort bleibt nur das Salt gleich; die Pipeline wird mit den neu
> generierten Artifakten des neuen Schemas deployed) — siehe
> [Token-Schema-Wechsel bei unverändertem Salt](#token-schema-wechsel-bei-unverändertem-salt).

### Strategie A — Retentionsfenster reindizieren

Reindiziere das Retentionsfenster der Rohdaten (`wazuh-events-v5-*`) durch die
neu gebaute Pipeline in den Masked Stream. Danach ist der gesamte Stream
konsistent mit dem neuen Salt.

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

Hinweis: Der Sync-Job verhindert Duplikate über `op_type: create` +
`conflicts: proceed`; ein Teilfenster wird nicht doppelt angelegt. Alte Tokens
(mit altem Salt) bleiben bis zum ISM-Delete im Quarantäne-/Masked-Stream und
korrelieren nicht mit den neuen — dokumentiere das Fenster.

### Strategie B — Zwei-Salt-Historie akzeptieren

Alte Dokumente behalten ihre Tokens (altes Salt), neue bekommen neue Tokens.
Korrelation zwischen alt und neu ist **gebrochen** (bewusst akzeptiert); alte
Dokumente verschwinden erst mit dem ISM-Delete (Masked 30d, Quarantäne 90d
Default). Kein Reindex, keine Ausfallzeit — aber Aggregationen über den
Gesamtzeitraum zählen alte und neue Entitäten getrennt.

## Token-Schema-Wechsel bei unverändertem Salt

*(engl. „token-scheme change with unchanged salt“)* — Ein Wechsel der
**Token-Konstruktion** — Hash-Funktion, Key/Message-Aufbau,
Trunkierung, Familien-/UTF-8-Kodierung — ist **keine Salt-Rotation**, hat aber
für den Masked Stream **dieselbe operative Konsequenz**: Bestandsdokumente im
Stream wurden unter dem alten Schema tokenisiert, die Korrelation alt ↔ neu ist
gebrochen.

Konkretes Beispiel: **0.1.8 → 0.1.9** — der Masked-Stream-Token wechselte von
Konkatenations-`SHA-256("family:value:salt")[:16]` zu
`HMAC-SHA256(key = salt, message = "family:value")[:16]`, bei **unverändertem
Salt**. Derselbe Rohwert produziert andere Tokens, obwohl das Salt gleich blieb.

- **Response-Layer: kein Reindex, keine Historie.** Response-Tokens sind
  ephemer — pro Query erzeugt und **nie gespeichert**. Mit der nächsten Query
  verwenden sie einfach die neue Konstruktion; es gibt kein Migrationsfenster.
- **Option-B Masked Stream: wie eine Salt-Rotation.** Der Stream speichert
  Tokens **dauerhaft** (mit dem Schema, das beim Deploy in die Pipeline
  eingebacken war). Das Vorgehen ist **identisch zu Pfad 2** —
  **Strategie A (Retentionsfenster reindizieren)** oder
  **Strategie B (Zwei-Salt-Historie akzeptieren)** oben — mit dem einzigen
  Unterschied, dass das Salt **gleich bleibt** und stattdessen die **neu
  generierten Artifakte** (neues Schema) deployed werden:
  `klaxon masking generate --tenant X`, dann
  `klaxon-mcp --apply-masked-infra --tenant X`, dann
  `klaxon masking selftest --tenant X` (Byte-Identität Painless ↔
  `derive_token` unter dem neuen Schema), danach Strategie A oder B. Die
  Korrelation ist in beiden Fällen gebrochen — dokumentiere das Fenster.

**Wann gilt das?** Bei JEDER Änderung der Token-Ableitung — nicht nur bei
HMAC-vs-SHA: Hash-Funktion, Key/Message-Konstruktion, Trunkierung (z.B. andere
Hex-Länge), Familien- oder UTF-8-Kodierung. Der Generator-Selbsttest
(`klaxon masking generate` / `klaxon masking selftest`) schlägt bei einem
Schema-Wechsel **nicht** fehl — er prüft nur, dass das generierte Painless mit
`derive_token` byte-identisch ist; die operative Migration ist Operator-Sache.

**Status: vor dem ersten produktiven Deploy klären.** Option B ist derzeit
**nicht deployed** (`klaxon-masked-*-v5-*` = 0 Shards) — es gibt also heute
**keine Produktionsdaten** zu migrieren. Der Fall ist kein akuter Notfall,
sondern ein **Must-Fix vor dem ersten produktiven Deploy / Migrationsfenster**:
der Schema-Wechsel 0.1.8 → 0.1.9 ist bereits geschehen, also muss der
Betreiber vor der ersten produktiven Befüllung des Streams entscheiden, ob
Strategie A oder B gilt.

## Gemeinsame Schritte (beide Pfade)

1. **Salt rotieren** — env auf allen Hosts (Secrets Manager / Deployment-Env;
   niemals committen, niemals loggen).
2. **Token-Determinismus verifizieren**: zwei Queries / zwei Syncs, gleicher
   Wert → gleiches Token; neues Token ≠ altes Token.
3. **Generator-Selbsttest** erneut ausführen: `klaxon masking selftest
   --tenant X` (byte-identität Painless ↔ `derive_token`).
4. **Pipeline neu deployen** (Pfad 2): `klaxon-mcp --apply-masked-infra
   --tenant X`, dann `klaxon masking salt-check --tenant X` (Deployed-Salt ==
   aktuelles Env-Salt).
5. **Masked Stream**: Strategie A (Reindex) oder B (Zwei-Salt-Fenster) — und
   die Korrelationsbrechung explizit dokumentieren.
6. **Doku/Log**: Rotation mit Datum + Grund (OHNE das Salt selbst) ins
   Betriebshandbuch/Incident-Log eintragen.

## Entropie des Salts

- Empfohlen: `python -c "import secrets; print(secrets.token_hex(32))"`
  (64 Hex-Zeichen = 32 Bytes = 256 Bit).
- Minimum, das die Startup-Warnung akzeptiert: 32 Hex-Zeichen (16 Bytes =
  128 Bit). Alles kürzere erzeugt eine Startup-Warnung (`weak_salt`) — das Salt
  ist der HMAC-Schlüssel, ein schwaches Salt macht aufzählbare Werte leicht
  brute-forcbar.
- Das Salt ist ein **Secret**: Zugriff beschränken (Secrets Manager / Env auf
  dem Deployment-Host, `0600` für `.salt`-Dateien, Pipeline-Read
  (`GET /_ingest/pipeline`) nur für Admins).

## Zusammenhang mit dem Brute-Force-Risiko

Rotation mildert die *Dauer* einer Kompromittierung (nach der Rotation gilt das
alte Salt nicht mehr für neue Werte), beseitigt aber **nicht** die Brute-Force-
Re-Identifikation bereits tokenisierter Werte. Das Risiko und die Mitigationen
sind in [security-concept.md](security-concept.md) dokumentiert.
