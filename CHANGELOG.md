# Changelog

## 0.4.0 — 2026-07-05

### Added — CRAM-MD5 als viertes Hash-Schema
- **Neues Schema `CRAM-MD5`** (Dovecot-kompatibel). Erzeugt einen
   32-Byte-HMAC-MD5-Key-Kontext, gespeichert als 64 Hex-Zeichen mit optionalem
  `{CRAM-MD5}`-Präfix. Beim Verify wird sowohl `{CRAM-MD5}` als auch das
  Dovecot-Alias `{HMAC-MD5}` akzeptiert.
- Implementierung in `lib/md5-block.js` (MD5-Block-Transform mit
  offengelegtem internen State) und `lib/cram-md5.js`. Ohne externe Deps.
- Neuer Test-Vektor gegen `doveadm pw` verifiziert:
  `password` → `{CRAM-MD5}9186d855e11eba527a7a52ca82b313e180d62234f0acc9051b527243d41e2740`.
- Cross-Check gegen Node `crypto.createHmac("md5", ...)` bestätigt: unsere
  gespeicherten ipad/opad-States entsprechen exakt der HMAC-MD5-Key-Setup.
- Sechs neue Tests (`hashes.test.js`): Round-Trip mit/ohne Präfix,
  Test-Vektor, Determinismus, Long-Key (>64 Byte), `{HMAC-MD5}`-Alias.

### Fixed — {SCHEMA}-Präfix wurde nicht immer korrekt geschrieben
- **Ursache:** Trigger-Action und Server-Funktionen lasen die Plugin-Config
  aus der **Closure**, die Saltcorn beim Registrieren des Plugins übergibt.
  Änderungen im „Modules → Configure”-Panel (u. a. `Dovecot-Präfix
  voranstellen`, `default_scheme`, `bcrypt_rounds`) griffen dort erst nach
  einem Neustart oder Neu-Register.
- **Fix:** `actionsFactory`, `functionsFactory` und `routesFactory` lesen
  jetzt aus `pluginState` — einer Modulvariable, die `onLoad` bei jedem
  Konfig-Update aktualisiert. Trigger-Attribute (`scheme`, `with_prefix`)
  haben weiterhin Vorrang; leere Attribute erben transparent den
  Plugin-Default.
- **Neu:** Der Trigger `hash_password_field` erhält ein zusätzliches
  Config-Feld `with_prefix` (Bool, leer = Plugin-Default). Damit kann pro
  Trigger überschrieben werden, ob das Ergebnis mit `{SCHEMA}` vorangestellt
  wird — praktisch, wenn parallel eine Tabelle Dovecot-kompatibel und eine
  andere ohne Präfix gespeist werden soll.
- Robustheit: alle Factories seeden `pluginState` mit ihrer Registrierungs-
  Config, falls `onLoad` noch nicht gelaufen ist.

### Changed
- `SCHEMES` exportiert jetzt `["BLF-CRYPT", "SHA512-CRYPT", "PBKDF2", "CRAM-MD5"]`.
- `detectSchemeFromHash` erkennt CRAM-MD5 bewusst **nicht** automatisch,
  weil 64 rohe Hex-Zeichen mehrdeutig sind (SHA-256 u. a.). Der Präfix ist
  Pflicht, wenn ein CRAM-MD5-Hash über `verifyPassword` geprüft werden soll.

### Tests
- 32/32 grün (25 → 32).

## 0.3.3 — 2026-07-04

### Fixed — DB-Insert-Regression
- **DB-Insert-Fehler `column "password_plain__confirm" of relation ... does not exist` behoben.**
  Der Trigger setzte `set_fields[<feld>__confirm] = undefined` und
  `set_fields[<feld>__scheme] = undefined`, um die Formularzusatzfelder aus
  der zu speichernden Row zu entfernen. `Object.assign` übernimmt aber auch
  `undefined`-Properties, sodass der pg-Client die nicht existierende Spalte
  in die INSERT-Query aufnahm. 0.3.3 verwendet stattdessen `delete row[...]`
  am Anfang der Trigger-Run-Funktion und lässt die Extra-Keys ganz weg.
- Regression-Test in `test/validation.test.js` ergänzt, der explizit prüft,
  dass `set_fields` weder `__confirm` noch `__scheme` als Keys enthält.

## 0.3.2 — 2026-07-04

> **Hinweis:** 0.3.2 hatte noch die `set_fields[...] = undefined`-Regression,
> die zum DB-Fehler `column "password_plain__confirm" of relation ... does not
> exist` geführt hat. Bitte direkt auf **0.3.3** aktualisieren.

### Fixed — echter Fix für Passwortbestätigung, Policy und Feld-Schema
- **Passwortbestätigung wird jetzt serverseitig zuverlässig durchgesetzt.**
  In 0.3.1 gab `readFromFormRecord` bei einem Mismatch `null` zurück. Bei
  nicht-required Feldern behandelt Saltcorn `readval===null` allerdings als
  Erfolg (`{success: null}`) — der Datensatz wurde deshalb weiterhin
  gespeichert. 0.3.2 gibt stattdessen einen Fehler-Marker (`__PWTOOLS_ERR__:…`)
  als Wert zurück; der Validate-Trigger `hash_password_field` erkennt den
  Marker und liefert ein `{error}`-Ergebnis, das den Insert/Update blockiert.
- **Policy (min_length, Score, Zeichenklassen) wird gleichermaßen erzwungen.**
  Bei umgangener Client-JS und aktivem Validate-Trigger blockt das Plugin jede
  Policy-Verletzung — mit passender Fehlermeldung im Feld.
- **Client-JS blockiert Save-Buttons robust.** Saltcorn rendert Save-Buttons
  als `<button type="button" onclick="ajaxSubmitForm(this, true)">`. Ein
  reines `submit`-Event feuert dabei nicht. 0.3.2 fängt Klicks auf alle
  plausiblen Submit-Buttons in der Capture-Phase ab, entfernt vorübergehend
  den inline `onclick`, führt eine Vor-Validierung durch und ruft den
  Original-Handler nur bei bestandener Prüfung wieder auf.
- Wrapper trägt jetzt `data-pwtools-enforce="1"`; damit greift die
  Client-JS-Blockade zuverlässig für jedes gerenderte Passwortfeld.

### Wichtig — Trigger-Empfehlung
- Der Trigger `hash_password_field` MUSS als **`Validate`**-Trigger
  konfiguriert werden, damit Fehler das Speichern blockieren. Insert/Update
  laufen zu spät (nach dem DB-Write). Die Dokumentation wurde entsprechend
  angepasst.

### Compatibility
- Rückwärtskompatibel. Keine Config- oder Feldänderungen nötig; bestehende
  Konfigurationen mit Insert/Update-Trigger arbeiten weiter, blockieren
  jedoch nicht — Umstellung auf Validate wird dringend empfohlen.

## 0.3.1 — 2026-07-04

### Fixed
- **Passwort-Bestätigung wird nun serverseitig erzwungen.** Bisher wurde
  `<feld>__confirm` vor dem DB-Insert verworfen (kein Tabellenfeld) und der
  Trigger lief erst nach dem Insert. Die Prüfung erfolgt jetzt im Fieldview
  `password_input` über `readFromFormRecord`, das laut Saltcorn-Feld-Validierung
  **vor** dem DB-Write ausgeführt wird. Bei nicht passender Bestätigung wird
  das Formular abgewiesen und der Fehler dem Feld angehängt.
- **Policy-Erzwingung greift jetzt zuverlässig.** Auch bei umgangenem
  Client-JS wird ein Passwort, das die Policy verletzt (Länge, Zeichenklassen,
  zxcvbn-Score), bereits im Fieldview abgelehnt.
- Trigger `hash_password_field` gibt nun `set_fields` mit dem Hash zurück.
  Bei Verwendung als **Validate**-Trigger schreibt Saltcorn den Hash direkt
  in die Tabelle statt das Klartext-Passwort — dies ist die neue empfohlene
  Konfiguration.
- Client-JS blockiert Submit robuster: Zusätzlich zum `submit`-Event werden
  Klicks auf Submit-Buttons in der Capture-Phase abgefangen, damit die
  Blockade auch bei AJAX-Submits und Direct-Button-Handlern greift.

### Migration
- **Empfehlung**: den Trigger `hash_password_field` auf **`Validate`**
  umstellen (statt `Insert`/`Update`). Dann wird das Klartextpasswort
  garantiert nie in der Datenbank landen und Policy-Verletzungen blockieren
  den Datensatz.
- Bestehende Insert/Update-Trigger funktionieren weiterhin, prüfen die
  Policy aber jetzt zuverlässig (dank neuem Fieldview-Pfad).

### Compatibility
- Rückwärtskompatibel. Keine Config- oder Feldänderungen nötig.

## 0.3.0 — 2026-07-04

### Added
- **Passwort-Bestätigungsfeld** in der Field-View `password_input`.
  Wenn aktiv (Default), zeigt die Field-View zwei nebeneinander liegende
  Passwortfelder (Bootstrap-Grid: nebeneinander ab `md`, untereinander auf
  schmalen Screens) und blockiert den Formular-Submit clientseitig, solange
  beide nicht identisch sind.
- Serverseitige Rückfall-Prüfung im Trigger `hash_password_field`: bricht
  mit Fehlermeldung ab, wenn `<feld>__confirm` mitgeliefert wird und nicht
  passt (fuer den Fall, dass die clientseitige Prüfung umgangen wird).
- Neue Field-View-Config-Optionen:
  - `require_confirm` (Bool, Default `true`) — Bestätigungsfeld anzeigen
  - `primary_label` (String) — Beschriftung des Passwortfelds
  - `confirm_label` (String) — Beschriftung des Bestätigungsfelds
- Live-Statusanzeige unter dem Bestätigungsfeld:
  grün „Stimmt überein“ / rot „Stimmen nicht überein“ mit
  Bootstrap-Validation-States (`is-valid`/`is-invalid`).

### Compatibility
- Rückwärtskompatibel. Bestehende Views mit `password_input` erhalten
  automatisch das Bestätigungsfeld. Wer das nicht will, setzt in den
  Field-View-Config-Optionen `require_confirm` auf `false`.

## 0.2.0 — 2026-07-03

### Fixed / Changed
- **Breaking:** Registriert nun **fieldviews auf dem bestehenden String-Typ**
  statt eigene SQL-Typen `Password Plain` / `Password Hash` anzulegen.
  Damit erscheinen die Views in Saltcorn's Field-Editor sofort und ohne
  DB-Migration:
  - `password_input` (Edit) — Klartext-Eingabe mit Live-Staerke und Schema-Dropdown
  - `password_hash_show` (Show) — maskierter Hash
- `module.exports` ist jetzt ein statisches Objekt (Saltcorn Plugin-API v1).
  Actions, Functions, Routes und Headers werden als Factories geliefert und
  bekommen die Plugin-Config aufgeloest.
- `routes`-Callback-Signatur auf `(req, res)` korrigiert.
- `serve_dependencies` entfernt: Dateien in `public/` werden automatisch
  unter `/plugins/public/saltcorn-password-tools/` ausgeliefert.
- `plugin_name` explizit gesetzt.

### Migration von 0.1.x
Falls Sie 0.1.x installiert hatten: Legen Sie Ihre Felder als **String**-Felder
an (nicht als "Password Plain" / "Password Hash") und waehlen Sie fuer sie
die neuen Field-Views `password_input` bzw. `password_hash_show`.

## 0.1.0 — 2026-07-03
- Initial release.
