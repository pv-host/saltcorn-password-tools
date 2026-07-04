# Changelog

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
