# Changelog

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
