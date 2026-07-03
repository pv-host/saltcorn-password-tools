# saltcorn-password-tools

Ein [Saltcorn](https://saltcorn.com/)-Plugin, das Passwörter im **Klartext** entgegennimmt
und automatisch als sicheren, **Dovecot-kompatiblen Hash** speichert.

Unterstützte Hash-Schemata:

| Schema        | Format (Beispiel)                                         |
| ------------- | --------------------------------------------------------- |
| `BLF-CRYPT`   | `{BLF-CRYPT}$2y$12$…` (bcrypt)                            |
| `SHA512-CRYPT`| `{SHA512-CRYPT}$6$rounds=5000$salt$hash`                  |
| `PBKDF2`      | `{PBKDF2}$1$salt$25000$…` (Dovecot-Format, hex-encoded)   |

Der Dovecot-`{SCHEME}`-Prefix ist **konfigurierbar** — sowohl global in der
Plugin-Config als auch pro Feld.

Zusätzlich wird die **Passwortstärke** live geprüft:
`zxcvbn`-Score (0–4) kombiniert mit klassischen Regeln (Mindestlänge, Groß-/Kleinbuchstaben, Ziffern, Sonderzeichen).

---

## Installation

### Aus dem Saltcorn-Modul-Store

Sobald das Plugin im Store gelistet ist:

1. **Settings → Modules → Available**
2. `saltcorn-password-tools` suchen → **Install**

### Aus lokalem Checkout / Fork

```bash
git clone https://github.com/pv-host/saltcorn-password-tools.git
cd saltcorn-password-tools
npm install
saltcorn install-plugin -d $(pwd)
```

### Direkt aus GitHub

```bash
saltcorn install-plugin -n saltcorn-password-tools \
  -s git -l https://github.com/pv-host/saltcorn-password-tools
```

---

## Verwendung

### 1. Tabelle vorbereiten

Lege in der Ziel-Tabelle **zwei String-Felder** an:

| Feldname         | Typ      | Zweck                                                              |
| ---------------- | -------- | ------------------------------------------------------------------ |
| `password_plain` | `String` | Eingabefeld (im Editor sichtbar, wird nach dem Hashen wieder geleert) |
| `password_hash`  | `String` | Gespeicherter Hash                                                 |

> Beide Felder sind normale `String`-Felder. Das Plugin erweitert den
> String-Typ um zwei neue Field-Views (`password_input`, `password_hash_show`).

### 2. Edit-View konfigurieren

Setze in der Edit-View für `password_plain` die Field-View **`password_input`**
(zu finden im Dropdown der verfügbaren Field-Views). Sie zeigt:

- ein Passwortfeld (`<input type="password">`)
- ein optionales Schema-Dropdown (`BLF-CRYPT` / `SHA512-CRYPT` / `PBKDF2`)
- einen live aktualisierten Stärke-Balken mit Feedback

Für `password_hash` in Show-Views die Field-View **`password_hash_show`** wählen
(zeigt den Hash maskiert). In Edit-Views braucht `password_hash` in der Regel
gar nicht angezeigt zu werden.

### 3. Automatisches Hashen einrichten

Erstelle einen **Trigger** in der Ziel-Tabelle:

- **When:** `Insert` und `Update`
- **Action:** `hash_password_field`
- Konfiguration:
  - Quellfeld: `password_plain`
  - Zielfeld: `password_hash`
  - Passwortpolicy erzwingen: ✅
  - Klartextfeld nach Hashen leeren: ✅

Damit wird bei jedem Speichern der Klartext gehasht, ins Hash-Feld geschrieben
und das Klartextfeld anschließend geleert.

---

## Plugin-Konfiguration (Settings → Modules → Configure)

| Option                | Default        | Beschreibung |
| --------------------- | -------------- | ------------ |
| Standard-Hash-Schema  | `BLF-CRYPT`    | Fallback, wenn im Formular nichts gewählt wird |
| Benutzer darf Schema wählen | `true`   | Steuert das Dropdown im Editor |
| Dovecot-Prefix        | `true`         | Prefix `{SCHEME}` voranstellen |
| BLF-CRYPT Rounds      | `12`           | bcrypt cost factor (4–15) |
| BLF-CRYPT Prefix      | `2y`           | `$2y$` empfohlen für Dovecot |
| SHA512-CRYPT Rounds   | `5000`         | ≥ 1000 |
| PBKDF2 Iterationen    | `25000`        | ≥ 1000 |
| Passwortpolicy: Mindestlänge | `10`    | |
| Grossbuchstabe / Kleinbuchstabe / Ziffer / Sonderzeichen | `✅ / ✅ / ✅ / ❌` | |
| Min. zxcvbn Score     | `3`            | 0 = beliebig, 4 = sehr stark |

Jede dieser Optionen lässt sich **pro Feld** überschreiben (Feldattribute).

---

## Programmatische Nutzung

Das Plugin registriert drei Funktionen (in Code-Actions / Formeln nutzbar):

```js
// Klartext hashen
const hash = await pwtools_hash("MeinPasswort!23", { scheme: "SHA512-CRYPT" });

// Verifizieren (Schema wird aus dem Prefix / Format automatisch erkannt)
const ok = await pwtools_verify("MeinPasswort!23", hash);

// Stärke ermitteln
const s = pwtools_strength("MeinPasswort!23");
// -> { valid, score: 0-4, problems: [...], suggestions: [...] }
```

Die Funktionen lassen sich auch direkt aus Node importieren, falls du das
Plugin als Library nutzen willst:

```js
const { hashPassword, verifyPassword } = require("saltcorn-password-tools/lib/hashes");
```

---

## HTTP-Endpoint

Für eine live Stärke-Prüfung via Ajax:

```
POST /pwtools/strength
Content-Type: application/json
{ "password": "…", "policy": { "minLength": 12, "minScore": 3 } }
```

Antwort:

```json
{ "valid": false, "score": 2, "problems": ["…"], "suggestions": ["…"] }
```

---

## Kompatibilität

- Saltcorn ≥ 0.9 (Plugin-API v1)
- Node.js ≥ 16
- Dovecot: `BLF-CRYPT`, `SHA512-CRYPT` und `PBKDF2` sind mit den offiziellen
  Dovecot-Formaten kompatibel (siehe [Dovecot Password Schemes](https://doc.dovecot.org/main/core/config/auth/schemes.html)).

---

## Sicherheit

- Klartextpasswörter werden **nie** in der Datenbank gespeichert.
  Die `Password Plain`-Field-View gibt beim erneuten Öffnen einer Zeile das
  Feld leer zurück; die `hash_password_field`-Action leert das Klartextfeld
  standardmäßig nach dem Hashen.
- Alle Hashes verwenden **kryptographisch sichere Zufallswerte** für den Salt
  (`crypto.randomBytes`).
- `verifyPassword` verwendet konstantzeitlichen Vergleich (`crypto.timingSafeEqual`).

---

## Entwicklung

```bash
git clone https://github.com/pv-host/saltcorn-password-tools.git
cd saltcorn-password-tools
npm install
npm test
```

Lokales Einbinden in eine laufende Saltcorn-Instanz:

```bash
saltcorn install-plugin -d $(pwd)
# oder umgekehrt: aus npm zurueck auf lokal umstellen
saltcorn dev:localize-plugin $(pwd)
```

## Lizenz

MIT © 2026 Peter Vassen / pv-host.net
