/**
 * saltcorn-password-tools
 *
 * Saltcorn plugin: nimmt Klartext-Passwoerter entgegen und speichert sie
 * automatisch als Dovecot-kompatiblen Hash. Unterstuetzt BLF-CRYPT,
 * SHA512-CRYPT und PBKDF2 mit konfigurierbarem {SCHEME}-Prefix.
 * Live-Passwortstaerke via zxcvbn + Regelpruefung.
 *
 * Bereitgestellt werden:
 *   - Zwei zusaetzliche fieldviews fuer den bestehenden Typ String:
 *       * password_input      (Edit: Klartext-Eingabe + Staerke-Meter + Schema-Dropdown)
 *       * password_hash_show  (Show: maskierter Hash-Anzeige)
 *   - Trigger-Action `hash_password_field`
 *   - Server-Funktionen pwtools_hash / pwtools_verify / pwtools_strength
 *   - HTTP-Endpoint POST /pwtools/strength
 */

"use strict";

const Workflow = require("@saltcorn/data/models/workflow");
const Form = require("@saltcorn/data/models/form");
const { input, span, select, option } = require("@saltcorn/markup/tags");

const { SCHEMES, hashPassword, verifyPassword } = require("./lib/hashes");
const { evaluate } = require("./lib/strength");

const PLUGIN_NAME = "saltcorn-password-tools";

// Sonderprefix fuer Fehler-Weitergabe: readFromFormRecord kann keinen
// {error}-Wert direkt zurueckgeben, weil Field.validate bei readval===null
// bei nicht-required Feldern einfach {success:null} produziert (kein Fehler).
// Wir schmuggeln daher einen Marker-String durch, den der Validate-Trigger
// erkennt und in {error} umwandelt.
const PWTOOLS_ERR_PREFIX = "__PWTOOLS_ERR__:";

// Sonderprefix fuer Schema-Weitergabe vom Fieldview zum Validate-Trigger.
// Hintergrund: Form.validate() baut form.values ausschliesslich aus
// registrierten Table-Feldern auf. Extra-Formfelder wie <name>__scheme sind
// keine Table-Felder und landen deshalb NIE in v_in, das der Trigger sieht.
// readFromFormRecord ist unsere einzige Chance, den req.body zu lesen -
// deshalb kodieren wir die User-Wahl in den Rueckgabewert (Klartext) und
// packen sie im Trigger wieder aus.
const PWTOOLS_SCHEME_PREFIX = "__PWTOOLS_SCHEME__:";

// Extrahiert eine ggf. vorangestellte Schema-Wahl aus einem Klartext-String.
// Rueckgabe: { scheme: string|null, plain: string }.
function extractSchemeSentinel(value) {
  if (typeof value !== "string" || !value.startsWith(PWTOOLS_SCHEME_PREFIX)) {
    return { scheme: null, plain: value };
  }
  const rest = value.slice(PWTOOLS_SCHEME_PREFIX.length);
  const sep = rest.indexOf("|");
  if (sep < 0) return { scheme: null, plain: value };
  return { scheme: rest.slice(0, sep), plain: rest.slice(sep + 1) };
}

// -----------------------------------------------------------------------------
// Configuration Workflow (Settings -> Modules -> Configure)
// -----------------------------------------------------------------------------

const configuration_workflow = () =>
  new Workflow({
    steps: [
      {
        name: "Standard-Einstellungen",
        form: () =>
          new Form({
            fields: [
              {
                name: "default_scheme",
                label: "Standard-Hash-Schema",
                type: "String",
                required: true,
                attributes: { options: SCHEMES },
                default: "BLF-CRYPT",
                sublabel:
                  "Wird verwendet, wenn im Feld/Formular nichts explizit ausgewaehlt ist.",
              },
              {
                name: "allow_user_choice",
                label: "Benutzer darf Schema im Formular waehlen",
                type: "Bool",
                default: true,
              },
              {
                name: "with_prefix",
                label: "Dovecot-Prefix {SCHEME} voranstellen",
                type: "Bool",
                default: true,
              },
              {
                name: "bcrypt_rounds",
                label: "BLF-CRYPT: Cost / Rounds",
                type: "Integer",
                default: 12,
                attributes: { min: 4, max: 15 },
              },
              {
                name: "bcrypt_prefix",
                label: "BLF-CRYPT: Prefix-Variante",
                type: "String",
                required: true,
                default: "2y",
                attributes: { options: ["2a", "2b", "2y"] },
              },
              {
                name: "sha512_rounds",
                label: "SHA512-CRYPT: Rounds",
                type: "Integer",
                default: 5000,
                attributes: { min: 1000, max: 1000000 },
              },
              {
                name: "pbkdf2_iterations",
                label: "PBKDF2: Iterationen",
                type: "Integer",
                default: 25000,
                attributes: { min: 1000, max: 1000000 },
              },
              {
                name: "min_length",
                label: "Passwortpolicy: Mindestlaenge",
                type: "Integer",
                default: 10,
                attributes: { min: 4, max: 128 },
              },
              {
                name: "require_upper",
                label: "Grossbuchstabe erforderlich",
                type: "Bool",
                default: true,
              },
              {
                name: "require_lower",
                label: "Kleinbuchstabe erforderlich",
                type: "Bool",
                default: true,
              },
              {
                name: "require_digit",
                label: "Ziffer erforderlich",
                type: "Bool",
                default: true,
              },
              {
                name: "require_symbol",
                label: "Sonderzeichen erforderlich",
                type: "Bool",
                default: false,
              },
              {
                name: "min_score",
                label: "Minimaler zxcvbn-Score (0-4)",
                type: "Integer",
                default: 3,
                attributes: { min: 0, max: 4 },
              },
            ],
          }),
      },
    ],
  });

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function mergeOpts(pluginCfg, attrs) {
  const c = pluginCfg || {};
  const a = attrs || {};
  return {
    scheme: a.scheme || c.default_scheme || "BLF-CRYPT",
    withPrefix:
      typeof a.with_prefix === "boolean"
        ? a.with_prefix
        : typeof c.with_prefix === "boolean"
        ? c.with_prefix
        : true,
    bcryptRounds: a.bcrypt_rounds || c.bcrypt_rounds || 12,
    bcryptPrefix: a.bcrypt_prefix || c.bcrypt_prefix || "2y",
    sha512Rounds: a.sha512_rounds || c.sha512_rounds || 5000,
    pbkdf2Iterations: a.pbkdf2_iterations || c.pbkdf2_iterations || 25000,
    pbkdf2KeyLen: 64,
    pbkdf2Digest: "sha512",
    allowUserChoice:
      typeof a.allow_user_choice === "boolean"
        ? a.allow_user_choice
        : typeof c.allow_user_choice === "boolean"
        ? c.allow_user_choice
        : true,
  };
}

function mergePolicy(pluginCfg, attrs) {
  const pick = (x, y, d) => (x !== undefined ? x : y !== undefined ? y : d);
  const c = pluginCfg || {};
  const a = attrs || {};
  return {
    minLength: pick(a.min_length, c.min_length, 10),
    requireUpper: pick(a.require_upper, c.require_upper, true),
    requireLower: pick(a.require_lower, c.require_lower, true),
    requireDigit: pick(a.require_digit, c.require_digit, true),
    requireSymbol: pick(a.require_symbol, c.require_symbol, false),
    minScore: pick(a.min_score, c.min_score, 3),
  };
}

function looksLikeHash(s) {
  return (
    typeof s === "string" &&
    (/^\{[A-Z0-9-]+\}/.test(s) ||
      /^\$2[aby]\$/.test(s) ||
      /^\$6\$/.test(s) ||
      /^\$1\$[^$]+\$\d+\$[0-9a-f]+$/i.test(s))
  );
}

function maskHash(s) {
  if (typeof s !== "string") return "";
  // Genug Kontext lassen, damit der Prefix ({SCHEMA}) sichtbar bleibt.
  // 10 Zeichen Anfang + Ellipse + 4 Zeichen Ende. Ist der Hash so kurz,
  // dass die Maske laenger waere als der Hash selbst, wird komplett maskiert.
  const HEAD = 10;
  const TAIL = 4;
  if (s.length <= HEAD + TAIL + 1) return "••••";
  return s.slice(0, HEAD) + "…" + s.slice(-TAIL);
}

function escapeAttrJson(obj) {
  return JSON.stringify(obj).replace(/'/g, "&#39;");
}

function renderPlainEditor({
  name,
  cls,
  schemes,
  defaultScheme,
  allowUserChoice,
  policy,
  requireConfirm,
  confirmLabel,
  primaryLabel,
}) {
  const id = `sc_pwd_${(name || "field").replace(/[^A-Za-z0-9_]/g, "_")}`;
  const confirmId = `${id}_confirm`;

  const schemeControl = allowUserChoice
    ? select(
        {
          name: `${name}__scheme`,
          id: `${id}_scheme`,
          class: "form-select form-select-sm mt-1",
          "data-pwtools-scheme": "1",
        },
        schemes.map((s) =>
          option(
            { value: s, ...(s === defaultScheme ? { selected: true } : {}) },
            s
          )
        )
      )
    : input({ type: "hidden", name: `${name}__scheme`, value: defaultScheme });

  const meter =
    `<div class="pwtools-strength mt-2" data-pwtools-meter-for="${id}">` +
    `<div class="progress" style="height:6px"><div class="progress-bar" role="progressbar" style="width:0%"></div></div>` +
    `<small class="pwtools-strength-label text-muted d-block mt-1">Bitte Passwort eingeben</small>` +
    `<ul class="pwtools-strength-feedback small text-danger mb-0 mt-1"></ul>` +
    `</div>`;

  const primaryInput = input({
    type: "password",
    class: `form-control ${cls || ""}`,
    name,
    id,
    autocomplete: "new-password",
    "data-pwtools-input": "1",
  });

  if (!requireConfirm) {
    return (
      `<div class="pwtools-wrapper" data-pwtools-enforce="1" data-pwtools-policy='${escapeAttrJson(policy)}' data-pwtools-confirm="0">` +
      primaryInput +
      (allowUserChoice
        ? `<label class="form-label small text-muted mt-1 mb-0" for="${id}_scheme">Hash-Schema</label>`
        : "") +
      schemeControl +
      meter +
      `</div>`
    );
  }

  const confirmInput = input({
    type: "password",
    class: `form-control ${cls || ""}`,
    name: `${name}__confirm`,
    id: confirmId,
    autocomplete: "new-password",
    "data-pwtools-confirm-input": "1",
  });

  const pLabel = primaryLabel || "Passwort";
  const cLabel = confirmLabel || "Passwort wiederholen";

  // Zwei Spalten nebeneinander (Bootstrap-Grid), untereinander auf schmalen Screens.
  return (
    `<div class="pwtools-wrapper" data-pwtools-enforce="1" data-pwtools-policy='${escapeAttrJson(policy)}' data-pwtools-confirm="1">` +
    `<div class="row g-2">` +
      `<div class="col-12 col-md-6">` +
        `<label class="form-label small text-muted mb-1" for="${id}">${pLabel}</label>` +
        primaryInput +
      `</div>` +
      `<div class="col-12 col-md-6">` +
        `<label class="form-label small text-muted mb-1" for="${confirmId}">${cLabel}</label>` +
        confirmInput +
        `<small class="pwtools-confirm-msg small text-danger d-block mt-1" style="min-height:1.2em"></small>` +
      `</div>` +
    `</div>` +
    (allowUserChoice
      ? `<label class="form-label small text-muted mt-2 mb-0" for="${id}_scheme">Hash-Schema</label>`
      : "") +
    schemeControl +
    meter +
    `</div>`
  );
}

// -----------------------------------------------------------------------------
// Plugin-Config Bridge fuer fieldviews (die selbst KEINE Config bekommen)
// -----------------------------------------------------------------------------

let pluginState = {};

// -----------------------------------------------------------------------------
// Fieldviews fuer bestehenden String-Typ
// -----------------------------------------------------------------------------

function fieldviewsFactory() {
  return {
    // Edit-View: Klartexteingabe mit Live-Staerke und Schema-Dropdown.
    // Anwenden auf ein String-Feld z.B. namens "password_plain".
    password_input: {
      type: "String",
      isEdit: true,
      description:
        "Passwort-Eingabefeld mit Staerke-Anzeige, optionalem Hash-Schema-Dropdown und optionaler Passwort-Bestaetigung.",
      // readFromFormRecord laeuft VOR dem DB-Write als Teil von
      // Field.validate(). Wir haben hier Zugriff auf den kompletten
      // Request-Body inkl. der Zusatzfelder __confirm und __scheme.
      //
      // Da Field.validate bei readval===null nur bei required=true einen
      // Fehler wirft, koennen wir Confirm-Mismatch oder Policy-Verletzungen
      // nicht ueber null-Rueckgabe blockieren. Wir geben deshalb einen
      // Marker-String zurueck (PWTOOLS_ERR_PREFIX + Nachricht). Dieser
      // String durchlaeuft den min_length-Check unbeschadet (Marker ist
      // laenger als jede sinnvolle min_length) und wird vom Validate-Trigger
      // als Fehler erkannt und via {error} zurueckgemeldet.
      readFromFormRecord: (rec, name) => {
        if (!rec) return null;
        const raw = rec[name];
        if (raw === undefined || raw === null || raw === "") return raw;
        const plain = String(raw);

        // Wenn wir hier bereits einen Sentinel sehen (z.B. bei erneutem
        // Form-POST derselben Session), unveraendert durchreichen. Der
        // Validate-Trigger packt ihn dann sauber aus.
        if (
          plain.startsWith(PWTOOLS_SCHEME_PREFIX) ||
          plain.startsWith(PWTOOLS_ERR_PREFIX)
        ) {
          return plain;
        }

        // Wenn bereits ein fertiger Hash uebergeben wird (z.B. Import),
        // unveraendert durchlassen (kein Confirm-Check, kein Schema-Sentinel).
        if (looksLikeHash(plain)) return plain;

        // Confirm pruefen, sofern uebermittelt. Wir akzeptieren den Wert
        // sowohl unter <name>__confirm als auch als plain confirm-Feld.
        const confirmKey = name + "__confirm";
        const confirmVal = rec[confirmKey];
        if (
          confirmVal !== undefined &&
          confirmVal !== null &&
          confirmVal !== "" &&
          String(confirmVal) !== plain
        ) {
          return (
            PWTOOLS_ERR_PREFIX +
            "Passwortbestaetigung stimmt nicht mit Passwort ueberein."
          );
        }

        // Policy pruefen (Server-Seite, unabhaengig vom Client).
        const policy = mergePolicy(pluginState, {});
        const check = evaluate(plain, policy);
        if (!check.valid) {
          return (
            PWTOOLS_ERR_PREFIX +
            "Passwort erfuellt die Policy nicht: " +
            check.problems.join("; ")
          );
        }

        // Schema-Wahl aus dem Formular durchreichen. Form.validate() verwirft
        // sonst alle Extra-Felder wie <name>__scheme, weil sie keine
        // Table-Fields sind. Wir kodieren die User-Wahl in den Rueckgabewert
        // und packen sie im Validate-Trigger wieder aus.
        const schemeKey = name + "__scheme";
        const chosenScheme = rec[schemeKey];
        if (
          typeof chosenScheme === "string" &&
          chosenScheme !== "" &&
          SCHEMES.includes(chosenScheme)
        ) {
          return PWTOOLS_SCHEME_PREFIX + chosenScheme + "|" + plain;
        }

        return plain;
      },
      configFields: [
        {
          name: "scheme",
          label: "Vorgabe Hash-Schema",
          type: "String",
          attributes: { options: ["", ...SCHEMES] },
          sublabel: "Leer = Wert aus Plugin-Config verwenden.",
        },
        {
          name: "allow_user_choice",
          label: "Benutzer darf Schema waehlen",
          type: "Bool",
        },
        {
          name: "min_length",
          label: "Min. Laenge (Override)",
          type: "Integer",
        },
        {
          name: "min_score",
          label: "Min. zxcvbn Score (Override)",
          type: "Integer",
        },
        {
          name: "require_confirm",
          label: "Passwort-Bestaetigung anzeigen",
          type: "Bool",
          default: true,
          sublabel:
            "Zeigt ein zweites Feld zur Bestaetigung. Submit wird blockiert, wenn beide Felder nicht uebereinstimmen.",
        },
        {
          name: "primary_label",
          label: "Beschriftung Passwortfeld",
          type: "String",
          sublabel: "Nur wirksam, wenn Bestaetigung aktiv ist. Default: Passwort",
        },
        {
          name: "confirm_label",
          label: "Beschriftung Bestaetigungsfeld",
          type: "String",
          sublabel: "Default: Passwort wiederholen",
        },
      ],
      run: (nm, v, attrs, cls) => {
        const a = attrs || {};
        const opts = mergeOpts(pluginState, a);
        const policy = mergePolicy(pluginState, a);
        const requireConfirm =
          typeof a.require_confirm === "boolean" ? a.require_confirm : true;
        return renderPlainEditor({
          name: nm,
          cls,
          schemes: SCHEMES,
          defaultScheme: opts.scheme,
          allowUserChoice: opts.allowUserChoice,
          policy,
          requireConfirm,
          primaryLabel: a.primary_label,
          confirmLabel: a.confirm_label,
        });
      },
    },
    // Show-View: maskierter Hash (fuer das Zielfeld "password_hash").
    password_hash_show: {
      type: "String",
      isEdit: false,
      description:
        "Zeigt einen Password-Hash maskiert (nur die ersten und letzten Zeichen).",
      run: (v) =>
        typeof v === "string" && v.length > 0
          ? span(
              { class: "font-monospace small text-muted", title: v },
              maskHash(v)
            )
          : "",
    },
  };
}

// -----------------------------------------------------------------------------
// Server-Funktionen (in Code-Actions und Formeln nutzbar)
// -----------------------------------------------------------------------------

function functionsFactory(config) {
  if (config && Object.keys(pluginState).length === 0) {
    pluginState = Object.assign({}, config);
  }
  return {
    pwtools_hash: {
      description:
        "Hasht ein Klartext-Passwort mit dem konfigurierten Schema (BLF-CRYPT / SHA512-CRYPT / PBKDF2 / CRAM-MD5).",
      arguments: [
        { name: "plain", type: "String" },
        { name: "options", type: "JSON" },
      ],
      run: async (plain, options) => {
        // pluginState reflects live plugin config (aktualisiert via onLoad),
        // waehrend `config` die Closure vom Registrierungszeitpunkt haelt.
        const opts = mergeOpts(pluginState, options || {});
        return await hashPassword(plain, opts);
      },
    },
    pwtools_verify: {
      description:
        "Prueft ein Klartext-Passwort gegen einen gespeicherten Hash.",
      arguments: [
        { name: "plain", type: "String" },
        { name: "stored", type: "String" },
      ],
      run: async (plain, stored) => await verifyPassword(plain, stored),
    },
    pwtools_strength: {
      description:
        "Berechnet die Passwortstaerke (zxcvbn + Regelpruefung).",
      arguments: [{ name: "plain", type: "String" }],
      run: (plain) => evaluate(plain, mergePolicy(pluginState, {})),
    },
  };
}

// -----------------------------------------------------------------------------
// Trigger-Action: hasht das Klartextfeld beim Insert/Update
// -----------------------------------------------------------------------------

function actionsFactory(config) {
  // Falls onLoad noch nicht gelaufen ist, mit Registrierungs-Config seed'en,
  // damit mergeOpts(pluginState, ...) nicht auf einem leeren Objekt landet.
  if (config && Object.keys(pluginState).length === 0) {
    pluginState = Object.assign({}, config);
  }
  return {
    hash_password_field: {
      description:
        "Liest ein Klartextfeld (Default: password_plain), hasht es und schreibt " +
        "das Ergebnis in ein Zielfeld (Default: password_hash). Danach wird das " +
        "Klartextfeld optional geleert.",
      configFields: ({ table }) => {
        const allFields = (table && table.fields) || [];
        const options = allFields
          .filter((f) => {
            const t = (f.type && (f.type.name || f.type)) || "";
            return t === "String";
          })
          .map((f) => f.name);
        return [
          {
            name: "plain_field",
            label: "Quellfeld (Klartext)",
            type: "String",
            required: true,
            default: "password_plain",
            attributes: { options: options.length ? options : ["password_plain"] },
          },
          {
            name: "hash_field",
            label: "Zielfeld (Hash)",
            type: "String",
            required: true,
            default: "password_hash",
            attributes: { options: options.length ? options : ["password_hash"] },
          },
          {
            name: "scheme",
            label: "Schema (leer = Auswahl im Formular / Default)",
            type: "String",
            attributes: { options: ["", ...SCHEMES] },
          },
          {
            name: "with_prefix",
            label: "Dovecot-Prefix {SCHEMA} voranstellen",
            type: "Bool",
            sublabel:
              "Leer = Wert aus Plugin-Config verwenden. Aktiv schreibt z.B. " +
              "{BLF-CRYPT}... in das Hash-Feld.",
          },
          {
            name: "enforce_policy",
            label: "Passwortpolicy erzwingen",
            type: "Bool",
            default: true,
          },
          {
            name: "clear_plain",
            label: "Klartextfeld nach Hashen leeren",
            type: "Bool",
            default: true,
          },
          {
            name: "allow_hash_import",
            label: "Vorberechnete Hashes importieren (nur vertrauenswürdiger Import)",
            type: "Bool",
            default: false,
          },
        ];
      },
      run: async ({ row, table, configuration, old_row, updated_fields }) => {
        const cfg = configuration || {};
        const plainField = cfg.plain_field || "password_plain";
        const hashField = cfg.hash_field || "password_hash";

        // Als Validate-Trigger enthaelt row die neuen Feldwerte (v_in);
        // als Insert/Update-Trigger enthaelt row die eingefuegte Zeile.
        let plain = row && row[plainField];

        // Bei Update-Trigger liefert Saltcorn updated_fields (=v_in) mit —
        // dort steht der rohe Sentinel evtl. drin, auch wenn row bereits
        // aus (existing + v) zusammengesetzt wurde. Wir bevorzugen den
        // rohen updated_fields-Wert, wenn er einen Sentinel/Err-Marker
        // enthaelt.
        if (
          updated_fields &&
          typeof updated_fields === "object" &&
          typeof updated_fields[plainField] === "string" &&
          (updated_fields[plainField].startsWith(PWTOOLS_SCHEME_PREFIX) ||
            updated_fields[plainField].startsWith(PWTOOLS_ERR_PREFIX))
        ) {
          plain = updated_fields[plainField];
        }

        // Zuerst: Fehler-Marker aus readFromFormRecord im Fieldview erkennen
        // (Confirm-Mismatch oder Policy-Fail).
        if (typeof plain === "string" && plain.startsWith(PWTOOLS_ERR_PREFIX)) {
          return { error: plain.slice(PWTOOLS_ERR_PREFIX.length) };
        }

        // Schema-Sentinel auspacken. Das Fieldview kodiert die User-Wahl aus
        // dem <name>__scheme-Dropdown hier hinein, weil Saltcorn Extra-
        // Formfelder sonst aus v_in wegwirft (siehe PWTOOLS_SCHEME_PREFIX).
        let userChosenScheme = null;
        if (typeof plain === "string") {
          const unwrapped = extractSchemeSentinel(plain);
          if (unwrapped.scheme) {
            userChosenScheme = unwrapped.scheme;
            plain = unwrapped.plain;
            // row auf den Klartext zurueckbiegen, damit spaetere
            // set_fields-Merges nicht den Sentinel weiterreichen.
            if (row && typeof row === "object") row[plainField] = plain;
          }
        }

        // Zweiter Fallback: wenn immer noch kein Sentinel gefunden wurde,
        // aber updated_fields[plainField] einen Sentinel enthaelt (siehe
        // oben), duerfte der schon oben gegriffen haben — hier extra
        // defensiv gegen ein moegliches Sentinel im row[plainField+"__sentinel"]
        // Case (frueher Zwischenstand).
        if (!userChosenScheme && row && typeof row === "object") {
          const rawSentinel = row[`${plainField}__sentinel`];
          if (
            typeof rawSentinel === "string" &&
            rawSentinel.startsWith(PWTOOLS_SCHEME_PREFIX)
          ) {
            const unwrapped = extractSchemeSentinel(rawSentinel);
            if (unwrapped.scheme) {
              userChosenScheme = unwrapped.scheme;
              delete row[`${plainField}__sentinel`];
            }
          }
        }

        if (!plain || typeof plain !== "string") {
          return { notice: "Kein Klartextpasswort - uebersprungen." };
        }

        // Serverseitige Bestaetigungspruefung (Fallback, falls das
        // Fieldview nicht 'password_input' ist und __confirm dennoch
        // durchkommt).
        const confirmVal = row[`${plainField}__confirm`];
        if (
          confirmVal !== undefined &&
          confirmVal !== null &&
          confirmVal !== "" &&
          String(confirmVal) !== plain
        ) {
          return {
            error:
              "Passwortbestaetigung stimmt nicht mit Passwort ueberein.",
          };
        }

        // Prioritaet der Schema-Wahl:
        //   1. User-Auswahl im Formular-Dropdown (via Sentinel im
        //      readFromFormRecord-Rueckgabewert). Gewinnt immer, weil der
        //      User im Formular aktiv gewaehlt hat.
        //   2. Direktes row[__scheme]-Extra-Feld — greift, wenn das
        //      Fieldview den Sentinel nicht durchlaufen hat (z.B.
        //      Legacy-Views ohne readFromFormRecord, oder Trigger, die
        //      row inkl. Extra-Feld reingereicht bekommen).
        //   3. Auch updated_fields[__scheme] pruefen (Update-Trigger-Pfad).
        //   4. Trigger-Config (Fixierung pro Trigger, cfg.scheme).
        //   5. Plugin-Default-Schema (nur Vorbelegung, kein Zwang).
        //   6. Hard fallback BLF-CRYPT.
        const rowSchemeExtra =
          (row && row[`${plainField}__scheme`]) ||
          (updated_fields && updated_fields[`${plainField}__scheme`]) ||
          null;
        const allowChoice = pluginState.allow_user_choice !== false;
        const scheme =
          (allowChoice && userChosenScheme && SCHEMES.includes(userChosenScheme) ? userChosenScheme : null) ||
          (allowChoice && rowSchemeExtra &&
          SCHEMES.includes(rowSchemeExtra)
            ? rowSchemeExtra
            : null) ||
          cfg.scheme ||
          (pluginState && pluginState.default_scheme) ||
          "BLF-CRYPT";

        // Extra-Formfelder aus row entfernen, damit sie nie in eine
        // DB-Insert/Update-Anfrage geraten. Object.assign mit
        // {key: undefined} wuerde die Property NICHT loeschen, sondern
        // den Wert auf undefined setzen — der pg-Client sendet die Spalte
        // dann trotzdem und die DB antwortet mit
        // "column \"...__confirm\" of relation ... does not exist".
        if (row && typeof row === "object") {
          delete row[`${plainField}__confirm`];
          delete row[`${plainField}__scheme`];
        }

        // Fall 1: es ist schon ein Hash - unveraendert speichern.
        if (looksLikeHash(plain)) {
          if (cfg.allow_hash_import !== true) {
            return { error: "Vorberechnete Hashes sind in diesem Passwortformular nicht zugelassen." };
          }
          // Bei Validate-Trigger: set_fields wird von Table.insertRow/updateRow
          // in v_in gemergt und blockt den DB-Write nicht.
          const setFields = { [hashField]: plain };
          if (cfg.clear_plain !== false) setFields[plainField] = "";

          // Insert/Update-Trigger: nachtraeglich schreiben.
          if (
            table &&
            typeof table.updateRow === "function" &&
            row.id
          ) {
            const upd = { [hashField]: plain };
            if (cfg.clear_plain !== false) upd[plainField] = "";
            await table.updateRow(upd, row.id);
          }
          return { notice: "Bestehender Hash uebernommen.", set_fields: setFields };
        }

        // Fall 2: Policy pruefen (Server-Fallback fuer den Fall, dass das
        // Fieldview readFromFormRecord nicht ausgefuehrt wurde).
        // pluginState statt config: reflektiert live-Config-Updates.
        const policy = mergePolicy(pluginState, {});
        const check = evaluate(plain, policy);
        if (cfg.enforce_policy !== false && !check.valid) {
          return {
            error:
              "Passwort erfuellt die Policy nicht: " +
              check.problems.join("; "),
          };
        }

        // Fall 3: Hashen.
        // pluginState statt config, damit Aenderungen an Default-Schema oder
        // Prefix-Toggle im Modules-Config sofort greifen. Trigger-Attrs
        // (scheme, with_prefix) haben Vorrang.
        const triggerAttrs = { scheme };
        if (typeof cfg.with_prefix === "boolean") {
          triggerAttrs.with_prefix = cfg.with_prefix;
        }
        const opts = mergeOpts(pluginState, triggerAttrs);
        const hashed = await hashPassword(plain, opts);

        const setFields = { [hashField]: hashed };
        if (cfg.clear_plain !== false) setFields[plainField] = "";

        // Insert/Update-Trigger: nachtraeglich schreiben.
        if (table && typeof table.updateRow === "function" && row.id) {
          const upd = { [hashField]: hashed };
          if (cfg.clear_plain !== false) upd[plainField] = "";
          await table.updateRow(upd, row.id);
        }

        // Als Validate-Trigger: set_fields wird von Saltcorn in v_in gemergt,
        // sodass beim Insert direkt der Hash landet, nicht das Klartextpasswort.
        return {
          notice: `Passwort als ${scheme} gespeichert.`,
          set_fields: setFields,
        };
      },
    },
  };
}

// -----------------------------------------------------------------------------
// Optionaler HTTP-Endpoint
// -----------------------------------------------------------------------------

function routesFactory(config) {
  if (config && Object.keys(pluginState).length === 0) {
    pluginState = Object.assign({}, config);
  }
  return [
    {
      url: "/pwtools/strength",
      method: "post",
      callback: async (req, res) => {
        try {
          res.set("Cache-Control", "no-store");
          if (!req.user || !req.user.id || req.user.role_id === 100)
            return res.status(401).json({ error: "Anmeldung erforderlich." });
          const body = req.body || {};
          if (typeof body.password !== "string" || body.password.length > 256)
            return res.status(400).json({ error: "Passwort muss eine Zeichenkette mit höchstens 256 Zeichen sein." });
          const merged = mergePolicy(pluginState, body.policy || {});
          const result = evaluate(body.password || "", merged);
          res.json(result);
        } catch (e) {
          res.status(400).json({ error: String(e && e.message) });
        }
      },
    },
  ];
}

// -----------------------------------------------------------------------------
// Module-Export
// -----------------------------------------------------------------------------

module.exports = {
  sc_plugin_api_version: 1,
  plugin_name: PLUGIN_NAME,
  ready_for_mobile: false,

  configuration_workflow,

  // Fieldviews fuer den bestehenden String-Typ
  fieldviews: fieldviewsFactory,

  // Actions/Functions/Routes bekommen die Config an der Factory-Signatur
  actions: actionsFactory,
  functions: functionsFactory,
  routes: routesFactory,

  headers: () => [
    {
      script:
        `/plugins/public/${PLUGIN_NAME}/zxcvbn.js`,
    },
    {
      script: `/plugins/public/${PLUGIN_NAME}/strength-client.js`,
    },
  ],

  // Wird beim Laden und nach Konfigurationsaenderungen aufgerufen und stellt
  // die Plugin-Config den (config-losen) fieldviews via Modul-Slot bereit.
  onLoad: async (config) => {
    // Wichtig: pluginState wird von allen Trigger-Actions, Functions und
    // Fieldviews live gelesen (mergeOpts/mergePolicy) - dadurch reagiert das
    // Plugin auf Konfigurationsaenderungen im Modules-Panel ohne Neustart.
    pluginState = config || {};
  },
};

// Named exports fuer direkte Nutzung / Tests
module.exports.hashPassword = hashPassword;
module.exports.verifyPassword = verifyPassword;
module.exports.evaluate = evaluate;
