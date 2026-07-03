/**
 * saltcorn-password-tools
 *
 * Ein Saltcorn-Plugin, das Passwoerter im Klartext entgegennimmt und beim
 * Speichern automatisch in einen konfigurierbaren Hash umwandelt.
 *
 * Unterstuetzte Schemata (Dovecot-kompatibel):
 *   - BLF-CRYPT      (bcrypt, Prefix z. B. $2y$)
 *   - SHA512-CRYPT   ($6$...)
 *   - PBKDF2         Dovecot-Format: $1$SALT$ROUNDS$HASH_HEX
 *
 * Nutzung:
 *   1. In der Ziel-Tabelle zwei Felder anlegen:
 *        - password_plain  (Typ String)                 -> Formular-Eingabe
 *        - password_hash   (Typ "Password Hash")        -> gespeicherter Hash
 *   2. In Views/Editor fuer das Zielfeld die Field-View
 *      "hash_from_plain" verwenden.
 *   3. Alternativ: Feld password_plain als Typ "Password Plain" markieren -
 *      die Field-View "with_strength" zeigt Live-Staerke-Anzeige plus Auswahl.
 *
 * Die Plugin-Config liefert Defaults (Standard-Schema, Prefix-Verhalten,
 * Rundenzahlen, Passwortpolicy).
 */

"use strict";

const path = require("path");

// Diese Imports werden erst zur Laufzeit im Saltcorn-Prozess aufgeloest.
// Beim isolierten Test/npm-install stehen sie ggf. nicht zur Verfuegung.
const Workflow = require("@saltcorn/data/models/workflow");
const Form = require("@saltcorn/data/models/form");
const { input, span, select, option } = require("@saltcorn/markup/tags");

const { SCHEMES, hashPassword, verifyPassword } = require("./lib/hashes");
const { evaluate } = require("./lib/strength");

// -----------------------------------------------------------------------------
// Configuration Workflow (Plugin-Ebene)
// -----------------------------------------------------------------------------

const configuration_workflow = () =>
  new Workflow({
    steps: [
      {
        name: "Standard-Einstellungen",
        form: async () =>
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
                  "Wird verwendet, wenn im Feld/Formular keine explizite Auswahl getroffen wird.",
              },
              {
                name: "allow_user_choice",
                label: "Benutzer darf Schema im Formular waehlen",
                type: "Bool",
                default: true,
                sublabel:
                  "Wenn deaktiviert, wird immer das Standard-Schema verwendet.",
              },
              {
                name: "with_prefix",
                label: 'Dovecot-Prefix "{SCHEME}" voranstellen',
                type: "Bool",
                default: true,
                sublabel:
                  "Speichert z. B. {BLF-CRYPT}$2y$... statt nur $2y$...",
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
                sublabel:
                  "Dovecot erwartet $2y$; fuer maximale Kompatibilitaet Standard belassen.",
              },
              {
                name: "sha512_rounds",
                label: "SHA512-CRYPT: Rounds",
                type: "Integer",
                default: 5000,
                attributes: { min: 1000, max: 999999999 },
              },
              {
                name: "pbkdf2_iterations",
                label: "PBKDF2: Iterationen",
                type: "Integer",
                default: 25000,
                attributes: { min: 1000, max: 10000000 },
              },
              // Passwortpolicy
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
                sublabel:
                  "0 = beliebig, 4 = sehr stark. Empfehlung: 3. Wird nur ausgewertet, wenn zxcvbn verfuegbar ist.",
              },
            ],
          }),
      },
    ],
  });

// -----------------------------------------------------------------------------
// Hilfsfunktionen zum Zusammenfuehren von Config + Feld-Attributen
// -----------------------------------------------------------------------------

/** Merge Plugin-Config mit Feld-spezifischen Attributen (Feld gewinnt). */
function mergeOpts(pluginCfg = {}, attrs = {}) {
  return {
    scheme:
      attrs.scheme || attrs.default_scheme || pluginCfg.default_scheme || "BLF-CRYPT",
    withPrefix:
      typeof attrs.with_prefix === "boolean"
        ? attrs.with_prefix
        : typeof pluginCfg.with_prefix === "boolean"
        ? pluginCfg.with_prefix
        : true,
    bcryptRounds: attrs.bcrypt_rounds || pluginCfg.bcrypt_rounds || 12,
    bcryptPrefix: attrs.bcrypt_prefix || pluginCfg.bcrypt_prefix || "2y",
    sha512Rounds: attrs.sha512_rounds || pluginCfg.sha512_rounds || 5000,
    pbkdf2Iterations:
      attrs.pbkdf2_iterations || pluginCfg.pbkdf2_iterations || 25000,
    pbkdf2KeyLen: 64,
    pbkdf2Digest: "sha512",
    allowUserChoice:
      typeof attrs.allow_user_choice === "boolean"
        ? attrs.allow_user_choice
        : typeof pluginCfg.allow_user_choice === "boolean"
        ? pluginCfg.allow_user_choice
        : true,
  };
}

function mergePolicy(pluginCfg = {}, attrs = {}) {
  return {
    minLength: attrs.min_length ?? pluginCfg.min_length ?? 10,
    requireUpper: attrs.require_upper ?? pluginCfg.require_upper ?? true,
    requireLower: attrs.require_lower ?? pluginCfg.require_lower ?? true,
    requireDigit: attrs.require_digit ?? pluginCfg.require_digit ?? true,
    requireSymbol: attrs.require_symbol ?? pluginCfg.require_symbol ?? false,
    minScore: attrs.min_score ?? pluginCfg.min_score ?? 3,
  };
}

// -----------------------------------------------------------------------------
// Field-View: HTML-Renderer
// -----------------------------------------------------------------------------

/**
 * Rendert den Eingabe-Block:
 *   - password input
 *   - optionales Schema-Dropdown
 *   - Staerke-Balken + Feedback (client-seitig via /plugins/public/... /strength.js)
 */
function renderPlainEditor({
  name,
  value,
  cls,
  schemes,
  defaultScheme,
  allowUserChoice,
  policyJson,
}) {
  const id = `sc_pwd_${name}`;
  const dropdown = allowUserChoice
    ? select(
        {
          name: `${name}__scheme`,
          id: `${id}_scheme`,
          class: "form-select form-select-sm mt-1",
          "data-pwtools-scheme": "1",
        },
        schemes.map((s) =>
          option({ value: s, ...(s === defaultScheme ? { selected: true } : {}) }, s)
        )
      )
    : input({ type: "hidden", name: `${name}__scheme`, value: defaultScheme });

  const meter =
    `<div class="pwtools-strength mt-2" data-pwtools-meter-for="${id}">` +
    `<div class="progress" style="height:6px"><div class="progress-bar" role="progressbar" style="width:0%"></div></div>` +
    `<small class="pwtools-strength-label text-muted d-block mt-1">Bitte Passwort eingeben</small>` +
    `<ul class="pwtools-strength-feedback small text-danger mb-0 mt-1"></ul>` +
    `</div>`;

  return (
    `<div class="pwtools-wrapper" data-pwtools-policy='${escapeJson(policyJson)}'>` +
    input({
      type: "password",
      class: `form-control ${cls || ""}`,
      name,
      id,
      autocomplete: "new-password",
      "data-pwtools-input": "1",
      ...(value ? { value } : {}),
    }) +
    (allowUserChoice
      ? `<label class="form-label small text-muted mt-1 mb-0" for="${id}_scheme">Hash-Schema</label>`
      : "") +
    dropdown +
    meter +
    `</div>`
  );
}

function escapeJson(obj) {
  return JSON.stringify(obj).replace(/'/g, "&#39;");
}

// -----------------------------------------------------------------------------
// Type-Definitionen
// -----------------------------------------------------------------------------

/**
 * "Password Plain" - virtueller String-Typ fuer das Eingabefeld.
 * Wird NICHT im Klartext gespeichert (leere Ausgabe beim show), sondern
 * ist der Ort, an dem eine Live-Staerke-Anzeige gezeigt wird.
 */
const passwordPlainType = (pluginCfg) => ({
  name: "Password Plain",
  sql_name: "text",
  fieldviews: {
    with_strength: {
      isEdit: true,
      run: (nm, v, attrs = {}, cls) => {
        const opts = mergeOpts(pluginCfg, attrs);
        const policy = mergePolicy(pluginCfg, attrs);
        return renderPlainEditor({
          name: nm,
          value: "", // Klartext nie zurueckspielen
          cls,
          schemes: SCHEMES,
          defaultScheme: opts.scheme,
          allowUserChoice: opts.allowUserChoice,
          policyJson: policy,
        });
      },
    },
    show: {
      isEdit: false,
      run: () => "••••••••",
    },
    edit: {
      // Alias fuer with_strength, damit Saltcorn's Default-Edit-View funktioniert
      isEdit: true,
      run: (nm, v, attrs = {}, cls) => {
        const opts = mergeOpts(pluginCfg, attrs);
        const policy = mergePolicy(pluginCfg, attrs);
        return renderPlainEditor({
          name: nm,
          value: "",
          cls,
          schemes: SCHEMES,
          defaultScheme: opts.scheme,
          allowUserChoice: opts.allowUserChoice,
          policyJson: policy,
        });
      },
    },
  },
  read: (v) => (typeof v === "string" ? v : v == null ? undefined : String(v)),
  attributes: [
    {
      name: "scheme",
      label: "Hash-Schema (Override)",
      type: "String",
      required: false,
      attributes: { options: ["", ...SCHEMES] },
      sublabel:
        "Optionaler Override des Standard-Schemas aus der Plugin-Config.",
    },
    {
      name: "with_prefix",
      label: 'Dovecot-Prefix "{SCHEME}" voranstellen (Override)',
      type: "Bool",
    },
    {
      name: "allow_user_choice",
      label: "Benutzer darf Schema waehlen (Override)",
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
  ],
});

/**
 * "Password Hash" - das eigentliche Zielfeld. Speichert einen String
 * und rendert eine Editieransicht identisch zu Password Plain, damit
 * man das Ziel-Feld direkt in Edit-Views einsetzen kann und der Wert
 * beim Absenden automatisch gehasht wird.
 */
const passwordHashType = (pluginCfg) => ({
  name: "Password Hash",
  sql_name: "text",
  fieldviews: {
    // Zeigt den gespeicherten Hash maskiert an
    show: {
      isEdit: false,
      run: (s) =>
        typeof s === "string" && s.length > 0
          ? span(
              { class: "font-monospace small text-muted", title: s },
              maskHash(s)
            )
          : "",
    },
    // Zeigt den vollen Hash (fuer Admin-Debug)
    show_raw: {
      isEdit: false,
      run: (s) =>
        typeof s === "string"
          ? span({ class: "font-monospace small" }, s)
          : "",
    },
    // Kern-Field-View: Klartext-Eingabe -> wird beim submit automatisch gehasht
    hash_from_plain: {
      isEdit: true,
      run: (nm, v, attrs = {}, cls) => {
        const opts = mergeOpts(pluginCfg, attrs);
        const policy = mergePolicy(pluginCfg, attrs);
        return renderPlainEditor({
          name: nm,
          value: "",
          cls,
          schemes: SCHEMES,
          defaultScheme: opts.scheme,
          allowUserChoice: opts.allowUserChoice,
          policyJson: policy,
        });
      },
    },
    // Roh-Edit fuer den Fall, dass ein Admin einen fertigen Hash einfuegt
    edit_raw: {
      isEdit: true,
      run: (nm, v, attrs, cls) =>
        input({
          type: "text",
          class: `form-control font-monospace ${cls || ""}`,
          name: nm,
          ...(v ? { value: v } : {}),
        }),
    },
  },
  read: (v) => (typeof v === "string" ? v : v == null ? undefined : String(v)),
  attributes: [
    {
      name: "scheme",
      label: "Hash-Schema (Override)",
      type: "String",
      required: false,
      attributes: { options: ["", ...SCHEMES] },
    },
    {
      name: "with_prefix",
      label: 'Dovecot-Prefix "{SCHEME}" voranstellen (Override)',
      type: "Bool",
    },
    {
      name: "allow_user_choice",
      label: "Benutzer darf Schema waehlen (Override)",
      type: "Bool",
    },
    {
      name: "bcrypt_rounds",
      label: "BLF-CRYPT Rounds (Override)",
      type: "Integer",
    },
    {
      name: "sha512_rounds",
      label: "SHA512-CRYPT Rounds (Override)",
      type: "Integer",
    },
    {
      name: "pbkdf2_iterations",
      label: "PBKDF2 Iterations (Override)",
      type: "Integer",
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
  ],
  /**
   * Wichtig: das Feld wird per Form eingelesen. Wenn der Wert bereits wie
   * ein Hash aussieht, uebernehmen wir ihn unveraendert; andernfalls wird
   * er in der Trigger-Action / im Save-Hook (siehe README) gehasht.
   * Ein synchrones read() reicht hier nicht fuer Async-Hashing - daher
   * empfehlen wir die Action `hash_password_field` als "Update" Trigger.
   */
});

function maskHash(s) {
  if (s.length <= 12) return "••••";
  return s.slice(0, 6) + "…" + s.slice(-4);
}

// -----------------------------------------------------------------------------
// Server-Funktionen (aus Code-Triggern nutzbar)
// -----------------------------------------------------------------------------

function makeFunctions(pluginCfg) {
  return {
    /**
     * pwtools_hash(plain, {scheme?, with_prefix?, ...})
     * Rueckgabe: String (Hash).
     */
    pwtools_hash: {
      description:
        "Hasht ein Klartext-Passwort mit dem konfigurierten Schema (BLF-CRYPT / SHA512-CRYPT / PBKDF2).",
      arguments: [
        { name: "plain", type: "String" },
        { name: "options", type: "JSON" },
      ],
      run: async (plain, options) => {
        const opts = mergeOpts(pluginCfg, options || {});
        return await hashPassword(plain, opts);
      },
    },
    /**
     * pwtools_verify(plain, stored) -> Bool
     */
    pwtools_verify: {
      description: "Prueft ein Klartext-Passwort gegen einen gespeicherten Hash.",
      arguments: [
        { name: "plain", type: "String" },
        { name: "stored", type: "String" },
      ],
      run: async (plain, stored) => await verifyPassword(plain, stored),
    },
    /**
     * pwtools_strength(plain) -> {valid, score, problems, suggestions}
     */
    pwtools_strength: {
      description: "Berechnet die Passwortstaerke (zxcvbn + Regelpruefung).",
      arguments: [{ name: "plain", type: "String" }],
      run: (plain) => evaluate(plain, mergePolicy(pluginCfg, {})),
    },
  };
}

// -----------------------------------------------------------------------------
// Action-Trigger: bequem als "Update" oder "InsertRow" Trigger einsetzbar
// -----------------------------------------------------------------------------

function makeActions(pluginCfg) {
  return {
    hash_password_field: {
      description:
        "Liest ein Klartext-Feld (Default: password_plain), hasht es und schreibt " +
        "das Ergebnis in ein Zielfeld (Default: password_hash). Danach wird das " +
        "Klartext-Feld geleert.",
      configFields: async ({ table }) => {
        const stringFields = (table?.fields || [])
          .filter((f) => f.type && (f.type.name === "String" || f.type === "String" || f.type.name === "Password Plain"))
          .map((f) => f.name);
        const hashFields = (table?.fields || [])
          .filter(
            (f) =>
              f.type &&
              (f.type.name === "String" ||
                f.type === "String" ||
                f.type.name === "Password Hash")
          )
          .map((f) => f.name);
        return [
          {
            name: "plain_field",
            label: "Quellfeld (Klartext)",
            type: "String",
            required: true,
            default: "password_plain",
            attributes: { options: stringFields.length ? stringFields : ["password_plain"] },
          },
          {
            name: "hash_field",
            label: "Zielfeld (Hash)",
            type: "String",
            required: true,
            default: "password_hash",
            attributes: { options: hashFields.length ? hashFields : ["password_hash"] },
          },
          {
            name: "scheme",
            label: "Schema (leer = aus Formular / Default)",
            type: "String",
            attributes: { options: ["", ...SCHEMES] },
          },
          {
            name: "enforce_policy",
            label: "Passwortpolicy erzwingen (Abbruch bei Verstoss)",
            type: "Bool",
            default: true,
          },
          {
            name: "clear_plain",
            label: "Klartextfeld nach Hashen leeren",
            type: "Bool",
            default: true,
          },
        ];
      },
      run: async ({ row, table, configuration = {} }) => {
        const plainField = configuration.plain_field || "password_plain";
        const hashField = configuration.hash_field || "password_hash";
        const plain = row?.[plainField];

        if (!plain || typeof plain !== "string") {
          return { success: true, notice: "Kein Klartextpasswort - uebersprungen." };
        }

        const scheme =
          configuration.scheme ||
          row?.[`${plainField}__scheme`] ||
          pluginCfg.default_scheme ||
          "BLF-CRYPT";

        // Wenn bereits ein gueltiger Hash im Klartextfeld steckt: unveraendert speichern.
        if (looksLikeHash(plain)) {
          const update = { [hashField]: plain };
          if (configuration.clear_plain !== false) update[plainField] = "";
          if (table?.updateRow) await table.updateRow(update, row.id);
          return { success: true };
        }

        const policy = mergePolicy(pluginCfg, {});
        const check = evaluate(plain, policy);
        if (configuration.enforce_policy !== false && !check.valid) {
          return {
            error:
              "Passwort erfuellt die Policy nicht: " +
              check.problems.join("; "),
          };
        }

        const opts = mergeOpts(pluginCfg, { scheme });
        const hashed = await hashPassword(plain, opts);

        const update = { [hashField]: hashed };
        if (configuration.clear_plain !== false) update[plainField] = "";
        if (table?.updateRow) await table.updateRow(update, row.id);

        return { success: true, notice: `Passwort als ${scheme} gespeichert.` };
      },
    },
  };
}

function looksLikeHash(s) {
  return (
    /^\{[A-Z0-9-]+\}/.test(s) ||
    /^\$2[aby]\$/.test(s) ||
    /^\$6\$/.test(s) ||
    /^\$1\$[^$]+\$\d+\$[0-9a-f]+$/i.test(s)
  );
}

// -----------------------------------------------------------------------------
// Routes: eine kleine JSON-API fuer Live-Staerke (nutzt zxcvbn serverseitig)
// -----------------------------------------------------------------------------

function makeRoutes(pluginCfg) {
  return [
    {
      url: "/pwtools/strength",
      method: "post",
      callback: async ({ req, res }) => {
        try {
          const { password, policy } = req.body || {};
          const merged = mergePolicy(pluginCfg, policy || {});
          const result = evaluate(password || "", merged);
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

module.exports = (pluginCfg = {}) => ({
  sc_plugin_api_version: 1,
  plugin_name: "saltcorn-password-tools",
  configuration_workflow,
  types: [passwordPlainType(pluginCfg), passwordHashType(pluginCfg)],
  functions: makeFunctions(pluginCfg),
  actions: makeActions(pluginCfg),
  routes: makeRoutes(pluginCfg),
  // Header: laedt zxcvbn (CDN) + unser client-seitiges Skript
  headers: [
    {
      script:
        "https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js",
    },
    {
      script: "/plugins/public/saltcorn-password-tools/strength-client.js",
    },
  ],
  // Statisch ausgelieferte Dateien (public/*)
  serve_dependencies: {
    "/plugins/public/saltcorn-password-tools": path.join(__dirname, "public"),
  },
});

