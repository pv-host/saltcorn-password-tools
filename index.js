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
                attributes: { min: 1000, max: 999999999 },
              },
              {
                name: "pbkdf2_iterations",
                label: "PBKDF2: Iterationen",
                type: "Integer",
                default: 25000,
                attributes: { min: 1000, max: 10000000 },
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
  if (s.length <= 12) return "••••";
  return s.slice(0, 6) + "…" + s.slice(-4);
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
      `<div class="pwtools-wrapper" data-pwtools-policy='${escapeAttrJson(policy)}' data-pwtools-confirm="0">` +
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
    `<div class="pwtools-wrapper" data-pwtools-policy='${escapeAttrJson(policy)}' data-pwtools-confirm="1">` +
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
  return {
    pwtools_hash: {
      description:
        "Hasht ein Klartext-Passwort mit dem konfigurierten Schema (BLF-CRYPT / SHA512-CRYPT / PBKDF2).",
      arguments: [
        { name: "plain", type: "String" },
        { name: "options", type: "JSON" },
      ],
      run: async (plain, options) => {
        const opts = mergeOpts(config, options || {});
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
      run: (plain) => evaluate(plain, mergePolicy(config, {})),
    },
  };
}

// -----------------------------------------------------------------------------
// Trigger-Action: hasht das Klartextfeld beim Insert/Update
// -----------------------------------------------------------------------------

function actionsFactory(config) {
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
        ];
      },
      run: async ({ row, table, configuration }) => {
        const cfg = configuration || {};
        const plainField = cfg.plain_field || "password_plain";
        const hashField = cfg.hash_field || "password_hash";
        const plain = row && row[plainField];

        if (!plain || typeof plain !== "string") {
          return { notice: "Kein Klartextpasswort - uebersprungen." };
        }

        // Serverseitige Bestaetigungspruefung: wenn ein Confirm-Feld mitgeschickt
        // wurde und nicht uebereinstimmt, Abbruch (fangt Faelle ab, in denen die
        // clientseitige Pruefung umgangen wurde).
        const confirmVal = row && row[`${plainField}__confirm`];
        if (
          confirmVal !== undefined &&
          confirmVal !== null &&
          confirmVal !== "" &&
          confirmVal !== plain
        ) {
          return {
            error:
              "Passwortbestaetigung stimmt nicht mit Passwort ueberein.",
          };
        }

        const scheme =
          cfg.scheme ||
          (row && row[`${plainField}__scheme`]) ||
          (config && config.default_scheme) ||
          "BLF-CRYPT";

        if (looksLikeHash(plain)) {
          const update = { [hashField]: plain };
          if (cfg.clear_plain !== false) update[plainField] = "";
          // Confirm-Feld nie persistieren
          update[`${plainField}__confirm`] = undefined;
          if (
            table &&
            typeof table.updateRow === "function" &&
            row &&
            row.id
          ) {
            await table.updateRow(update, row.id);
          }
          return { notice: "Bestehender Hash uebernommen." };
        }

        const policy = mergePolicy(config, {});
        const check = evaluate(plain, policy);
        if (cfg.enforce_policy !== false && !check.valid) {
          return {
            error:
              "Passwort erfuellt die Policy nicht: " +
              check.problems.join("; "),
          };
        }

        const opts = mergeOpts(config, { scheme });
        const hashed = await hashPassword(plain, opts);

        const update = { [hashField]: hashed };
        if (cfg.clear_plain !== false) update[plainField] = "";
        if (table && typeof table.updateRow === "function" && row && row.id) {
          await table.updateRow(update, row.id);
        }
        return { notice: `Passwort als ${scheme} gespeichert.` };

      },
    },
  };
}

// -----------------------------------------------------------------------------
// Optionaler HTTP-Endpoint
// -----------------------------------------------------------------------------

function routesFactory(config) {
  return [
    {
      url: "/pwtools/strength",
      method: "post",
      callback: async (req, res) => {
        try {
          const body = req.body || {};
          const merged = mergePolicy(config, body.policy || {});
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
        "https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js",
    },
    {
      script: `/plugins/public/${PLUGIN_NAME}/strength-client.js`,
    },
  ],

  // Wird beim Laden und nach Konfigurationsaenderungen aufgerufen und stellt
  // die Plugin-Config den (config-losen) fieldviews via Modul-Slot bereit.
  onLoad: async (config) => {
    pluginState = config || {};
  },
};

// Named exports fuer direkte Nutzung / Tests
module.exports.hashPassword = hashPassword;
module.exports.verifyPassword = verifyPassword;
module.exports.evaluate = evaluate;
