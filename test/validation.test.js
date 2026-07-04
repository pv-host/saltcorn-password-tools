/**
 * Integrationstests fuer v0.3.1:
 * - readFromFormRecord im Fieldview 'password_input'
 * - Trigger-Fehlerpfade (Confirm-Mismatch, Policy-Fail, Hash-Passthrough)
 */

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const Module = require("node:module");

// Saltcorn-Stubs in NODE_PATH einbinden, damit require("@saltcorn/*") funktioniert.
const STUB_PATH = path.resolve(__dirname, "..", "..", "..", "tmp", "sc-stubs");
// Fallback fuer lokale Entwicklung: absoluter Pfad zu /tmp/sc-stubs
const stubs =
  process.env.SC_STUBS ||
  "/tmp/sc-stubs" ||
  path.resolve(__dirname, "..", "sc-stubs");
process.env.NODE_PATH = stubs + path.delimiter + (process.env.NODE_PATH || "");
Module._initPaths();

const plugin = require("..");

// Plugin-Config laden lassen (onLoad ist async, wird hier synchron aufgerufen).
async function withPluginConfig(cfg, fn) {
  await plugin.onLoad(cfg);
  try {
    return await fn();
  } finally {
    await plugin.onLoad({});
  }
}

function getFieldview() {
  const fvs = plugin.fieldviews();
  return fvs.password_input;
}

function getTrigger() {
  const acts = plugin.actions({
    default_scheme: "BLF-CRYPT",
    min_length: 10,
    require_upper: true,
    require_lower: true,
    require_digit: true,
    require_symbol: false,
    min_score: 0, // Score-Check in Tests deaktivieren
  });
  return acts.hash_password_field;
}

test("readFromFormRecord: leerer Wert wird durchgereicht", async () => {
  await withPluginConfig({}, () => {
    const fv = getFieldview();
    const rec = { password_plain: "" };
    const result = fv.readFromFormRecord(rec, "password_plain");
    assert.equal(result, "");
  });
});

test("readFromFormRecord: gueltiges Passwort + passender Confirm -> gibt Passwort zurueck", async () => {
  await withPluginConfig(
    {
      min_length: 8,
      require_upper: true,
      require_lower: true,
      require_digit: true,
      require_symbol: false,
      min_score: 0,
    },
    () => {
      const fv = getFieldview();
      const rec = {
        password_plain: "Passwort99",
        password_plain__confirm: "Passwort99",
      };
      const result = fv.readFromFormRecord(rec, "password_plain");
      assert.equal(result, "Passwort99");
      assert.equal(rec.__pwtools_error__password_plain, undefined);
    }
  );
});

test("readFromFormRecord: Confirm-Mismatch -> null + Fehlerkontext im rec", async () => {
  await withPluginConfig(
    {
      min_length: 8,
      require_upper: true,
      require_lower: true,
      require_digit: true,
      require_symbol: false,
      min_score: 0,
    },
    () => {
      const fv = getFieldview();
      const rec = {
        password_plain: "Passwort99",
        password_plain__confirm: "Passwort00",
      };
      const result = fv.readFromFormRecord(rec, "password_plain");
      assert.equal(result, null);
      assert.match(
        rec.__pwtools_error__password_plain,
        /Passwortbestaetigung stimmt nicht/
      );
    }
  );
});

test("readFromFormRecord: Policy-Fail (zu kurz) -> null + Fehlerkontext", async () => {
  await withPluginConfig(
    {
      min_length: 12,
      require_upper: true,
      require_lower: true,
      require_digit: true,
      require_symbol: false,
      min_score: 0,
    },
    () => {
      const fv = getFieldview();
      const rec = {
        password_plain: "Pass1",
        password_plain__confirm: "Pass1",
      };
      const result = fv.readFromFormRecord(rec, "password_plain");
      assert.equal(result, null);
      assert.match(
        rec.__pwtools_error__password_plain,
        /Policy nicht/
      );
    }
  );
});

test("readFromFormRecord: fertiger Hash (BLF-CRYPT) wird ohne Confirm-Pruefung akzeptiert", async () => {
  await withPluginConfig({}, () => {
    const fv = getFieldview();
    const rec = {
      password_plain: "{BLF-CRYPT}$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV",
    };
    const result = fv.readFromFormRecord(rec, "password_plain");
    assert.equal(
      result,
      "{BLF-CRYPT}$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"
    );
  });
});

test("Trigger: readFromFormRecord-Fehlerkontext wird abgefangen und als error zurueckgegeben", async () => {
  const trigger = getTrigger();
  const res = await trigger.run({
    row: {
      password_plain: "Pass1",
      __pwtools_error__password_plain:
        "Passwortbestaetigung stimmt nicht mit Passwort ueberein.",
    },
    table: null,
    configuration: {
      plain_field: "password_plain",
      hash_field: "password_hash",
      enforce_policy: true,
    },
  });
  assert.ok(res.error, "Trigger sollte error zurueckgeben");
  assert.match(res.error, /Passwortbestaetigung/);
});

test("Trigger: schwaches Passwort -> error bei enforce_policy=true", async () => {
  const trigger = getTrigger();
  const res = await trigger.run({
    row: { password_plain: "abc" },
    table: null,
    configuration: {
      plain_field: "password_plain",
      hash_field: "password_hash",
      enforce_policy: true,
    },
  });
  assert.ok(res.error, "Trigger sollte error zurueckgeben");
  assert.match(res.error, /Policy nicht/);
});

test("Trigger: schwaches Passwort -> KEIN error bei enforce_policy=false", async () => {
  const trigger = getTrigger();
  const res = await trigger.run({
    row: { password_plain: "abc" },
    table: null,
    configuration: {
      plain_field: "password_plain",
      hash_field: "password_hash",
      enforce_policy: false,
    },
  });
  assert.ok(!res.error, "Kein Fehler erwartet");
  assert.ok(res.set_fields, "set_fields sollte gesetzt sein");
  assert.ok(res.set_fields.password_hash, "Hash sollte gesetzt sein");
});

test("Trigger: gutes Passwort -> Hash im set_fields + Klartext geleert", async () => {
  const trigger = getTrigger();
  const res = await trigger.run({
    row: {
      password_plain: "SehrSicher99xy",
      password_plain__scheme: "BLF-CRYPT",
    },
    table: null,
    configuration: {
      plain_field: "password_plain",
      hash_field: "password_hash",
      enforce_policy: true,
      clear_plain: true,
    },
  });
  assert.ok(!res.error, "Kein Fehler erwartet: " + JSON.stringify(res));
  assert.ok(res.set_fields.password_hash);
  assert.match(res.set_fields.password_hash, /^\{BLF-CRYPT\}/);
  assert.equal(res.set_fields.password_plain, "");
});

test("Trigger: Confirm-Mismatch als Fallback (ohne readFromFormRecord) -> error", async () => {
  const trigger = getTrigger();
  // Simuliert den Fall, dass ein anderes Fieldview verwendet wird und __confirm
  // dennoch als eigenes Feld im Row landet.
  const res = await trigger.run({
    row: {
      password_plain: "SehrSicher99xy",
      password_plain__confirm: "SehrSicher00xy",
    },
    table: null,
    configuration: {
      plain_field: "password_plain",
      hash_field: "password_hash",
      enforce_policy: true,
    },
  });
  assert.ok(res.error);
  assert.match(res.error, /Passwortbestaetigung/);
});

test("Trigger: bestehender Hash wird durchgereicht", async () => {
  const trigger = getTrigger();
  const hash =
    "{BLF-CRYPT}$2y$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV";
  const res = await trigger.run({
    row: { password_plain: hash },
    table: null,
    configuration: {
      plain_field: "password_plain",
      hash_field: "password_hash",
    },
  });
  assert.ok(!res.error);
  assert.equal(res.set_fields.password_hash, hash);
});

test("Trigger: leeres Klartextfeld -> notice, kein Fehler, keine Aktion", async () => {
  const trigger = getTrigger();
  const res = await trigger.run({
    row: { password_plain: "" },
    table: null,
    configuration: {
      plain_field: "password_plain",
      hash_field: "password_hash",
    },
  });
  assert.ok(!res.error);
  assert.match(res.notice, /uebersprungen/);
});
