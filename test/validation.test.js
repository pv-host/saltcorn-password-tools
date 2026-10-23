/**
 * Integrationstests fuer v0.3.2:
 * - readFromFormRecord im Fieldview 'password_input' liefert einen
 *   Marker-String (__PWTOOLS_ERR__:...) bei Fehler statt null, damit
 *   Saltcorn den Wert nicht durch die {success:null}-Falle rutschen laesst.
 * - Trigger-Fehlerpfade (Marker, Confirm-Mismatch als Fallback, Policy-Fail,
 *   Hash-Passthrough)
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

test("readFromFormRecord: Confirm-Mismatch -> Marker-String mit Meldung", async () => {
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
      assert.ok(
        typeof result === "string" && result.startsWith("__PWTOOLS_ERR__:"),
        "Erwartet Marker-String, bekommen: " + JSON.stringify(result)
      );
      assert.match(result, /Passwortbestaetigung stimmt nicht/);
    }
  );
});

test("readFromFormRecord: Policy-Fail (zu kurz) -> Marker-String mit Meldung", async () => {
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
      assert.ok(
        typeof result === "string" && result.startsWith("__PWTOOLS_ERR__:"),
        "Erwartet Marker-String, bekommen: " + JSON.stringify(result)
      );
      assert.match(result, /Policy nicht/);
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

test("Trigger: erkennt Marker-String aus Fieldview und liefert error", async () => {
  const trigger = getTrigger();
  const res = await trigger.run({
    row: {
      password_plain:
        "__PWTOOLS_ERR__:Passwortbestaetigung stimmt nicht mit Passwort ueberein.",
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
  assert.doesNotMatch(res.error, /__PWTOOLS_ERR__/, "Prefix soll entfernt sein");
});

test("Trigger: Marker-String fuer Policy-Fehler wird korrekt extrahiert", async () => {
  const trigger = getTrigger();
  const res = await trigger.run({
    row: {
      password_plain:
        "__PWTOOLS_ERR__:Passwort erfuellt die Policy nicht: Mindestens 10 Zeichen",
    },
    table: null,
    configuration: {
      plain_field: "password_plain",
      hash_field: "password_hash",
      enforce_policy: true,
    },
  });
  assert.ok(res.error);
  assert.match(res.error, /Policy nicht/);
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

test("Trigger: Hash-Import braucht explizite Freigabe", async () => {
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
  assert.match(res.error, /nicht zugelassen/);
  const imported = await trigger.run({
    row: { password_plain: hash }, table: null,
    configuration: { plain_field: "password_plain", hash_field: "password_hash", allow_hash_import: true },
  });
  assert.ok(!imported.error);
  assert.equal(imported.set_fields.password_hash, hash);
});

test("Trigger: set_fields enthaelt KEINE Extra-Formfelder (__confirm, __scheme)", async () => {
  // Regression-Test fuer 0.3.2-Bugfix: set_fields[<name>__confirm] = undefined
  // fuehrte dazu, dass pg die Spalte in die INSERT-Query aufnahm und mit
  // "column \"...__confirm\" of relation ... does not exist" ablehnte.
  const trigger = getTrigger();
  const res = await trigger.run({
    row: {
      password_plain: "SehrSicher99xy",
      password_plain__confirm: "SehrSicher99xy",
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
  assert.ok(res.set_fields, "set_fields sollte gesetzt sein");
  const keys = Object.keys(res.set_fields);
  assert.ok(
    !keys.includes("password_plain__confirm"),
    "set_fields darf __confirm nicht enthalten, hat: " + JSON.stringify(keys)
  );
  assert.ok(
    !keys.includes("password_plain__scheme"),
    "set_fields darf __scheme nicht enthalten, hat: " + JSON.stringify(keys)
  );
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

// ---------------------------------------------------------------------------
// v0.4.0: Schema-Sentinel - User-Auswahl aus Form-Dropdown durchreichen
// ---------------------------------------------------------------------------

test("Fieldview: __scheme-Auswahl wird als Sentinel kodiert", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const fv = getFieldview();
      const rec = {
        password_plain: "password1234",
        password_plain__scheme: "SHA512-CRYPT",
      };
      const out = fv.readFromFormRecord(rec, "password_plain");
      assert.match(out, /^__PWTOOLS_SCHEME__:SHA512-CRYPT\|password1234$/);
    }
  );
});

test("Fieldview: unbekanntes Schema wird ignoriert (kein Sentinel)", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const fv = getFieldview();
      const rec = {
        password_plain: "password1234",
        password_plain__scheme: "BOGUS-SCHEME",
      };
      const out = fv.readFromFormRecord(rec, "password_plain");
      assert.equal(out, "password1234");
    }
  );
});

test("Fieldview: leeres __scheme wird ignoriert", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const fv = getFieldview();
      const rec = { password_plain: "password1234", password_plain__scheme: "" };
      const out = fv.readFromFormRecord(rec, "password_plain");
      assert.equal(out, "password1234");
    }
  );
});

test("Fieldview: doppelter Sentinel-Wrap wird vermieden", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const fv = getFieldview();
      const already = "__PWTOOLS_SCHEME__:CRAM-MD5|password";
      const out = fv.readFromFormRecord(
        { password_plain: already },
        "password_plain"
      );
      assert.equal(out, already);
    }
  );
});

test("Trigger: User-Wahl aus Sentinel gewinnt gegen Plugin-Default", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      bcrypt_rounds: 4,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const trigger = getTrigger();
      const res = await trigger.run({
        row: { password_plain: "__PWTOOLS_SCHEME__:SHA512-CRYPT|password1234" },
        table: null,
        configuration: {
          plain_field: "password_plain",
          hash_field: "password_hash",
          enforce_policy: false,
          clear_plain: false,
        },
      });
      assert.ok(!res.error, "error should be undefined, got: " + res.error);
      assert.match(
        res.set_fields.password_hash,
        /^\{SHA512-CRYPT\}\$6\$/,
        "hash should be SHA512-CRYPT, got: " + res.set_fields.password_hash
      );
    }
  );
});

test("Trigger: User-Wahl gewinnt auch gegen Trigger-cfg.scheme", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      bcrypt_rounds: 4,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const trigger = getTrigger();
      const res = await trigger.run({
        row: { password_plain: "__PWTOOLS_SCHEME__:CRAM-MD5|password" },
        table: null,
        configuration: {
          plain_field: "password_plain",
          hash_field: "password_hash",
          scheme: "PBKDF2", // Admin will PBKDF2 fixieren
          enforce_policy: false,
          clear_plain: false,
        },
      });
      assert.match(res.set_fields.password_hash, /^\{CRAM-MD5\}[0-9a-f]{64}$/);
    }
  );
});

test("Trigger: ohne Sentinel -> Plugin-Default wird verwendet", async () => {
  await withPluginConfig(
    {
      default_scheme: "PBKDF2",
      with_prefix: true,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const trigger = getTrigger();
      const res = await trigger.run({
        row: { password_plain: "password1234" },
        table: null,
        configuration: {
          plain_field: "password_plain",
          hash_field: "password_hash",
          enforce_policy: false,
          clear_plain: false,
        },
      });
      assert.match(res.set_fields.password_hash, /^\{PBKDF2\}\$1\$/);
    }
  );
});

// -----------------------------------------------------------------------------
// v0.4.2: Prio-Chain-Fixes fuer Prefix-Bug bei individueller Hash-Wahl
// -----------------------------------------------------------------------------

test("v0.4.2: row[__scheme] direkt (kein Sentinel) schlaegt cfg.scheme", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      bcrypt_rounds: 4,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const trigger = getTrigger();
      const row = {
        password_plain: "password1234",
        password_plain__scheme: "PBKDF2",
      };
      const res = await trigger.run({
        row,
        table: null,
        configuration: {
          plain_field: "password_plain",
          hash_field: "password_hash",
          scheme: "BLF-CRYPT",
          enforce_policy: false,
        },
      });
      assert.ok(res.set_fields.password_hash.startsWith("{PBKDF2}"),
        "Erwartet {PBKDF2}-Prefix, bekam: " + res.set_fields.password_hash.slice(0, 20));
    }
  );
});

test("v0.4.2: updated_fields mit Sentinel wird als User-Wahl erkannt", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      bcrypt_rounds: 4,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const trigger = getTrigger();
      const row = { password_plain: "password1234" };
      const updated_fields = {
        password_plain: "__PWTOOLS_SCHEME__:CRAM-MD5|password1234",
      };
      const res = await trigger.run({
        row,
        table: null,
        configuration: {
          plain_field: "password_plain",
          hash_field: "password_hash",
          scheme: "BLF-CRYPT",
          enforce_policy: false,
        },
        updated_fields,
      });
      assert.ok(res.set_fields.password_hash.startsWith("{CRAM-MD5}"),
        "Erwartet {CRAM-MD5}-Prefix, bekam: " + res.set_fields.password_hash.slice(0, 20));
    }
  );
});

test("v0.4.2: updated_fields[__scheme] direkt schlaegt cfg.scheme", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      bcrypt_rounds: 4,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const trigger = getTrigger();
      const row = { password_plain: "password1234" };
      const updated_fields = {
        password_plain: "password1234",
        password_plain__scheme: "SHA512-CRYPT",
      };
      const res = await trigger.run({
        row,
        table: null,
        configuration: {
          plain_field: "password_plain",
          hash_field: "password_hash",
          scheme: "BLF-CRYPT",
          enforce_policy: false,
        },
        updated_fields,
      });
      assert.ok(res.set_fields.password_hash.startsWith("{SHA512-CRYPT}"),
        "Erwartet {SHA512-CRYPT}-Prefix, bekam: " + res.set_fields.password_hash.slice(0, 20));
    }
  );
});

test("v0.4.2: ungueltiges row[__scheme] wird verworfen, cfg.scheme greift", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      bcrypt_rounds: 4,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const trigger = getTrigger();
      const row = {
        password_plain: "password1234",
        password_plain__scheme: "NICHT-VORHANDEN",
      };
      const res = await trigger.run({
        row,
        table: null,
        configuration: {
          plain_field: "password_plain",
          hash_field: "password_hash",
          scheme: "SHA512-CRYPT",
          enforce_policy: false,
        },
      });
      assert.ok(res.set_fields.password_hash.startsWith("{SHA512-CRYPT}"),
        "Erwartet {SHA512-CRYPT}-Prefix, bekam: " + res.set_fields.password_hash.slice(0, 20));
    }
  );
});

test("v0.4.2: maskHash liefert 10 Kopf- + 4 Endzeichen fuer lange Hashes", async () => {
  const fvs = plugin.fieldviews();
  const showView = fvs.password_hash_show;
  const long = "{BLF-CRYPT}$2y$12$AbCdEfGhIjKlMnOpQrStUvWxYz012345";
  const html = showView.run(long);
  // Der sichtbare Text ist zwischen den <span>-Tags, nicht im title=-Attribut.
  const bodyMatch = />([^<]+)<\/span>$/.exec(html);
  assert.ok(bodyMatch, "HTML muss span-Inhalt enthalten: " + html);
  const body = bodyMatch[1];
  // Erwartet: '{BLF-CRYPT' (10 Zeichen) + '…' + letzte 4 Zeichen '2345'
  assert.equal(body, "{BLF-CRYPT\u20262345",
    "maskHash muss HEAD=10 + \u2026 + TAIL=4 rendern, aber gerendert wurde: " + body);
});

test("v0.4.2: maskHash liefert Punkte fuer sehr kurze Werte", async () => {
  const fvs = plugin.fieldviews();
  const showView = fvs.password_hash_show;
  const short = "kurz1";
  const html = showView.run(short);
  assert.ok(html.includes("\u2022\u2022\u2022\u2022") || html.includes("••••"),
    "Kurzer Wert muss vollstaendig maskiert werden: " + html);
});

test("Trigger: nach Sentinel-Unwrap ist row[plain] Klartext, kein Sentinel", async () => {
  await withPluginConfig(
    {
      default_scheme: "BLF-CRYPT",
      with_prefix: true,
      bcrypt_rounds: 4,
      min_length: 4,
      min_score: 0,
      require_upper: false,
      require_lower: false,
      require_digit: false,
      require_symbol: false,
    },
    async () => {
      const trigger = getTrigger();
      const row = { password_plain: "__PWTOOLS_SCHEME__:SHA512-CRYPT|password1234" };
      await trigger.run({
        row,
        table: null,
        configuration: {
          plain_field: "password_plain",
          hash_field: "password_hash",
          enforce_policy: false,
          clear_plain: true, // request clear -> row[plain] must not contain sentinel
        },
      });
      // clear_plain: true -> das Fieldview-Wert im row wird nach dem Trigger
      // via set_fields ueberschrieben; unser eigener Unwrap darf keinesfalls
      // den Sentinel im row belassen.
      assert.ok(
        !row.password_plain.startsWith("__PWTOOLS_SCHEME__:"),
        "row[plain] soll den Sentinel nicht enthalten, ist: " + row.password_plain
      );
    }
  );
});
