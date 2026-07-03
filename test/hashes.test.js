/* eslint-env node */
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  hashPassword,
  verifyPassword,
  stripScheme,
  detectSchemeFromHash,
  SCHEMES,
} = require("../lib/hashes");

const { evaluate } = require("../lib/strength");

const PW = "CorrectHorse!Battery9Staple";
const WRONG = "wrong-password";

test("SCHEMES exports", () => {
  assert.deepEqual(SCHEMES, ["BLF-CRYPT", "SHA512-CRYPT", "PBKDF2"]);
});

test("BLF-CRYPT round-trip with prefix", async () => {
  const h = await hashPassword(PW, { scheme: "BLF-CRYPT", withPrefix: true, bcryptRounds: 6 });
  assert.match(h, /^\{BLF-CRYPT\}\$2y\$/);
  assert.equal(await verifyPassword(PW, h), true);
  assert.equal(await verifyPassword(WRONG, h), false);
});

test("BLF-CRYPT round-trip without prefix", async () => {
  const h = await hashPassword(PW, { scheme: "BLF-CRYPT", withPrefix: false, bcryptRounds: 6 });
  assert.match(h, /^\$2y\$/);
  assert.equal(await verifyPassword(PW, h), true);
});

test("SHA512-CRYPT round-trip with prefix", async () => {
  const h = await hashPassword(PW, { scheme: "SHA512-CRYPT", withPrefix: true });
  assert.match(h, /^\{SHA512-CRYPT\}\$6\$/);
  assert.equal(await verifyPassword(PW, h), true);
  assert.equal(await verifyPassword(WRONG, h), false);
});

test("SHA512-CRYPT with custom rounds", async () => {
  const h = await hashPassword(PW, {
    scheme: "SHA512-CRYPT",
    withPrefix: false,
    sha512Rounds: 6000,
  });
  assert.match(h, /^\$6\$rounds=6000\$/);
  assert.equal(await verifyPassword(PW, h), true);
});

test("PBKDF2 round-trip with prefix", async () => {
  const h = await hashPassword(PW, {
    scheme: "PBKDF2",
    withPrefix: true,
    pbkdf2Iterations: 2000,
  });
  assert.match(h, /^\{PBKDF2\}\$1\$[0-9a-f]+\$2000\$[0-9a-f]+$/);
  assert.equal(await verifyPassword(PW, h), true);
  assert.equal(await verifyPassword(WRONG, h), false);
});

test("stripScheme detects Dovecot prefix", () => {
  assert.deepEqual(stripScheme("{BLF-CRYPT}$2y$abc"), {
    scheme: "BLF-CRYPT",
    hash: "$2y$abc",
  });
  assert.deepEqual(stripScheme("$2y$abc"), { scheme: null, hash: "$2y$abc" });
});

test("detectSchemeFromHash", () => {
  assert.equal(detectSchemeFromHash("$2y$12$abc"), "BLF-CRYPT");
  assert.equal(detectSchemeFromHash("$6$salt$hash"), "SHA512-CRYPT");
  assert.equal(detectSchemeFromHash("$1$abc$1000$deadbeef"), "PBKDF2");
  assert.equal(detectSchemeFromHash("garbage"), null);
});

test("empty password rejected", async () => {
  await assert.rejects(() => hashPassword("", { scheme: "BLF-CRYPT", bcryptRounds: 4 }));
});

test("strength: too short flagged", () => {
  const r = evaluate("abc", { minLength: 8, minScore: 0 });
  assert.equal(r.valid, false);
  assert.ok(r.problems.some((p) => p.includes("Mindestens")));
});

test("strength: strong password passes rules", () => {
  const r = evaluate("CorrectHorse!Battery9Staple", {
    minLength: 10,
    requireUpper: true,
    requireLower: true,
    requireDigit: true,
    requireSymbol: true,
    minScore: 0, // ignore zxcvbn for this check
  });
  assert.equal(r.valid, true, JSON.stringify(r));
});
