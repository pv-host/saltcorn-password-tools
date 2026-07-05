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
  assert.deepEqual(SCHEMES, ["BLF-CRYPT", "SHA512-CRYPT", "PBKDF2", "CRAM-MD5"]);
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

// ---------------------------------------------------------------------------
// CRAM-MD5 (Dovecot-Format)
// ---------------------------------------------------------------------------

test("CRAM-MD5 round-trip with prefix", async () => {
  const h = await hashPassword(PW, { scheme: "CRAM-MD5", withPrefix: true });
  // {CRAM-MD5} + 64 hex chars.
  assert.match(h, /^\{CRAM-MD5\}[0-9a-f]{64}$/);
  assert.equal(await verifyPassword(PW, h), true);
  assert.equal(await verifyPassword(WRONG, h), false);
});

test("CRAM-MD5 round-trip without prefix", async () => {
  const h = await hashPassword(PW, { scheme: "CRAM-MD5", withPrefix: false });
  assert.match(h, /^[0-9a-f]{64}$/);
  // Ohne Prefix ist der Hash nicht selbstbeschreibend - verify braucht Prefix.
  const withPref = `{CRAM-MD5}${h}`;
  assert.equal(await verifyPassword(PW, withPref), true);
});

test("CRAM-MD5 known Dovecot test vector", async () => {
  // doveadm pw -s CRAM-MD5 -p password  -> deterministisch (kein Salt).
  const h = await hashPassword("password", { scheme: "CRAM-MD5", withPrefix: true });
  assert.equal(
    h,
    "{CRAM-MD5}9186d855e11eba527a7a52ca82b313e180d62234f0acc9051b527243d41e2740"
  );
});

test("CRAM-MD5 is deterministic (no salt)", async () => {
  const a = await hashPassword("hello", { scheme: "CRAM-MD5" });
  const b = await hashPassword("hello", { scheme: "CRAM-MD5" });
  assert.equal(a, b);
});

test("CRAM-MD5 handles long password (>64 bytes)", async () => {
  const longPw = "x".repeat(100);
  const h = await hashPassword(longPw, { scheme: "CRAM-MD5", withPrefix: true });
  assert.match(h, /^\{CRAM-MD5\}[0-9a-f]{64}$/);
  assert.equal(await verifyPassword(longPw, h), true);
});

test("CRAM-MD5 accepts {HMAC-MD5} alias on verify", async () => {
  const h = await hashPassword("password", { scheme: "CRAM-MD5", withPrefix: false });
  // Same hash body, but stored under Dovecot's alias prefix.
  assert.equal(await verifyPassword("password", `{HMAC-MD5}${h}`), true);
  assert.equal(await verifyPassword("wrong", `{HMAC-MD5}${h}`), false);
});

test("stripScheme recognises {CRAM-MD5} prefix", () => {
  const { scheme, hash } = stripScheme(
    "{CRAM-MD5}9186d855e11eba527a7a52ca82b313e180d62234f0acc9051b527243d41e2740"
  );
  assert.equal(scheme, "CRAM-MD5");
  assert.equal(hash.length, 64);
});
