/**
 * Password hashing helpers for saltcorn-password-tools.
 *
 * Supported schemes:
 *   - BLF-CRYPT     ($2y$ / $2a$ / $2b$) via bcryptjs
 *   - SHA512-CRYPT  ($6$rounds=NN$SALT$HASH) via sha512-crypt-ts
 *   - PBKDF2        Dovecot format: $1$SALT$ROUNDS$HASH (hex) via node:crypto
 *
 * All functions return a plain hash string without prefix by default and
 * a `{PREFIX}...` string when `withPrefix` is true (Dovecot-style).
 */

"use strict";

const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const { sha512 } = require("sha512-crypt-ts");

const SCHEMES = ["BLF-CRYPT", "SHA512-CRYPT", "PBKDF2"];

/**
 * Format a hash with optional Dovecot-style scheme prefix.
 * @param {string} scheme
 * @param {string} hash
 * @param {boolean} withPrefix
 */
function withScheme(scheme, hash, withPrefix) {
  if (!withPrefix) return hash;
  return `{${scheme}}${hash}`;
}

/**
 * Detect a Dovecot-style prefix and strip it for verification.
 * @param {string} value
 * @returns {{ scheme: string|null, hash: string }}
 */
function stripScheme(value) {
  if (typeof value !== "string") return { scheme: null, hash: "" };
  const m = value.match(/^\{([A-Z0-9-]+)\}(.*)$/);
  if (m) return { scheme: m[1].toUpperCase(), hash: m[2] };
  return { scheme: null, hash: value };
}

/**
 * Hash a plaintext password with the requested scheme.
 *
 * @param {string} plain
 * @param {object} opts
 * @param {"BLF-CRYPT"|"SHA512-CRYPT"|"PBKDF2"} opts.scheme
 * @param {boolean} [opts.withPrefix=true]
 * @param {number} [opts.bcryptRounds=12]         cost factor (4-15)
 * @param {number} [opts.sha512Rounds=5000]       SHA-512 crypt rounds (>=1000)
 * @param {number} [opts.pbkdf2Iterations=25000]  PBKDF2 iterations
 * @param {number} [opts.pbkdf2KeyLen=64]         PBKDF2 output length in bytes
 * @param {string} [opts.pbkdf2Digest="sha512"]   PBKDF2 hash digest
 * @param {"2a"|"2b"|"2y"} [opts.bcryptPrefix="2y"] bcrypt variant prefix
 * @returns {Promise<string>}
 */
async function hashPassword(plain, opts) {
  if (typeof plain !== "string" || plain.length === 0) {
    throw new Error("Password must be a non-empty string");
  }
  const o = normalizeOpts(opts);

  switch (o.scheme) {
    case "BLF-CRYPT": {
      // bcryptjs generates $2a$ or $2b$ salts; normalise to configured prefix.
      const salt = await bcrypt.genSalt(o.bcryptRounds);
      let hash = await bcrypt.hash(plain, salt);
      if (o.bcryptPrefix && /^\$2[aby]\$/.test(hash)) {
        hash = hash.replace(/^\$2[aby]\$/, `$${o.bcryptPrefix}$`);
      }
      return withScheme("BLF-CRYPT", hash, o.withPrefix);
    }
    case "SHA512-CRYPT": {
      // Generate a 16-char base64-ish salt (glibc allows [./0-9A-Za-z], up to 16).
      const salt = randomCryptSalt(16);
      const saltSpec =
        o.sha512Rounds && o.sha512Rounds !== 5000
          ? `$6$rounds=${o.sha512Rounds}$${salt}$`
          : `$6$${salt}$`;
      const hash = sha512.crypt(plain, saltSpec);
      return withScheme("SHA512-CRYPT", hash, o.withPrefix);
    }
    case "PBKDF2": {
      // Dovecot format: $1$SALT$ROUNDS$HASH (hex-encoded).
      // See doc.dovecot.org - "PKCS5 Password hashing algorithm".
      const salt = crypto.randomBytes(16).toString("hex");
      const iterations = o.pbkdf2Iterations;
      const derived = await pbkdf2Async(
        plain,
        salt,
        iterations,
        o.pbkdf2KeyLen,
        o.pbkdf2Digest
      );
      const hex = derived.toString("hex");
      const hash = `$1$${salt}$${iterations}$${hex}`;
      return withScheme("PBKDF2", hash, o.withPrefix);
    }
    default:
      throw new Error(`Unsupported scheme: ${o.scheme}`);
  }
}

/**
 * Verify a plaintext password against a stored hash (with or without {SCHEME} prefix).
 * Scheme is auto-detected from the prefix or from the hash format.
 *
 * @param {string} plain
 * @param {string} stored
 * @returns {Promise<boolean>}
 */
async function verifyPassword(plain, stored) {
  if (!plain || !stored) return false;
  const { scheme, hash } = stripScheme(stored);
  const detected = scheme || detectSchemeFromHash(hash);
  if (!detected) return false;

  try {
    switch (detected) {
      case "BLF-CRYPT": {
        // bcryptjs supports $2a/$2b but not always $2y; normalise to $2a for verify.
        const normalized = hash.replace(/^\$2y\$/, "$2a$");
        return await bcrypt.compare(plain, normalized);
      }
      case "SHA512-CRYPT": {
        // Parse $6$[rounds=N$]SALT$HASH and re-hash to compare.
        const parts = hash.split("$");
        // ["", "6", (maybe "rounds=NN"), salt, hashPart]
        if (parts.length < 4 || parts[1] !== "6") return false;
        let saltSpec;
        if (parts[2].startsWith("rounds=")) {
          saltSpec = `$6$${parts[2]}$${parts[3]}$`;
        } else {
          saltSpec = `$6$${parts[2]}$`;
        }
        const recomputed = sha512.crypt(plain, saltSpec);
        return timingSafeEqStr(recomputed, hash);
      }
      case "PBKDF2": {
        // Dovecot format: $1$SALT$ROUNDS$HASH_HEX
        const parts = hash.split("$");
        if (parts.length !== 5 || parts[1] !== "1") return false;
        const [, , salt, roundsStr, hex] = parts;
        const iterations = parseInt(roundsStr, 10);
        if (!Number.isFinite(iterations) || iterations <= 0) return false;
        const keyLen = Buffer.from(hex, "hex").length;
        const derived = await pbkdf2Async(
          plain,
          salt,
          iterations,
          keyLen,
          "sha512"
        );
        return timingSafeEqStr(derived.toString("hex"), hex);
      }
      default:
        return false;
    }
  } catch (_err) {
    return false;
  }
}

/**
 * Best-effort scheme detection from a raw (unprefixed) hash string.
 * @param {string} hash
 */
function detectSchemeFromHash(hash) {
  if (/^\$2[aby]\$/.test(hash)) return "BLF-CRYPT";
  if (/^\$6\$/.test(hash)) return "SHA512-CRYPT";
  if (/^\$1\$[^$]+\$\d+\$[0-9a-f]+$/i.test(hash)) return "PBKDF2";
  return null;
}

function normalizeOpts(opts) {
  const o = Object.assign(
    {
      scheme: "BLF-CRYPT",
      withPrefix: true,
      bcryptRounds: 12,
      bcryptPrefix: "2y",
      sha512Rounds: 5000,
      pbkdf2Iterations: 25000,
      pbkdf2KeyLen: 64,
      pbkdf2Digest: "sha512",
    },
    opts || {}
  );
  if (!SCHEMES.includes(o.scheme)) {
    throw new Error(
      `Unknown scheme "${o.scheme}". Allowed: ${SCHEMES.join(", ")}`
    );
  }
  // Sanity clamps
  o.bcryptRounds = clamp(parseInt(o.bcryptRounds, 10) || 12, 4, 15);
  o.sha512Rounds = clamp(parseInt(o.sha512Rounds, 10) || 5000, 1000, 999999999);
  o.pbkdf2Iterations = clamp(
    parseInt(o.pbkdf2Iterations, 10) || 25000,
    1000,
    10000000
  );
  o.pbkdf2KeyLen = clamp(parseInt(o.pbkdf2KeyLen, 10) || 64, 16, 128);
  if (!["2a", "2b", "2y"].includes(o.bcryptPrefix)) o.bcryptPrefix = "2y";
  return o;
}

function clamp(v, lo, hi) {
  return Math.max(lo, Math.min(hi, v));
}

function pbkdf2Async(password, salt, iterations, keyLen, digest) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, iterations, keyLen, digest, (err, dk) => {
      if (err) reject(err);
      else resolve(dk);
    });
  });
}

/**
 * Random crypt-style salt (chars ./0-9A-Za-z).
 * @param {number} n
 */
function randomCryptSalt(n) {
  const alphabet =
    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const bytes = crypto.randomBytes(n);
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[bytes[i] % alphabet.length];
  return out;
}

function timingSafeEqStr(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

module.exports = {
  SCHEMES,
  hashPassword,
  verifyPassword,
  stripScheme,
  detectSchemeFromHash,
};
