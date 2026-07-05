/**
 * CRAM-MD5 password hash generator (Dovecot-compatible).
 *
 * Dovecot stores the HMAC-MD5 key setup state - i.e. the MD5 internal state
 * after processing the ipad and opad blocks - as a 32-byte hex blob:
 *
 *   {CRAM-MD5}<64 hex chars>
 *
 * Byte layout (little-endian 32-bit words, verified against Dovecot's
 * hmac_md5_get_cram_context in src/lib/hmac-md5.c):
 *
 *   [ opad.a | opad.b | opad.c | opad.d | ipad.a | ipad.b | ipad.c | ipad.d ]
 *
 * The stored value contains only the two intermediate MD5 states after
 * hashing the padded 64-byte key blocks - no further data is folded in.
 * This is exactly what Dovecot needs to verify a CRAM-MD5 SASL challenge
 * without keeping the plaintext password around.
 *
 * References:
 *   - RFC 1321 (MD5) and RFC 2104 (HMAC).
 *   - Dovecot source: src/auth/password-scheme-cram-md5.c
 *     https://github.com/dovecot/core/blob/main/src/auth/password-scheme-cram-md5.c
 */

"use strict";

const crypto = require("crypto");
const { md5BlockDigest } = require("./md5-block");

const BLOCK_SIZE = 64;
const IPAD = 0x36;
const OPAD = 0x5c;

/**
 * Build the 64-byte padded key used by HMAC.
 * If the key is longer than the block size, it is first hashed with MD5.
 * The result is then either right-padded with zeros or replaced by its MD5.
 *
 * @param {string|Buffer} key
 * @returns {Buffer} 64-byte buffer
 */
function padKey(key) {
  let k = Buffer.isBuffer(key) ? key : Buffer.from(key, "utf8");
  if (k.length > BLOCK_SIZE) {
    k = crypto.createHash("md5").update(k).digest();
  }
  const padded = Buffer.alloc(BLOCK_SIZE, 0);
  k.copy(padded, 0);
  return padded;
}

/**
 * XOR every byte of the 64-byte block with `byte` in place and return it.
 * @param {Buffer} block  64-byte buffer (will be modified)
 * @param {number} byte
 */
function xorBlock(block, byte) {
  for (let i = 0; i < BLOCK_SIZE; i++) block[i] ^= byte;
  return block;
}

/**
 * Serialise an MD5 state {a,b,c,d} to 16 little-endian bytes.
 * @param {{a:number,b:number,c:number,d:number}} state
 * @returns {Buffer}
 */
function stateToLE(state) {
  const out = Buffer.alloc(16);
  out.writeUInt32LE(state.a >>> 0, 0);
  out.writeUInt32LE(state.b >>> 0, 4);
  out.writeUInt32LE(state.c >>> 0, 8);
  out.writeUInt32LE(state.d >>> 0, 12);
  return out;
}

/**
 * Compute the Dovecot CRAM-MD5 hash body (64 lowercase hex chars).
 * Does not include the `{CRAM-MD5}` scheme prefix.
 *
 * @param {string} plain  plaintext password
 * @returns {string} 64-char lowercase hex string
 */
function hashCramMd5(plain) {
  if (typeof plain !== "string" || plain.length === 0) {
    throw new Error("Password must be a non-empty string");
  }
  const key = padKey(plain);

  // ipad and opad each need their own copy so the XOR is independent.
  const ipadBlock = xorBlock(Buffer.from(key), IPAD);
  const opadBlock = xorBlock(Buffer.from(key), OPAD);

  const ipadState = md5BlockDigest(ipadBlock);
  const opadState = md5BlockDigest(opadBlock);

  // Dovecot writes opad state first, then ipad state.
  return Buffer.concat([stateToLE(opadState), stateToLE(ipadState)]).toString(
    "hex"
  );
}

/**
 * Verify a plaintext password against a stored CRAM-MD5 hash body (hex, no
 * prefix). Returns false for malformed input rather than throwing.
 *
 * @param {string} plain
 * @param {string} storedHex  64 hex chars, no `{CRAM-MD5}` prefix
 * @returns {boolean}
 */
function verifyCramMd5(plain, storedHex) {
  if (typeof plain !== "string" || plain.length === 0) return false;
  if (typeof storedHex !== "string" || !/^[0-9a-fA-F]{64}$/.test(storedHex)) {
    return false;
  }
  let expected;
  try {
    expected = hashCramMd5(plain);
  } catch (_err) {
    return false;
  }
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(storedHex.toLowerCase(), "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = { hashCramMd5, verifyCramMd5 };
