/**
 * Minimal MD5 block transform for use inside the CRAM-MD5 helper.
 *
 * MD5 processes 512-bit (64-byte) blocks. This helper takes exactly one
 * 64-byte block and returns the resulting internal state (a, b, c, d) as
 * unsigned 32-bit integers. Node's crypto.createHash("md5") does not expose
 * the intermediate state, so we implement the transform here.
 *
 * Reference: RFC 1321, section 3.4 (padding is intentionally NOT applied
 * here because Dovecot stores the state after exactly one raw block).
 */

"use strict";

// Per-round shift amounts.
const S = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

// Precomputed table K[i] = floor(2^32 * abs(sin(i + 1))).
const K = new Uint32Array(64);
for (let i = 0; i < 64; i++) {
  K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
}

// Initial MD5 state (a0, b0, c0, d0).
const INIT_STATE = new Uint32Array([
  0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
]);

function leftRotate(x, c) {
  return ((x << c) | (x >>> (32 - c))) >>> 0;
}

/**
 * Run one MD5 block transform on the given 64-byte Buffer.
 * @param {Buffer} block
 * @returns {{a:number,b:number,c:number,d:number}} raw 32-bit words
 */
function md5BlockDigest(block) {
  if (!Buffer.isBuffer(block) || block.length !== 64) {
    throw new Error("md5BlockDigest requires a 64-byte Buffer");
  }

  // Parse block into 16 little-endian 32-bit words.
  const M = new Uint32Array(16);
  for (let i = 0; i < 16; i++) M[i] = block.readUInt32LE(i * 4);

  let a = INIT_STATE[0];
  let b = INIT_STATE[1];
  let c = INIT_STATE[2];
  let d = INIT_STATE[3];

  for (let i = 0; i < 64; i++) {
    let f;
    let g;
    if (i < 16) {
      f = (b & c) | (~b & d);
      g = i;
    } else if (i < 32) {
      f = (d & b) | (~d & c);
      g = (5 * i + 1) % 16;
    } else if (i < 48) {
      f = b ^ c ^ d;
      g = (3 * i + 5) % 16;
    } else {
      f = c ^ (b | ~d);
      g = (7 * i) % 16;
    }
    f = (f + a + K[i] + M[g]) >>> 0;
    a = d;
    d = c;
    c = b;
    b = (b + leftRotate(f, S[i])) >>> 0;
  }

  return {
    a: (INIT_STATE[0] + a) >>> 0,
    b: (INIT_STATE[1] + b) >>> 0,
    c: (INIT_STATE[2] + c) >>> 0,
    d: (INIT_STATE[3] + d) >>> 0,
  };
}

module.exports = { md5BlockDigest };
