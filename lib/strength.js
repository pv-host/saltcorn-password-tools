/**
 * Server-side password-strength evaluator (used for validation on save).
 * Combines zxcvbn score with configurable rule checks:
 *   - minimum length
 *   - required character classes (upper, lower, digit, symbol)
 *   - minimum zxcvbn score (0-4)
 */

"use strict";

let zxcvbn;
try {
  zxcvbn = require("zxcvbn");
} catch (_e) {
  zxcvbn = null;
}

/**
 * @typedef {Object} StrengthPolicy
 * @property {number} [minLength]      default 10
 * @property {boolean} [requireUpper]  default true
 * @property {boolean} [requireLower]  default true
 * @property {boolean} [requireDigit]  default true
 * @property {boolean} [requireSymbol] default false
 * @property {number} [minScore]       default 3 (0..4)
 */

/**
 * @typedef {Object} StrengthResult
 * @property {boolean} valid
 * @property {number} score            0..4 (zxcvbn) or -1 if unavailable
 * @property {string[]} problems
 * @property {string[]} suggestions
 */

/**
 * @param {string} password
 * @param {StrengthPolicy} [policy]
 * @returns {StrengthResult}
 */
function evaluate(password, policy) {
  const p = Object.assign(
    {
      minLength: 10,
      requireUpper: true,
      requireLower: true,
      requireDigit: true,
      requireSymbol: false,
      minScore: 3,
    },
    policy || {}
  );

  const problems = [];
  const suggestions = [];

  if (typeof password !== "string" || password.length === 0) {
    return {
      valid: false,
      score: -1,
      problems: ["Passwort ist leer"],
      suggestions: ["Bitte ein Passwort eingeben"],
    };
  }

  if (password.length < p.minLength)
    problems.push(`Mindestens ${p.minLength} Zeichen erforderlich`);
  if (p.requireUpper && !/[A-Z]/.test(password))
    problems.push("Mindestens ein Grossbuchstabe (A-Z)");
  if (p.requireLower && !/[a-z]/.test(password))
    problems.push("Mindestens ein Kleinbuchstabe (a-z)");
  if (p.requireDigit && !/[0-9]/.test(password))
    problems.push("Mindestens eine Ziffer (0-9)");
  if (p.requireSymbol && !/[^A-Za-z0-9]/.test(password))
    problems.push("Mindestens ein Sonderzeichen");

  let score = -1;
  if (zxcvbn) {
    const z = zxcvbn(password);
    score = z.score;
    if (z.feedback && z.feedback.warning) suggestions.push(z.feedback.warning);
    if (z.feedback && Array.isArray(z.feedback.suggestions))
      suggestions.push(...z.feedback.suggestions);
    if (score < p.minScore)
      problems.push(
        `Passwortstaerke zu gering (Score ${score} von 4, mindestens ${p.minScore} erforderlich)`
      );
  }

  return {
    valid: problems.length === 0,
    score,
    problems,
    suggestions,
  };
}

module.exports = { evaluate };
