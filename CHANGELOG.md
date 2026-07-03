# Changelog

## 0.1.0 — 2026-07-03

### Added
- Initial release.
- Field types `Password Plain` and `Password Hash`.
- Field-views: `with_strength` (Edit), `show`, `show_raw`, `hash_from_plain`, `edit_raw`.
- Server functions: `pwtools_hash`, `pwtools_verify`, `pwtools_strength`.
- Trigger action `hash_password_field` for automatic hashing on insert/update.
- Configurable Dovecot-compatible schemes: BLF-CRYPT, SHA512-CRYPT, PBKDF2.
- Configurable `{SCHEME}` prefix (per plugin / per field).
- Live strength meter combining zxcvbn score with rule checks.
- HTTP endpoint `POST /pwtools/strength`.
- Full test suite (BLF-CRYPT / SHA512-CRYPT / PBKDF2 round-trip).
