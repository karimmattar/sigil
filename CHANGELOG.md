# Changelog

Versions follow [Semantic Versioning](https://semver.org); every minor version also gets a
fruit codename (see [docs/RELEASING.md](docs/RELEASING.md)).

## Unreleased

## 1.0.0 "Apricot" — 2026-11-24

First release: a complete rewrite of the original single-file signing script.

### Breaking
- The API now lives under `/api/v1`; the old `/health`, `/tokens` and `/sign-pdf` routes are gone.
- Tokens are addressed by `token_serial` instead of a slot index; certificates by `cert_id` (hex) instead of `cert_label`.
- Errors use one JSON shape: `{"error": {"code", "message", "details"}}`.

### Fixed
- PDF signing failed on every request (`asyncio.run()` inside the server's event loop).
- A PDF could be signed only once (fixed field name).
- Signing failed without `cert_label` on tokens holding more than one certificate.
- Slot numbering mismatch between token listing and signing.
- Concurrent requests could collide on the token.
- Any website could submit PIN attempts (CSRF) and target the agent via DNS rebinding.

### Added
- Automatic signing-certificate selection; certificate listing without a PIN.
- PAdES (default) and `adbe.pkcs7` profiles, SHA-256/384/512, visible stamps, RFC 3161 timestamps.
- Detached/attached CMS and CAdES-BES signing of arbitrary data (`/api/v1/sign/data`).
- PIN retry-counter reporting, fail-fast on locked tokens, `TOKEN_BUSY` instead of hangs.
- Driver auto-detection for Windows/macOS/Linux, built from vendor packages and documentation
  (Feitian HyperPKI HYP2003 / ePass2003, WatchData ProxKey, SafeNet, Thales IDPrime, OpenSC);
  every catalog entry is tagged with its evidence.
- Desktop app: tray/menu-bar icon, start at login (Windows/macOS/Linux), single-instance detection, CLI (`serve`, `diagnose`, `autostart`, `config`).
- TOML configuration + environment overrides, rotating logs, JSON audit log.
- Origin/Host guards, upload limits, security headers, Private Network Access support, optional TLS.
- Tests (unit + SoftHSM2 end-to-end), strict typing, PyInstaller packaging, GitHub Actions on Windows/macOS/Linux.
- Release pipeline: pushing a `vX.Y.Z` tag publishes a GitHub Release with the Windows, macOS
  and Linux apps plus SHA-256 checksums.
- Repository rulesets (protected `main`, immutable release tags), Dependabot, CODEOWNERS,
  pull-request and issue templates.
