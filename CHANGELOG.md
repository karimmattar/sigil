# Changelog

## 1.0.0 — 2026-11-24

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
- Driver auto-detection for Windows/macOS/Linux (Egypt Trust/DeltaTrust ePass2003, SafeNet, IDPrime, WatchData, OpenSC).
- Desktop app: tray/menu-bar icon, start at login (Windows/macOS/Linux), single-instance detection, CLI (`serve`, `diagnose`, `autostart`, `config`).
- TOML configuration + environment overrides, rotating logs, JSON audit log.
- Origin/Host guards, upload limits, security headers, Private Network Access support, optional TLS.
- 250 tests (unit + SoftHSM2 end-to-end), strict typing, PyInstaller packaging, GitHub Actions matrix for Windows/macOS/Linux.
