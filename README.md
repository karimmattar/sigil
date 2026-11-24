# Sigil

*Your token's seal, one click from the browser.*

**Sigil** is a small desktop app for **Windows, macOS and Linux** that lets your web system sign with a
**USB hard token** (Egypt Trust / DeltaTrust ePass2003, SafeNet eToken, OpenSC-supported cards,
… — anything with a PKCS#11 driver).

The browser talks to Sigil on `http://127.0.0.1:8765`; Sigil talks to the token driver.
The private key never leaves the token, and the PIN is used once per request and never stored.

```
 Web system (browser)  ──HTTP──►  Sigil (this app)  ──PKCS#11──►  token driver  ──►  USB token
```

What it can do:

| Capability | Endpoint |
|---|---|
| Agent + driver health | `GET /api/v1/health` |
| List connected tokens (incl. PIN retry state) | `GET /api/v1/tokens` |
| List certificates on a token — no PIN needed | `GET /api/v1/tokens/{serial}/certificates` |
| Sign a PDF — PAdES (default) or `adbe.pkcs7`, invisible or visible stamp, optional RFC 3161 timestamp, multiple signatures per PDF | `POST /api/v1/sign/pdf` |
| Sign arbitrary data — detached/attached CMS, CAdES-BES | `POST /api/v1/sign/data` |

Full API reference with browser examples: **[docs/API.md](docs/API.md)**.
Architecture: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**. Security audit: **[docs/SECURITY.md](docs/SECURITY.md)**.

---

## 1. Install the token driver

The agent uses the driver that ships with your token; install it first (vendor installer).

| OS | Egypt Trust / DeltaTrust (Feitian ePass2003) driver the agent looks for |
|---|---|
| Windows | `C:\Windows\System32\eps2003csp11.dll` (or `eps2003csp11v2.dll`, `SignatureP11.dll`, …) |
| macOS | `/usr/local/lib/libcastle_v2.1.0.0.dylib` |
| Linux | `/usr/lib/libcastle.so.1.0.0` |

SafeNet eToken, Thales IDPrime, WatchData, Hypersecu and OpenSC are auto-detected too
(full list: `src/sigil/infrastructure/pkcs11/locator.py`). Any other driver works by
setting `pkcs11_module` in the config. **The driver and the agent must have the same
architecture** (64-bit; Intel vs Apple Silicon on macOS).

## 2. Run the agent

**End users** — run the packaged app (built per OS, see [Packaging](#6-packaging)):

* Windows: `sigil.exe` · macOS: `Sigil.app` · Linux: `sigil`
* A tray / menu-bar icon appears: green = token ready, amber = no token, red = driver problem.
  Its menu has *Start at login*, *Open API docs*, *Open logs folder* and *Quit*.

**Developers** — from source (Python ≥ 3.11):

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[tray,dev]"
sigil diagnose        # is the driver found? is the token visible?
sigil                 # run with tray icon   (or: sigil serve --no-tray)
```

`python -m sigil …` works too.

## 3. Configure

```bash
sigil config init     # writes a commented config.toml
sigil config path     # where it is
sigil config show     # effective settings after file + environment
```

| OS | Config file | Logs (`agent.log`, `audit.log`) |
|---|---|---|
| Windows | `%APPDATA%\Sigil\config.toml` | `%LOCALAPPDATA%\Sigil\logs` |
| macOS | `~/Library/Application Support/Sigil/config.toml` | `~/Library/Logs/Sigil` |
| Linux | `~/.config/sigil/config.toml` | `~/.local/state/sigil/logs` |

The setting you **must** change is `allowed_origins`: the exact origin(s) of your web system.
Every other website is refused.

```toml
allowed_origins = ["https://erp.example.com"]
# tsa_url = "http://timestamp.digicert.com"   # optional: time-stamp every signature
```

Every key can also be set as an environment variable `SIGIL_<KEY>`
(lists comma-separated), e.g. `SIGIL_ALLOWED_ORIGINS=https://erp.example.com`.
The old `PKCS11_LIB_PATH` variable is still honoured.

Key settings: `host`/`port` (default `127.0.0.1:8765`), `pkcs11_module`, `max_upload_mb` (50),
`token_lock_timeout_seconds` (30), `tsa_url`, `pdf_strict_parsing` (false), `ssl_certfile`/`ssl_keyfile`,
`enable_docs`, `tray`, `log_level`.

## 4. Command line

```
sigil [--config FILE] [command]

  serve [--no-tray] [--host H] [--port P]   run the agent (default when no command is given)
  diagnose [--json]                         driver, tokens and certificates — no PIN needed
  autostart enable|disable|status           start at login (per user, no admin rights)
  config init [--force] | path | show
  version
```

`diagnose` exit codes: `0` driver OK, `3` driver missing, `2` invalid configuration.
On Windows the packaged exe has no console window; use `sigil.exe diagnose > report.txt`.

## 5. Develop & test

```bash
ruff check src tests && ruff format --check src tests   # lint + format
mypy                                                    # strict type checking
pytest --cov                                            # unit + integration tests
```

Integration tests drive a real PKCS#11 module (SoftHSM2) end to end — HTTP → token → signed PDF
validated by pyHanko. They are skipped automatically when SoftHSM2 is missing:
`brew install softhsm` (macOS) · `sudo apt install softhsm2` (Debian/Ubuntu).

## 6. Packaging

Build on each target OS (PyInstaller does not cross-compile):

```bash
./packaging/build.sh                                       # macOS → dist/Sigil.app, Linux → dist/sigil
powershell -ExecutionPolicy Bypass -File packaging\build.ps1   # Windows → dist\sigil.exe
```

`.github/workflows/ci.yml` runs lint, type-check and tests on Windows/macOS/Linux (Python 3.11 and
3.13, SoftHSM integration on macOS/Linux) and builds all three binaries as downloadable artifacts.
The macOS artifact is Apple Silicon; build Intel Macs on an Intel machine. Binaries are not
code-signed/notarised yet — macOS Gatekeeper and Windows SmartScreen will warn until they are.

## 7. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| health `status: degraded`, `DRIVER_NOT_FOUND` | Token driver not installed, or in a non-standard place → set `pkcs11_module`. |
| `DRIVER_LOAD_FAILED` "architecture" | 32/64-bit or Intel/ARM mismatch between driver and agent. |
| `TOKEN_NOT_FOUND` | Token unplugged, or blank (uninitialised) token. Re-insert, check `diagnose`. |
| `ORIGIN_NOT_ALLOWED` (403) | Add your web system's exact origin to `allowed_origins`. |
| `PIN_INCORRECT` with `final_try: true` | One attempt left — stop and verify the PIN before retrying. |
| `PIN_LOCKED` (423) | Unblock the PIN with the vendor's token manager (needs the SO/PUK). |
| Browser blocks calls from an HTTPS page | Chrome/Edge/Firefox allow `http://127.0.0.1`; for others enable TLS (`ssl_certfile`/`ssl_keyfile`, e.g. via mkcert). Chrome may also show a "local network access" permission prompt — allow it. |
| Visible stamp shows boxes instead of Arabic names | The built-in stamp font is Latin-only; use an invisible signature or Latin stamp text for now. |

## Project layout

```
src/sigil/
  domain/          value objects, errors, policies, ports (pure Python)
  application/     use cases: TokenService, SigningService
  infrastructure/  python-pkcs11 gateway, pyHanko engines, config, logging
  api/             FastAPI routes, DTOs, security middleware, error mapping
  desktop/         CLI, uvicorn runner, tray icon, start-at-login
  container.py     composition root
tests/unit/        fast tests with fakes · tests/integration/  SoftHSM2 end-to-end
packaging/         PyInstaller spec + build scripts
```
