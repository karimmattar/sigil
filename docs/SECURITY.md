# Security & audit report

Audience: the team owning the web system and the people who deploy the agent to users' machines.

## 1. Threat model

The agent runs on the user's computer and holds the door to a legally binding signing key.

| Actor | Can | Must not be able to |
|---|---|---|
| Your web system (allow-listed origin) | Ask the user for the PIN and request signatures | — |
| **Any other website** the user visits | Make the browser send requests to `127.0.0.1` | Trigger PIN attempts (could lock the token), read token data, obtain signatures |
| A website using DNS rebinding | Make its own hostname resolve to `127.0.0.1` | Talk to the agent |
| Other programs of the same user | Everything the user can do (same privileges) | — (out of scope: they could load the driver themselves) |
| Network attackers | — | Reach the agent (it listens on loopback only) |

## 2. Audit of the original single-file agent

Each finding was reproduced against the installed libraries (pyHanko 0.38.2, python-pkcs11 0.9.5)
and, where a token was needed, SoftHSM2 2.7.0.

| # | Severity | Finding | Evidence | Status |
|---|---|---|---|---|
| 1 | **Critical** | `/sign-pdf` could never succeed: an `async def` endpoint called pyHanko's synchronous `sign_pdf`, which runs `asyncio.run()` inside the server's event loop. | `RuntimeError: asyncio.run() cannot be called from a running event loop` | Fixed — sync handlers in worker threads + `_run_sync`; regression test. |
| 2 | — | *Withdrawn.* The plan suspected per-request library loading would finalise the driver under concurrent requests. python-pkcs11 0.9.5 caches library objects per path, so this does not happen. | `pkcs11/__init__.py` `_loaded` cache; SoftHSM experiment | n/a (the agent still owns one module instance — see §3). |
| 3 | High | No serialisation of token access. The driver is initialised with `C_Initialize(NULL)` (no threading guarantees) and login state is shared per token, so parallel requests could collide. | PKCS#11 `C_Initialize` with `pInitArgs = NULL` (python-pkcs11) | Fixed — one lock around every PKCS#11 call, `TOKEN_BUSY` on timeout; 6 parallel signatures pass on SoftHSM. |
| 4 | High | `slot_no` meant different things: `/tokens` numbered only slots *with* a token, while pyHanko indexes *all* slots. Multi-slot drivers (Feitian exposes several "ES SLOT n") could pick the wrong or an empty slot. | `pyhanko/sign/pkcs11.py` `slots[slot_no]` | Fixed — tokens are addressed by serial. |
| 5 | High | Hard-coded field name `EgyTrustSignature`: a PDF could be signed only once. | `SigningError: Signature field with name EgyTrustSignature appears to be filled already.` | Fixed — next free `SignatureN`, explicit names checked; test signs twice and validates both. |
| 6 | High | Without `cert_label` pyHanko cannot choose a certificate when the token holds more than one (typical: the CA chain is stored too). | SoftHSM: `PKCS11Error: Found more than one certificate.` | Fixed — `CertificateSelectionPolicy` auto-selects or asks (`CERTIFICATE_AMBIGUOUS`). |
| 7 | **High (security)** | CSRF / PIN brute force: `multipart/form-data` POSTs are sent cross-origin without a preflight; the agent processed them. Any website could submit PIN guesses and lock the token. No Host check (DNS rebinding). | A request with `Origin: https://evil.example` and `Host: attacker.com` reached the token-login call with the guessed PIN (login intercepted in the test). | Fixed — server-side Origin allow-list and Host guard before routing; tests. |
| 8 | Medium | Unsanitised upload filename in `Content-Disposition` (header breakage/injection). | code review | Fixed — sanitised ASCII fallback + RFC 6266 `filename*`. |
| 9 | Medium | Unbounded upload size; raw exception text (driver internals) returned to callers; no audit trail. | code review | Fixed — size limit (Content-Length and streamed), stable error codes, correlation ids, `audit.log`. |
| 10 | Low | Placeholder CORS origin, no Private Network Access support, blocking PKCS#11 I/O on the event loop, no tests/config/logging. | code review | Fixed. |

## 3. Controls in the new agent

* **Network exposure** — binds to `127.0.0.1` by default; a loud warning is logged if configured otherwise.
* **Host guard** — only `localhost`, `127.0.0.1`, `::1` Host headers are served (DNS-rebinding defence).
* **Origin guard** — browser requests from origins outside `allowed_origins` are rejected with
  `403` *before* any route runs, including the "simple" multipart POSTs that CORS does not stop.
  `"*"` is refused by configuration validation. Requests without `Origin` (local non-browser
  tools) are accepted — they already have the user's privileges.
* **CORS** — same allow-list; `allow_credentials=false`; Chrome Private Network Access preflight answered.
* **PIN handling** — `Pin` value object masks itself in `repr`/logs; length/format validated
  before the token is touched; never echoed in validation errors; never written to the audit log;
  login refused up-front when the token reports the PIN as locked; retry-counter flags returned
  so the UI can warn before the last attempt.
* **Token access** — one operation at a time; sessions closed (logged out) after every request.
* **Input limits** — request size (`max_upload_mb`), field-name and metadata length limits,
  strict base64, encrypted/corrupt PDFs rejected.
* **Response hardening** — `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, no `Server` header.
* **Errors** — stable codes; unexpected failures return only a correlation id (details in the log).
* **Audit trail** — `audit.log`: time, operation, outcome, token serial, certificate id,
  payload SHA-256 and size, requesting origin.

## 4. Residual risks & recommendations

| Risk | Recommendation |
|---|---|
| An allow-listed origin that gets compromised (XSS) could request signatures once it has the PIN. | Keep `allowed_origins` minimal; strong CSP on the web system. Optional future control: a desktop confirmation dialog per signature (see ARCHITECTURE "Extension recipes"). |
| Lenient PDF parsing (`pdf_strict_parsing = false`) accepts hybrid-xref PDFs (needed for some Word exports); such files can in theory display differently in different viewers. | Documents come from your own backend; set `pdf_strict_parsing = true` if you can guarantee clean PDFs. |
| Unsigned binaries: Windows SmartScreen / macOS Gatekeeper warnings; users can't verify the publisher. | Sign the Windows exe (Authenticode) and sign + notarise the macOS app before distribution. |
| `http://127.0.0.1` from an HTTPS page relies on browsers treating loopback as secure (Chrome, Edge, Firefox do). | Configure `ssl_certfile`/`ssl_keyfile` (e.g. mkcert) where needed. |
| Local programs of the same user can call the agent. | Inherent to any local agent; the PIN still protects the key. |
| Visible stamp font is Latin-only (Arabic names render incorrectly). | Use invisible signatures or Latin stamp text; adding an embedded OpenType font is a planned enhancement. |

## 5. Reporting

Send security issues privately to the agent's maintainers (not in public issue trackers).
Include the agent version (`sigil version`) and, if possible, the `diagnose --json` output
(it contains no secrets).
