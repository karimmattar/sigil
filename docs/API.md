# Sigil API — v1

For developers of the web system that calls the agent from the browser.

* Base URL: `http://127.0.0.1:8765/api/v1` (port/TLS configurable). Interactive docs: `http://127.0.0.1:8765/docs`.
* Only origins listed in the agent's `allowed_origins` may call it (others get `403 ORIGIN_NOT_ALLOWED`).
* The PIN is sent with each signing request, used for one token login, and never stored or logged.
* Every error has the same shape — **switch on `error.code`, not on the message**:

```json
{ "error": { "code": "PIN_INCORRECT", "message": "The PIN is incorrect. Only ONE attempt is left before the token locks.",
             "details": { "count_low": true, "final_try": true, "locked": false } } }
```

## Recommended flow in the web UI

1. `GET /health` → if the request fails, the agent is not running/installed: show a download link.
   If `status` is `"degraded"`, show `driver.error` (token driver missing).
2. `GET /tokens` → none: "plug in your token". Several: let the user pick (`serial`).
   Warn when `pin_status.final_try` is true; block when `pin_status.locked` is true.
3. Optional: `GET /tokens/{serial}/certificates` to show who will sign / let the user choose (`cert_id`).
   Without `cert_id` the agent picks the valid signing certificate itself.
4. Ask for the PIN, call `POST /sign/pdf` or `POST /sign/data`, clear the PIN from memory afterwards.
5. On `PIN_INCORRECT`, show `message` (it includes the remaining-tries warning) and **do not retry automatically**.

## Endpoints

### `GET /health`

Always `200` while the agent runs.

```json
{
  "service": "sigil", "version": "1.0.0", "status": "ok",
  "platform": { "system": "Windows", "release": "11", "machine": "AMD64", "python": "3.13.9 (64-bit)" },
  "driver": { "loaded": true, "module_path": "C:\\Windows\\System32\\eps2003csp11.dll",
              "manufacturer": "Feitian Technologies Co., Ltd.", "description": "…", "library_version": "1.20",
              "error_code": null, "error": null, "searched": ["…"] },
  "features": { "timestamp_available": false, "pdf_profiles": ["pades", "pkcs7"],
                "digest_algorithms": ["sha256", "sha384", "sha512"] }
}
```

### `GET /tokens`

```json
{ "tokens": [ { "serial": "2C4B000123", "label": "EgyptTrust", "manufacturer": "Feitian", "model": "ePass2003",
                "slot_id": 1, "slot_description": "ES SLOT 1",
                "pin_status": { "initialized": true, "count_low": false, "final_try": false, "locked": false,
                                "to_be_changed": false, "protected_authentication_path": false } } ] }
```

### `GET /tokens/{serial}/certificates`

No PIN needed. `has_private_key` may be `null` (unknown) because many tokens hide keys until login.

```json
{ "token_serial": "2C4B000123",
  "certificates": [ { "cert_id": "a1b2c3", "label": "Ahmed Ali", "subject": "Common Name: Ahmed Ali, …",
                      "subject_common_name": "Ahmed Ali", "issuer": "…", "issuer_common_name": "Egypt Trust CA G6",
                      "serial_number": "5f3a…", "not_before": "2025-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
                      "key_usage": ["digital_signature", "non_repudiation"], "is_ca": false,
                      "has_private_key": true, "sha256_fingerprint": "…", "pem": "-----BEGIN CERTIFICATE-----\n…" } ] }
```

### `POST /sign/pdf` — `multipart/form-data`

| Field | Required | Default | Notes |
|---|---|---|---|
| `file` | ✔ | | The PDF |
| `pin` | ✔ | | 4–64 characters |
| `token_serial` | | the only token | Required when several tokens are connected |
| `cert_id` | | auto | Hex id from the certificates endpoint |
| `field_name` | | `SignatureN` | Letters, digits, `_`, `-`, space; must not already be signed |
| `reason`, `location`, `contact_info` | | | ≤ 256 characters each |
| `profile` | | `pades` | `pades` (ETSI.CAdES.detached) or `pkcs7` (adbe.pkcs7.detached) |
| `digest_algorithm` | | `sha256` | `sha256`, `sha384`, `sha512` |
| `timestamp` | | `true` if a TSA is configured | RFC 3161 timestamp |
| `visible` | | `false` | Draw a visible stamp |
| `page` | | `0` | 0-based; `-1` = last page |
| `box` | | `36,36,256,96` | `x1,y1,x2,y2` in points from the bottom-left corner |
| `stamp_text` | | `Digitally signed by %(signer)s\nDate: %(ts)s` | `%(signer)s` and `%(ts)s` are replaced |

Response `200 application/pdf` with headers `X-Signature-Field`, `X-Signer-Certificate-Id`,
`X-Token-Serial` and `Content-Disposition: attachment; filename="signed_…"` (readable from JS).
Signing a PDF that is already signed adds a new signature and keeps the earlier ones valid.

### `POST /sign/data` — JSON

```json
{ "pin": "12345678", "data_base64": "eyJpbnZvaWNlIjoxfQ==",
  "token_serial": null, "cert_id": null,
  "detached": true, "cades": true, "digest_algorithm": "sha256", "timestamp": null }
```

```json
{ "signature_base64": "MIAGCSqGSIb3DQEHAqCAMIAC…", "signature_format": "CMS", "detached": true,
  "digest_algorithm": "sha256", "token_serial": "2C4B000123", "certificate": { "cert_id": "a1b2c3", "…": "…" } }
```

`signature_base64` is a DER CMS `ContentInfo` (SignedData). `cades: true` adds the
CAdES-BES `signing-certificate-v2` attribute. Integrators of external systems (e.g. e-invoice
portals) must canonicalise the payload exactly as that system requires *before* base64-encoding it,
and should check the produced signature against that system's validator.

## Browser examples

```js
const AGENT = "http://127.0.0.1:8765/api/v1";

async function agent(path, init) {
  let response;
  try {
    response = await fetch(AGENT + path, init);
  } catch {
    throw { code: "AGENT_UNREACHABLE", message: "Sigil is not running on this computer." };
  }
  if (!response.ok) throw (await response.json()).error;   // { code, message, details }
  return response;
}

const health = await (await agent("/health")).json();
const { tokens } = await (await agent("/tokens")).json();

// Sign a PDF
async function signPdf(pdfBlob, pin, { tokenSerial, certId, visible } = {}) {
  const form = new FormData();
  form.append("file", pdfBlob, "contract.pdf");
  form.append("pin", pin);
  if (tokenSerial) form.append("token_serial", tokenSerial);
  if (certId) form.append("cert_id", certId);
  if (visible) { form.append("visible", "true"); form.append("page", "-1"); }
  form.append("reason", "Approved");
  const response = await agent("/sign/pdf", { method: "POST", body: form });
  return { pdf: await response.blob(), field: response.headers.get("X-Signature-Field") };
}

// Sign arbitrary data (CMS / CAdES)
async function signData(text, pin) {
  const bytes = new TextEncoder().encode(text);
  const data_base64 = btoa(String.fromCharCode(...bytes));
  const response = await agent("/sign/data", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pin, data_base64 }),
  });
  return (await response.json()).signature_base64;
}

try {
  await signPdf(file, pinInput.value);
} catch (err) {
  if (err.code === "PIN_INCORRECT" && err.details.final_try) showWarning(err.message);
  else showError(err.message);
} finally {
  pinInput.value = "";
}
```

## Error codes

| HTTP | `code` | Meaning / what the UI should do |
|---|---|---|
| 401 | `PIN_INCORRECT` | Wrong PIN. `details.count_low/final_try/locked` tell how close the token is to locking. |
| 403 | `ORIGIN_NOT_ALLOWED` | This website is not in `allowed_origins`. |
| 403 | `HOST_NOT_ALLOWED` | Request did not target localhost (DNS-rebinding protection). |
| 404 | `TOKEN_NOT_FOUND` | No (matching) token connected. |
| 404 | `CERTIFICATE_NOT_FOUND` | No usable signing certificate / unknown `cert_id`. `details` lists what is on the token. |
| 404 | `NOT_FOUND` | Unknown URL. |
| 405 | `METHOD_NOT_ALLOWED` | Wrong HTTP method. |
| 409 | `TOKEN_AMBIGUOUS` | Several tokens — send `token_serial` (`details.available_serials`). |
| 409 | `CERTIFICATE_AMBIGUOUS` | Several signing certificates — send `cert_id` (`details.candidates`). |
| 409 | `CERTIFICATE_NOT_USABLE` | Chosen certificate expired / not yet valid / not for signing. |
| 409 | `TOKEN_BUSY` | Another signature is running (or another app holds the token). Retry shortly. |
| 409 | `TOKEN_REMOVED` | Token unplugged during the operation. |
| 409 | `FIELD_ALREADY_SIGNED` | `field_name` already holds a signature. |
| 413 | `PAYLOAD_TOO_LARGE` | Larger than `max_upload_mb`. |
| 422 | `PIN_INVALID` | PIN length/format invalid or expired — the token was **not** tried. |
| 422 | `INVALID_REQUEST` | Bad option (box, page, cert_id format, timestamp without TSA, base64…). |
| 422 | `INVALID_DOCUMENT` | Not a PDF, corrupt, or password-protected. |
| 422 | `VALIDATION_ERROR` | Missing/invalid fields (`details.errors[].field`). Input values are never echoed. |
| 423 | `PIN_LOCKED` | PIN blocked — unblock with the vendor's token manager. |
| 500 | `SIGNING_FAILED` | Token rejected the operation (e.g. unsupported mechanism). |
| 500 | `INTERNAL_ERROR` | Bug — quote `details.correlation_id`; details are in the agent log. |
| 502 | `TIMESTAMP_FAILED` | TSA unreachable or returned an error. |
| 503 | `DRIVER_NOT_FOUND` / `DRIVER_LOAD_FAILED` | Token driver missing or incompatible. |
