# Online static QR verification

`POST /api/v1/qr/static/verify` accepts `{"token": "<signed QR token>"}`.
The body accepts no extra properties, the token must contain 1–1024 characters,
and query parameters are rejected. Responses use `Cache-Control: no-store`.
Validation errors do not echo submitted credentials.

The scanner must send `Authorization: Bearer <SSO Access Token>`. The server fixes
the expected resource audience to `SSO_ACCESS_AUDIENCE`, verifies the token's
signature, issuer, lifetime and Access Token purpose, and requires the exact
`qr:static:verify` scope. This scope is advertised in OIDC Discovery. A browser
session cookie, OIDC ID Token, or QR token cannot authenticate the scanner.
Registration of this scope for an SSO client is an administrative grant; it is
not granted automatically to all clients.

Each call rechecks that the scanner user exists and is enabled, and that the
client exists, is enabled and currently permits `qr:static:verify`. An earlier
Access Token does not override a later client disable or scope removal.

The QR token must pass the dedicated QR format, Ed25519 signature, key purpose,
key ID, issuer, audience and lifetime checks. The server then resolves its random
credential ID against the current database mapping. The stored token must match
using a constant-time comparison, the issue/expiry timestamps must match exactly,
the database expiry must still be in the future, and the scanned user must exist
and be enabled. Deleted, replaced, corrupted or disabled-user credentials all
produce the same error. The successful response is only `{"valid": true}`;
it discloses no credential ID, user ID, profile or eligibility.

| Status | Meaning |
| --- | --- |
| 200 | The credential currently passes cryptographic and online mapping checks. |
| 400 | Invalid QR credential, or unsupported query parameters. |
| 401 | Scanner Access Token is missing/invalid, or scanner/client is no longer enabled. |
| 403 | Access Token scope is missing, or the client no longer permits that scope. |
| 422 | Invalid request body; credential input is not reflected. |
| 503 | Signing keys, configuration or database is unavailable. |

Error responses contain only a generic `detail` string. Authentication errors
also include the appropriate `WWW-Authenticate: Bearer` challenge. Neither QR
tokens nor scanner Access Tokens should be placed in URLs or logs.

This endpoint verifies a credential; it does not authorize admission or establish
student eligibility. Offline signature validation cannot immediately observe
database changes. This implementation does not yet consume a one-time request
nonce: replay prevention belongs to the subsequent nonce integration.
