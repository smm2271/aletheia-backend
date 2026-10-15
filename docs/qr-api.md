# Static QR credential issuance

`POST /api/v1/qr/credentials` obtains a credential for the current browser user.
Send the `aletheia_session` cookie and an `Origin` header exactly equal to
`SESSION_PUBLIC_ORIGIN`. Omit the request body or send `{}`. Query parameters and
extra JSON properties are rejected; callers cannot select another user. An SSO
access token alone does not authenticate this endpoint.

The JSON response contains `token`, `credential_id`, `format_version`, `issued_at`
and `expires_at`. Dates are UTC timestamps. `format_version` is currently `1`.
The response uses `Cache-Control: no-store` and `Pragma: no-cache`. The signed
token is a bearer credential: a copied image can be replayed until expiry.
Do not place the token in URLs, application logs, analytics, or error reports.

## Lifetime and persistence

Issuance locks the user row and rechecks that the user still exists and is enabled.
The database stores one current credential per user, with a unique random
credential ID. Concurrent first requests and concurrent renewal requests share
the resulting credential. While the stored credential is valid, requests return
the exact same signed token and timestamps, including after signing-key rotation.
At expiry, the mapping is replaced with a new credential ID and token. There is no
client-controlled refresh or force-reissue option.

The database deliberately stores the complete signed bearer token to preserve
this exact response across key rotations. Protect database access and backups
accordingly. The mapping includes the user ID; the token payload does not contain
the user ID, email, name, or student details. Its credential ID is pseudonymous,
and repeat presentation remains linkable during its lifetime.

`QR_TOKEN_TTL_SECONDS` defaults to 600 and must be between 1 and 3600 seconds.
The QR signing purpose uses its own Ed25519 key. Retired verification keys must
remain available for outstanding token lifetimes. A valid existing row whose
token or timestamps no longer validate returns 409 until its stored expiry,
instead of allowing repeated issuance. Key-provider or database failures return
503 without disclosing configuration or connection details.

## Error responses

| Status | Meaning |
| --- | --- |
| 400 | Query parameters are unsupported. |
| 401 | Browser session is missing/expired, or the user is deleted/disabled. |
| 403 | Origin is absent or differs from the configured origin. |
| 409 | The current unexpired mapping cannot be validated; wait until expiry. |
| 422 | Request body fails validation, including extra JSON properties. |
| 503 | QR issuance, signing keys, session store, or credential database is unavailable. |

The endpoint is described in `/openapi.json`. Authentication and issuance errors
use `{"detail": "..."}`; request-validation errors use FastAPI's validation-error
schema. Error precedence can depend on authentication and request validation.

## Verification boundary

`QRValidator.validate()` checks token format, signature, purpose, issuer, audience,
and lifetime. It does not query the credential mapping, user status, student
eligibility, or admission rules. This issuance API does not authorize entry.

Deleting a user cascades to the stored credential, and disabled users cannot
obtain credentials. A future online scanning API must check the current mapping
and user state to reject deleted, disabled, or replaced credentials. An offline
copy may still pass cryptographic validation within its signed lifetime: database
changes do not provide immediate offline revocation.
