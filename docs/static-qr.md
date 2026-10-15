# Static QR credential format

The QR image contains the compact JWT itself, without a URL prefix or personal
fields. It is a reusable bearer credential: a copy or screenshot remains usable
until it expires or its online credential mapping is revoked. It does not prove
that the holder is the original account owner, is physically present, or is a
live person. Applications needing those guarantees require a separate check or
challenge protocol.

## Signed token

`QRIssuer` signs with the active Ed25519 key whose purpose is `qr`. The protected
header contains exactly `alg: EdDSA`, `typ: argus-qr+jwt`, and `kid`. Key IDs must
be 1–128 ASCII letters, digits, underscores, or hyphens. QR keys are separate from
SSO keys and are not exposed by the OIDC JWKS endpoint.

The payload contains exactly these claims:

| Claim | Value |
| --- | --- |
| `ver` | Integer `1` |
| `purpose` | `static_qr` |
| `iss` | Configured issuer URL |
| `aud` | `argus-qr-verifier` |
| `cid` | Random 256-bit credential identifier, canonical unpadded base64url |
| `iat` | Integer issuance time, Unix seconds |
| `exp` | Integer expiration time, Unix seconds |

No user ID, name, email, school identifier, or student eligibility is embedded.
`cid` is an opaque lookup reference; possession of a correctly signed token alone
does not authorize a user lookup or establish current eligibility. The online
service must also enforce its stored credential mapping, revocation state, user
state, and caller authorization.

The default lifetime is 600 seconds. `QR_TOKEN_TTL_SECONDS` accepts integers from
1 through 3600; this maximum matches the signing-key public-key retention period.
Rotation keeps the previous QR public key available for validation; retiring or
removing that key prevents further validation of tokens signed with it. The
issuer must be an ASCII HTTPS URL (loopback HTTP is allowed), at most 256
characters, without credentials, query, fragment, quotes, or backslashes. Use
IDNA for internationalized hosts and percent-encode non-ASCII path characters.

## Encoding and validation boundaries

`encode_png` emits a standard QR Code using byte mode, ASCII text, error
correction level M, four modules of quiet zone on every side, and four pixels per
module. It supports QR versions up to 26 and rejects compact tokens over 1024
ASCII bytes. The maximum supported issuer length, 128-character key ID, and
3600-second lifetime are covered by a PNG-to-ZXing round-trip test.

The encoder checks compact-token structure, canonical unpadded base64url, a
64-byte signature, exact header and claim fields, and their types. It rejects
duplicate JSON members, non-standard JSON numeric constants, malformed UTF-8,
extra claims, and unexpected algorithms or token types. These checks do **not**
verify a signature: an attacker can construct a well-formed image, so scanning
software must never treat successful image decoding as authentication.

`QRValidator.validate` selects only a locally trusted public key scoped to `qr`,
verifies Ed25519 signatures, and checks the expected issuer, audience, token
type, purpose, schema version, issuance time, expiration, and maximum lifetime.
It never follows URLs or accepts public keys supplied inside a token. SSO access
tokens and ID tokens cannot be used as QR credentials, and QR credentials cannot
be used as SSO tokens. Invalid credentials raise `QRValidationError` without
including token data. Key-provider failures remain `KeyManagementError` so the
API can distinguish an unavailable verifier from invalid user input.

QR payloads, PNG responses, and decoded token strings must be treated as secrets:
avoid logging them, sharing screenshots, or caching responses outside the
authenticated user's control. A static credential is intentionally not a
single-use token; replay protection is a separate application decision.
