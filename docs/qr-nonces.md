# QR verification request nonces

`qr.nonces` deduplicates a verification request within a trusted client scope.
It does not validate QR credentials, authorize callers, or decide eligibility.
The verification API must authenticate the caller before using its stable client
ID as `client_id`; accepting a client ID chosen by an unauthenticated caller
would allow that caller to bypass the intended scope.

## Generation and format

The trusted verification requester generates a fresh nonce with
`generate_nonce()` for each new request, or the server can issue it. The nonce is
`v1.<unix_seconds>.<random>`, where `random` is 32 cryptographically random bytes
encoded as canonical unpadded base64url (43 characters). Timestamps are canonical
nonnegative decimal integers; the complete value is at most 64 ASCII characters.
Nonce timestamps are not signed. Authentication of the trusted requester remains
a separate API requirement.

`NonceSettings()` defaults to 300 seconds and accepts integers from 1 through
600. `NonceSettings.from_environment()` reads `QR_NONCE_TTL_SECONDS`; a configured
API should construct settings once and pass them into the consumer. All verifier
workers for the same namespace must use the same TTL. Clocks on requesters and
verifiers must be synchronized: there is no future timestamp allowance. With
`now = int(time.time())`, a nonce is fresh exactly when:

```text
now - ttl < issued_at <= now
```

The lower boundary is exclusive. An expired nonce stays invalid even after its
Redis key disappears. The maximum valid time resolution is one Unix second.

## Atomic client scope

```python
from qr.nonces import NonceSettings, consume_nonce

await consume_nonce(
    redis_client,
    client_id=authenticated_client_id,
    nonce=request_nonce,
    settings=NonceSettings.from_environment(),
)
```

The default namespace is `qr-static-verify:v1`. The Redis key is
`<namespace>:<sha256(client_id)>:<sha256(nonce)>`; its value is the constant `1`.
Neither the key nor its value stores a QR token, a raw nonce, or the raw client
identifier. Client IDs must contain 1–256 characters without surrounding
whitespace. Custom namespaces use 1–64 ASCII letters, digits, colons, periods,
underscores, or hyphens and must be controlled by the service.

One atomic `SET key 1 NX EX remaining_seconds` reserves the nonce, where
`remaining_seconds = issued_at + ttl - now`. Only a confirmed Redis success
accepts the request; simultaneous requests for the same namespace, client, and
nonce have at most one success while the key is retained. Different clients may
consume the same nonce independently. The QR token does not participate in the
key, so switching QR credentials does not reset a nonce already used by the same
client. Do not use a caller-selected namespace to bypass deduplication.

## Errors and operational limits

| Result | Exception |
| --- | --- |
| Malformed, expired, future nonce, or invalid scope | `NonceValidationError` |
| Redis reports that the scoped key already exists | `NonceReplayError` (subclass of `NonceValidationError`) |
| Redis error or unrecognized/ambiguous response | `NonceStoreUnavailable` |

Exception messages omit nonces, QR tokens, and connection details. Redis
unavailability fails closed: the API must refuse the request instead of treating
the lack of a successful reservation as authorization. A lost response can mean
that Redis committed the reservation; the consumer does not retry acceptance or
delete the key. A later failure in QR verification or response delivery does not
undo the reservation. The caller must start a new request with a fresh nonce.

This is bounded request deduplication, not durable exactly-once processing. Redis
eviction, a restart without retained data, or failover losing recent writes can
remove a reservation while its nonce is still fresh; that nonce can then be
accepted again. Configure capacity, an appropriate no-eviction policy, and Redis
availability/persistence for the deployment's requirements. Connection-failure
handling alone does not preserve state lost by Redis. Cross-service transactions
or durable business idempotency require a separate design.

Nonce deduplication **cannot prevent copying a static QR and submitting it with
a fresh nonce**. It does not establish a live person, physical presence, or
single-use QR semantics and does not implement a dynamic QR blacklist.

## Verification

Run `python -m pytest tests/test_qr_nonces.py -q`. Set
`TEST_QR_NONCE_REDIS_URL` to a dedicated Redis instance to include the real Redis
test: 100 concurrent consumers, exactly one acceptance, client isolation,
remaining TTL, actual key expiration, and rejection of expired nonces after key
removal. That test only deletes keys in a fresh randomly named test namespace.
