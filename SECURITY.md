# Security

Report suspected vulnerabilities privately using this repository's GitHub **Report a vulnerability** feature.
Do not post account information, locations, tokens, keys or decrypted Pack data in public issues.
If private reporting is unavailable, use Pack-In's support contact published at https://www.pack-in.app/.

## Trust boundaries

The authenticated phone approves one device identity, one Pack and explicit scopes.
Pairing codes expire after five minutes; the high-entropy device secret and device proof are required to claim credentials.
HA HTTP requests bind method, exact path, body digest, time, nonce and credential digest to a Tink-compatible P-256 signature.
The server rejects reused proofs, expired/revoked credentials, wrong Pack membership and missing Premium entitlement.
Credentials rotate, and a retry of a lost renewal response must match the same saved renewal intent.

Encrypted event envelopes bind Pack, event ID, sender device, device sequence, type and key epoch.
Signatures are verified before AES-GCM decryption. Wrapped Pack keys use the existing Tink ECIES format.
The integration does not upload plaintext task, calendar, grocery or location content to Cloudflare.

One shared Pack key underlies existing encrypted categories. API scopes restrict which encrypted categories the HA device receives;
they do not create separate cryptographic category keys. A previously disclosed key or plaintext cannot be retroactively forgotten.
Pack key rotation, membership removal and server-side device revocation remain separate controls.

## Household privacy

Each member's location permission is independent and defaults off.
A Pack administrator can revoke a home but cannot opt another person into sharing.
Home Assistant actions run as the linking Pack member and retain normal assignment restrictions.
HA administrators, filesystem owners, backups, Recorder and other integrations are inside the local trust boundary.
No claim of protection from the HA administrator is made.

## Safe diagnostics and development

Never log HTTP authorization headers, private keys, refresh credentials, encrypted key material, decrypted payloads or coordinates.
Diagnostics are explicit allowlists. Test fixtures contain only synthetic identities.
Production endpoints use fixed HTTPS/WSS origins with redirects disabled. Loopback overrides are test-only literal addresses.
No remote debugging endpoint or unauthenticated private-data API is provided.

Development preview status is not a security certification or a claim of perfect protection.
A production release requires all security and live acceptance gates in docs/ACCEPTANCE.md.
