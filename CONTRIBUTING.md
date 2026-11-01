# Contributing

Use a separate branch and a pull request. Run the Python, HA, lint, manifest, HACS, Hassfest and secret checks.
Keep one client per Pack and all entity reads local. Do not add short-interval polling or per-member GPS requests.
Preserve unknown item metadata, canonical IDs, idempotency and assignment permissions.

Tests use synthetic identities and loopback servers only. Never commit real credentials, wrapped Pack keys, user data or production logs.
Changes to wire formats need cross-language vectors and backward-compatibility tests.
Only Pack-In's private controlled workflows may change or deploy its Android app/backend; those sources do not belong in this repository.

Use semantic prereleases until live household acceptance passes. Public CI is useful evidence, not a substitute for real-account tests.
