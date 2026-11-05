# Release acceptance status

The Pack-In integration is implemented. Qualification of the versioned public HACS release is still in progress.

## Evidence already retained

- An approved Home Assistant connection has decrypted real groceries and chores. A grocery created in Home Assistant reached the Pack-In phone app, and the temporary test item was removed.
- The same connection and dashboard survived a normal Home Assistant Core restart without recreating pairing or keys.
- Legacy Pack compatibility and the startup fix are present in the candidate. Connecting a home preserves the Pack's authority, encryption keys and synchronization epoch.
- The candidate fixes stale reconnect backoff after a connection lasts more than five minutes. Four new timing regressions reproduced the original failure. All 167 local pure tests pass, including unchanged server cooldowns and pending-action preservation.
- The current private installation has an encrypted configuration backup and an independently retained protected recovery key. This is recovery preparation, not a completed restore test.

These results apply to the recorded installation and exact tested source. They do not establish all-user acceptance or the complete native Home Assistant lifecycle suite.

## Remaining release gates

- Use the supported matching stable Home Assistant and test-helper releases. The prepared test toolchain pins pytest-homeassistant==2026.11.0, which requires Home Assistant 2026.11.0. Its official PyPI release is currently unavailable following an upstream upload failure.
- Keep the strict full-environment dependency audit. Home Assistant 2026.10.4 pins Pillow 12.3.0; the old test toolchain remains unsuitable for that gate. Do not override Home Assistant's dependency pins or waive the failed audit.
- Run the existing native Home Assistant tests on both amd64 and ARM64, and pass the existing HACS, hassfest, lint, secret and dependency checks on the final candidate.
- Publish a versioned GitHub release from the qualified commit and update the repository's default branch to the corrected source. HACS currently has no published release to select and can download older default-branch source.
- Verify the normal HACS upgrade path installs the exact qualified runtime and preserves the configuration entry, Pack association, keys, entity identities and pending actions.
- Complete the remaining real-account, privacy and recovery cases in [ACCEPTANCE.md](ACCEPTANCE.md) before claiming v1.0.0 production readiness. Local tests and one successful household connection do not replace those cases.

The current local checks are not a public release, a verified HACS upgrade or full native Home Assistant qualification.

Upstream publication issue: https://github.com/home-assistant/core/issues/190470
