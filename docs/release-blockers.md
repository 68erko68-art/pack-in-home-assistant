# Release acceptance status

The Pack-In integration is implemented as a custom Home Assistant integration. The checks below govern versioned public HACS releases.

## Evidence already retained

- An approved Home Assistant connection has decrypted real groceries and chores. A grocery created in Home Assistant reached the Pack-In phone app, and the temporary test item was removed.
- The same connection and dashboard survived a normal Home Assistant Core restart without recreating pairing or keys.
- Legacy Pack compatibility and the startup fix are present in the candidate. Connecting a home preserves the Pack's authority, encryption keys and synchronization epoch.
- The candidate fixes stale reconnect backoff after a connection lasts more than five minutes. Four new timing regressions reproduced the original failure. All 167 local pure tests pass, including unchanged server cooldowns and pending-action preservation.
- Native Linux tests passed on amd64 and ARM64 using the helper built from the exact official Home Assistant 2026.11.0 source: 178 cases per architecture, including real integration reload checks for legacy and v3 Packs. Reload retained the entry, credentials, keys, pending actions and entity identities without a new pairing request. Evidence: https://github.com/68erko68-art/pack-in-home-assistant/actions/runs/42029158659
- The current private installation has an encrypted configuration backup and an independently retained protected recovery key. This is recovery preparation, not a completed restore test.

These results apply to the recorded installation and exact tested source. Source-built helper tests supplement the official-package release checks. They do not establish all-user acceptance, a full process restart on the candidate, or a completed HACS upgrade.

## Remaining release gates

- Use the supported matching stable Home Assistant and test-helper releases. The prepared test toolchain pins pytest-homeassistant==2026.11.0, which requires Home Assistant 2026.11.0. The official helper was published on November 5, 2026 after the upstream upload configuration was repaired.
- Keep the strict full-environment dependency audit. Home Assistant 2026.10.4 pins Pillow 12.3.0; the old test toolchain remains unsuitable for that gate. Do not override Home Assistant's dependency pins or waive the failed audit.
- Run the existing native Home Assistant tests with the official packages on both amd64 and ARM64, require pip check in the test and audit environments, and pass the existing HACS, hassfest, lint, secret and strict dependency checks on the final candidate.
- Publish a versioned GitHub release from the qualified commit and update the repository's default branch to the corrected source. The default branch and tagged release must both resolve to qualified source so an ordinary redownload cannot restore older code.
- Verify the normal HACS upgrade path installs the exact qualified runtime and preserves the configuration entry, Pack association, keys, entity identities and pending actions.
- Complete the remaining real-account, privacy and recovery cases in [ACCEPTANCE.md](ACCEPTANCE.md) before claiming v1.0.0 production readiness. Local tests and one successful household connection do not replace those cases.

Record official-package qualification, publication and normal HACS upgrade evidence separately. A passing development test does not establish public delivery.

Upstream publication issue: https://github.com/home-assistant/core/issues/190470
