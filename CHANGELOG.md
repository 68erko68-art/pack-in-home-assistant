# Changelog

## 0.1.1 — legacy compatibility preview

- Connect existing legacy Packs without resetting data, changing encryption keys or advancing their sync epoch.
- Send legacy actions through a scoped gateway with atomic concurrency checks and durable retry identities.
- Preserve saved state and pending actions when a legacy connection encounters an unexpected mode or epoch change.
- Household installation, phone approval and real-data acceptance remain separate verification steps.

## 0.1.0-beta.1 — unreleased development preview

- Password-free phone-approved connection with device-bound credentials and explicit Pack permissions.
- Tink-compatible local encrypted synchronization, ordered replay, atomic snapshots and durable actions.
- Native task/grocery to-do lists, read-only recurring calendar, consented GPS trackers and status entities.
- Shared batched Find Me cadence and local diagnostics.
- Production activation and live installation acceptance remain pending.
