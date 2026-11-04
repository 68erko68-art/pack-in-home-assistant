# Pack-In for Home Assistant

Native chores, groceries, calendar and consenting member locations, with end-to-end encryption.

**Development preview.** Cloud linking requires a Premium account and approval in the Pack-In phone app.
Version 0.1.1 adds compatibility with existing legacy Packs. Real-household acceptance is still in progress;
no production-ready release is claimed.
The current implementation is being verified against Home Assistant 2026.10.4.
Local protocol tests are not a substitute for installing and testing with real phones and Home Assistant.

## Requirements

- Home Assistant 2026.10 or later, including its supported Python runtime.
- A Pack-In Premium linking account and current Pack membership.
- The Pack-In phone app with **Settings → Connected homes**.
- Outbound HTTPS/WSS access. No router ports, MQTT broker, extra server, API subscription or Home Assistant Cloud subscription.

Other Pack members do not need Premium to appear in an eligible home's authorized household view.
Each member must separately enable sharing their own Find Me location with that home.

## Install with HACS

For a published prerelease:

1. Open HACS → Custom repositories.
2. Add `https://github.com/68erko68-art/pack-in-home-assistant`, category **Integration**.
3. Download Pack-In and restart Home Assistant when prompted.
4. Open Settings → Devices & services → Add integration → Pack-In.
5. Name this home and select read-only access and/or Find Me.
6. In Pack-In on your phone, open Settings → Connected homes, enter the displayed code, select a Pack and review permissions.
7. Return to Home Assistant and submit to finish.

Codes expire after five minutes. No Firebase token, password, API key, YAML or CLI is required.
Connect each Pack separately; one config entry and one synchronization client are allowed per Pack.
This is a HACS **custom repository**, not an entry in its default catalog.

## What appears

| Entity | Behavior |
| --- | --- |
| Your chores | Interactive work assigned to the linking member or to anyone. Ordinary completed tasks can be reopened. |
| Pack chores | Optional read-only whole-Pack view, including completed recurring occurrences. Enable it in the entity registry. |
| Groceries | Add, rename, purchase/unpurchase and delete items. Quantities, grouping, assignment and purchase history are preserved. |
| Calendar | Read-only Pack-In calendar, with all-day events, time zones, recurrence, cancellations and exceptions. |
| Member locations | Native GPS trackers. A member's location remains unavailable until that member explicitly consents. |
| Synchronization | Connection/error status, plus optional timestamps, member summary and pending-action sensors. |
| Refresh locations | One batched request, subject to a 60-second cooldown. |

One eligible assignee completes a multi-assignee task for everyone. Unassigned work may be completed by any writable member.
Being the Pack owner does not permit completing another person's assigned work.
Recurring completion records an occurrence and advances the parent schedule; old occurrences remain read-only history.

The linking account is the actor for Home Assistant actions. Household HA users do not silently impersonate different Pack members.
Do not give untrusted HA users control of this integration.

## Dashboard and automations

Use [the native-card dashboard example](examples/dashboard.yaml) and [automation examples](examples/automations.yaml).
Replace the sample entity IDs with those created in your own entity registry. Renaming a Pack does not change stable unique IDs.
No existing dashboard, zone, person or automation is created or overwritten automatically.

Standard `todo.add_item`, `todo.update_item` and `todo.remove_item` actions work.
Pack-In also exposes `packin.assign_task`, `packin.add_grocery` and `packin.set_quantity`.
Assignment uses current Pack member IDs; an empty list unassigns the task.
Find Me trackers work with normal Home Assistant zones. Stored private Pack-In addresses are not imported as zones.

## Traffic and recovery

Tasks, groceries and calendar share one event-driven WebSocket per Pack.
There is **no periodic full-data polling** for those categories and no network access in entity property getters.
Legacy Packs keep their existing authority, encryption keys and sync epoch. Their signed actions use a scoped
gateway that checks for concurrent native changes; connecting a home never resets the Pack.
Replay resumes from the last verified sequence. A snapshot replaces local state only after its complete digest matches.
An immutable encrypted action is saved before sending; uncertain actions are not rewritten and retried as new actions.

Find Me defaults to one batched request every ten minutes: 144/day or 4,320 per 30-day month, when enabled, connected and at least one member consents.
Options: Disabled, 5, 10, 15, 30 or 60 minutes. Opening more dashboards does not increase that cadence.
Observed location time and retrieval time remain separate. Old positions become unavailable after three intervals, with a 15-minute minimum.
A position is last-known information, not a live GPS stream.

Reconnect delays increase from 5 seconds to a 15-minute maximum, with jitter and server cooldowns.
Revocation, invalid credentials, unsupported schemas or failed integrity checks require attention instead of endless retries.
A new Pack key may require opening Connected homes on the approving phone and sharing pending encryption keys.

## Privacy and local storage

Cloudflare receives encrypted Pack payloads and wrapped keys. Decryption and signing happen locally in Home Assistant.
The local state/outbox cache is AES-GCM encrypted with a separate local cache key.
Device private keys, refresh credentials and that cache key are stored in Home Assistant configuration storage.
**An administrator with access to the HA filesystem or backups can access them and synchronized plaintext.**
The local cache encryption does not protect against that administrator.

The integration does not persist GPS coordinates in its own cache.
Home Assistant Recorder, dashboards, third-party integrations, automations and backups may retain previously exposed data.
Review Recorder exclusions and backup access for your household. Revocation stops future access; it cannot erase previously made copies.

Disable your own location consent in Pack-In to remove active coordinates for this home.
A linking member or Pack administrator may disconnect a home; administrators cannot enable another member's location consent.
Removing the HA integration attempts remote revocation and removes its local cache and configuration entry.
If offline, revoke the connection later from the phone app.

Diagnostics allowlist connection counters and error categories, excluding tokens, keys, item content, member IDs and coordinates.
See [SECURITY.md](SECURITY.md) for the threat model and reporting guidance.

## Status and limitations

- Calendar editing is deliberately unsupported in this version.
- Completed recurring occurrences are history, not independently reopenable tasks.
- Pack-specific metadata is preserved even when HA's native to-do UI cannot edit it.
- A Home Assistant administrator can read the data approved for the home; category scopes are server-enforced.
- Actual HACS installation, real-account round trips, revocation and both supported CPU architectures must pass before a production release.
- Cloud pairing, consent and native app delivery remain subject to Pack-In's controlled backend and Android release workflow.

## Development

Use Python 3.14.2 or later on Linux:

```sh
python -m pip install -r requirements-test.txt
python -m pytest tests
python -m ruff check .
python -m ruff format --check .
```

Pure protocol tests use synthetic identities and local loopback servers. HA tests load the real Home Assistant test framework.
CI checks both amd64 and ARM64; repository validation is distinct from live product acceptance.
See [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md) and [release acceptance](docs/ACCEPTANCE.md).
