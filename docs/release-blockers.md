# Release acceptance blockers

This repository is a source preview. Cloud linking is disabled in production.

- Only verified Pack Sync V3 Packs are currently supported. Older Packs are refused before approval; the integration does not silently migrate, empty or reset household data. A general non-destructive migration remains a release requirement.
- Home Assistant 2026.10.4 pins Pillow 12.3.0. The full environment audit reports published advisories fixed in Pillow 13.0.0. Pack-In adds no image-processing dependency and does not override Home Assistant's pins. The failing dependency gate is retained until a supported remedy is verified.
- Real phone approval, two-member consent/revocation, live Home Assistant installation and production traffic measurements remain acceptance gates.
- Android source qualification passed for the exact candidate 0d5472517402d37be5a60ac4253bf2d327ccdd6c (1052 tests). No signed app update or backend activation is claimed by that result.

Pillow release notes: https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html
Home Assistant constraints: https://github.com/home-assistant/core/blob/2026.10.4/homeassistant/package_constraints.txt
