# HIAD: Know Your Data — Discover, Classify and Protect Sensitive Information with Microsoft Purview

Hack in a Day challenge lab. Four challenges building a Microsoft Purview information
protection baseline from an empty tenant: discovering sensitive data, creating and publishing
sensitivity labels with auto-labelling in simulation, Data Loss Prevention including a
device-scoped policy for third-party AI apps, and configuring insider risk detection for
departing users.

Nothing is pre-seeded. Attendees build the whole configuration themselves and generate the
evidence they then interpret. Security Copilot in Microsoft Purview is not provisioned in this
environment and no challenge depends on it.

- Lab guide: maintained in `CloudLabsAI-Azure/hack-in-a-day-challenges` under
  `security/purview-know-your-data-learner-built/`. That is the copy the CloudLabs Guide tab
  serves. Both `masterdoc.json` files here point to it; edit the guide there, not in this repo.
- Validations: `Validations/`, tested against a live tenant on 29 Sep 2026.

Deployment assets (ARM, parameters, bootstrap) are hosted separately in blob storage.
