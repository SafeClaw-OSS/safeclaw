# SafeClaw Service Catalog

Known service definitions for SafeClaw. This is a **data file** — it is not compiled into the binary and can be updated independently.

## `services.json`

Contains preset configurations for well-known API services:

- **Upstream URL** — where the service lives
- **Auth type** — how credentials are injected (header, query param, OAuth2, path, basic)
- **Default approval levels** — read/write access tiers
- **Category** — grouping for UI display (ai, google, channel, service)
- **Metadata** — display name, color, docs URL, key placeholder

## Usage

**Setup UIs** read this file to offer service presets — users pick a service, enter their API key, and SafeClaw fills in the rest from the catalog.

**CLI tools** (future) can use it for `safeclaw add openai` style quick-setup commands.

**Custom services** not in the catalog can still be added manually with full configuration. The catalog is a convenience, not a constraint.

## Adding a service

Add an entry to `services.json` under `services`, and optionally add it to the relevant category's `priority` array. Submit a PR.
