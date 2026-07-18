# Vault: sealed under your passkey

The vault is where credentials live. Its defining property: **plaintext
exists in exactly one place**, the daemon's memory on your machine, and only
while the vault is unlocked.

## No password, by construction

A vault is sealed under a key derived from your passkey (WebAuthn: Touch ID,
Windows Hello, a security key). There is no master password to invent, reuse,
phish, or forget. The passkey that seals the vault is the same one that signs
approvals later, so the root of trust is a single physical gesture.

## What's inside

- **Secrets**: a flat pool of `KEY = value` pairs. A secret on its own is
  inert storage; it becomes spendable only when a
  [connection](connections.md) claims it.
- **Connections**: the bindings that turn secrets into phantoms, each
  anchored to its service's hosts.
- **Policy**: your per-connection decisions and overrides
  ([Approvals & policy](approvals.md)).

## Lifecycle

```bash
sc up       # daemon up + vault unlocked: one passkey tap, idempotent
sc lock     # wipe decrypted state from memory
sc status   # which vault, locked or not, daemon health
```

On disk, yours or the cloud's, the vault only ever exists sealed. `sc lock`
(or stopping the daemon) ends the plaintext's life entirely.

## Backup and multi-device

The cloud stores the sealed vault for backup and syncs it across your
machines per item, so two devices editing different entries don't clobber
each other. The cloud cannot read what it syncs: sealing and unsealing happen
on your devices only. Pairing a new machine is `sc login` plus a passkey
approval; unpairing revokes that device's standing cloud-side too.

## Multiple vaults

One account can hold several vaults (work and personal, say). The daemon
hosts all of them at once; which vault a request touches is named in the
request itself, not global daemon state. Your CLI's active vault comes from
`sc vault use`, and an agent's env can never redirect it.

## The honest edge case

Lose every enrolled passkey and the vault stays sealed forever; nobody,
including SafeClaw, can decrypt it. That is the price of the cloud being
unable to read your keys. Enroll a backup passkey (your vault's Passkeys tab)
on day one.
