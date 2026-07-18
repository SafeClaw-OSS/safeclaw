# Security model: where your keys actually live

Straight answers to the questions that decide whether you trust a credential
broker. The cryptographic detail behind each one is in
[PROTOCOL.md](https://github.com/SafeClaw-OSS/safeclaw/blob/main/design/protocol.md).

## Where is the plaintext?

In exactly one place: the daemon's memory on your machine, while the vault is
unlocked. On disk (yours and ours) the vault exists only as a blob sealed
under a key derived from your passkey. `sc lock` wipes the decrypted copy from
memory; so does stopping the daemon.

## What does the cloud store?

The sealed vault blob (for backup and cross-device sync), your device and
agent registrations, and approval/audit metadata. It cannot decrypt the blob:
sealing and unsealing happen on your devices. Credential values you add in the
web console are encrypted in your browser before upload; values you enter at
the CLI never leave your machine at all.

## So a breach of your servers leaks my keys?

It leaks sealed blobs. Without a passkey tap on one of your enrolled
authenticators, they stay sealed. That is also the honest cost of the design:
lose every enrolled passkey and nobody, including us, can decrypt your vault.
Enroll a backup passkey (your vault's Passkeys tab) the day you set up.

## What can a compromised agent do?

Less than you'd fear. It holds phantoms, which are inert everywhere except
SafeClaw's proxy. Through the proxy it can spend a credential only toward that
connection's own hosts, under your policy, and sensitive actions block until
you approve them with a passkey. What it cannot do: read a value, send a
credential to an attacker's host, or approve its own requests. Exfiltrating a
key it never held is not on the table.

## Is SafeClaw intercepting all my traffic?

No. Only commands you deliberately prefix with `sc run --` are brokered.
Everything else on your machine goes straight out, untouched.

## What does a passkey tap actually authorize?

One specific operation. Approval surfaces speak SUDP, a passkey-signed
single-use-grant protocol: the pending operation is what you see, what you
sign, and all the signature is good for. There is no session-wide "approve
everything" token to steal.

## Can I verify any of this?

Yes: this repo is the entire client. The sealing, the proxy substitution, and
the approval protocol all happen in code you can read and build yourself
(`cargo build --release`), and releases carry sigstore build-provenance
attestations tying the binary you installed to this source.
