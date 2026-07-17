# Design principles

The rules the system is built on. Each one is checkable against behavior you
can observe; none is aspirational.

**1. Use is not possession.** The agent gets the *use* of a credential,
never the credential. Phantoms in, API responses out; the value appears only
inside the proxy, at egress, on your machine.

**2. One egress, and only one.** Everything brokered flows through a single
local choke point. And only that: SafeClaw never intercepts traffic you
didn't route. The phantom is the only trigger; a request without one is
forwarded untouched.

**3. Host is a constraint, never a selector.** A connection's hosts bound
where its credential may go. The broker validates destinations against the
anchor; it never *chooses* a credential based on destination. Constraints
narrow, they don't route.

**4. Undefined means no.** A request no rule matches falls to ask-always. In
the fail-safe family of cloud IAM: when sources disagree, the strictest
wins; when nothing speaks, the answer is not yes.

**5. Boundaries refuse; they don't prompt.** Out-of-policy is a loud error,
not an approval popup. Prompts are reserved for actions you defined as
sensitive, so every tap you see is a real decision. Approval fatigue is a
security hole; we spend taps like money.

**6. One tap, one operation.** An approval is a passkey-signed single-use
grant, scope-bound to the specific action on the consent card. No
session-wide approve-all token exists, so none can be stolen or replayed.

**7. Plaintext lives in exactly one place.** The daemon's memory, on your
machine, while unlocked. Disk holds only sealed data; the cloud syncs blobs
it cannot read; `sc lock` ends even the one copy.

**8. Gate, don't block.** `deny` is never a factory default. SafeClaw exists
to let agents do real work; the value is a human at the choke point that
matters, not a wall in front of everything.

**9. No risk scores.** We don't grade other people's APIs "medium risk" on
your behalf. Rules state objective facts (what an action is, read or write);
levels state *your* decision. Third-party vibes are not a security input.

**10. Fail loudly.** Every refusal carries a stable `SafeClaw: <code>` line
and a documented fix ([DIAGNOSTICS.md](../DIAGNOSTICS.md)). No swallowed
errors, no mystery timeouts, no fake successes. A system you can't debug is
a system you'll route around, and routing around SafeClaw is the one failure
we can't accept.
