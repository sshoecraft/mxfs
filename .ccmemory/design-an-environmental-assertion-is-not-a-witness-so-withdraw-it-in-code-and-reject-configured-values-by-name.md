---
name: design-an-environmental-assertion-is-not-a-witness-so-withdraw-it-in-code-and-reject-configured-values-by-name
description: DESIGN (Astra s83 ruling, 0.89.16): removing an unsupported certificate-producing path IS the integrity fix; withdraw in code, not config, and refuse…
metadata:
  type: project
tags: [fencing, retirement, design-ruling, scsipr]
---

# An environmental assertion is not a witness

Design-consult ruling (Astra, session 83), shipped as 0.89.16. Continues
`docs/rulings/retirement-witness-routes-lu-reset-early-preempt-or-refuse.md`.
The operator-facing form is `docs/retirement-witness-and-what-refusal-means.md`.

## The shape of the decision

A path was minting a replay-authorising certificate from a *deployment
assertion* — a per-LUN clause the deployment stated about the target's
ordering. Two things make that unfixable by strengthening the assertion:

1. The module **cannot detect a target that breaks it**. There is no error
   return, no refusal, no log line — only a replay that quietly overwrote live
   metadata.
2. Its support was observational (four probe laps, no late write in a 180 s
   window at 50 ms). That characterises a target under one workload. It cannot
   exclude a command the target retained without it ever becoming observable,
   and more laps improve the characterisation without turning the absence of an
   observed counterexample into a guarantee.

**Removing the unsupported certificate-producing path IS a fix to the integrity
defect, not a relabelling.** What remains — the recovery is now unavailable —
is a separate availability limitation and gets its own record. This is the
answer whenever the honest mechanism is out of reach: disabling the unsafe
transition is a disposition, and it is graded on the refusal being *enforced*,
*terminal* and *bounded*, not on the feature still existing.

## The four things the ruling required, and they are the checklist

- **Withdraw in CODE, not in configuration.** A default an administrator can
  put back is not a fix. The choke point every replay-authorising kind crosses
  (here the certificate constructor) must refuse, so no path routes around it.
- **Reject a configured value OUT LOUD, by name.** Keep reading the parameter
  so a deployment that qualified its LUN is TOLD its qualification is rejected
  rather than left to infer it from a refusal that never mentions it. Print the
  value on its OWN log line — inside a reason buffer it is the part that
  truncates away.
- **Legacy authority must not survive the upgrade.** A durable certificate of a
  kind that could only ever have been minted on the withdrawn basis is refused
  where certificates are *consumed*, as well as where they are minted. You do
  not need durable basis provenance for this if the KIND is only reachable from
  the premise the withdrawal removed.
- **No override, in any form.** Not waiting, not retrying, not a mount option,
  not "I accept the risk", not re-registering a replacement key, not a
  read-only mount. An override reproduces the defect with the operator's name
  on it.

## The refusal has an operational bar of its own

"Refusing" by hanging fails as surely as certifying wrongly. Grade it:
the dependent mount returns a real failure inside its own bound (never a
timeout kill), the slot reaches a durable BLOCKED state after a bounded series
so dependent operations fail fast instead of waiting, the surviving node stays
up and keeps serving what it owns, and nothing crashes or shuts a filesystem
down.
