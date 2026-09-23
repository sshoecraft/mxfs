---
name: compiled-pr-fencing-and-dlm-identity-traps
description: PR fencing/DLM identity traps sess513-576: node-id reuse, self-only fence guard, CAW-only DEMAND flag, PR-evidence misreads, set -u false FAIL.
metadata:
  type: project
tags: [compiled, fencing, scsi-pr, dlm, identity, traps]
---

# SCSI PR fencing, node identity and DLM demand-lock gaps

Five traps, sess513-576, all rooted in the same fact: MXFS's identity and
locking primitives are not as unique or as symmetric as they look, and the
evidence for "the fence worked" or "the lock was denied" is easier to
overread than to read correctly.

## Identity is not unique per incarnation — it's unique per {host, boot, fs}

The SCSI PR key is derived from `{host_uuid, boot_uuid, fs_uuid}`
(`dlm/prledger.c mxfs_prledger_derive_key`), one I_T nexus per host. Two
successive incarnations of the same host in the same kernel boot carry the
**identical** key — the target cannot tell them apart. Node id is a
different axis (`uuid_to_node_id` at DLM init, per-mount), and a harness or
a fence path that conflates the two, or assumes either is unique across a
death/rejoin cycle, breaks.

- **sess513**: `tests/rejoin_residue.sh` arm 4 rejoined node B with
  `node_id_override=100`, the same id arm 1 had already departed with. The
  peer manager retires departed ids (`P164-DEAD-NOTE`); B's announces and
  heartbeats were answered `P164-DEAD-REJECT ... retired identity ignored`
  once a second, forever. B's mount parked on `why[prepare=60]` /
  `P-TAUTH-HANDOFF-DEFER cfg_match=0`, the harness's 40s mount bound killed
  it, and A fenced and foreign-replayed slot 1. Not a filesystem defect — a
  40-bit-random node id colliding with a retired one is ~k/2^32 — but a
  harness rule: never reuse a departed node id in the same run; cycle
  IDs or the peer's mount between reuses
  ([[trap-reused-node-id-override-is-a-retired-identity-p164-dead-reject-peer-never-admitted]]).

- **sess576**: the mount path's slot fence (`dlm/v5_mount.c`,
  `P238-FENCE-OWN-KEY`) compares a victim's PR key against the fencer's own
  key and refuses to preempt when they match — correct, a node must not
  preempt its own previous incarnation. But when a **peer** fences a dead
  incarnation whose host has already remounted, the victim key belongs to
  that other host and never matches the fencer's own key, so the guard
  never fires and the PREEMPT AND ABORT lands on the live successor sharing
  the same derived key. Same hazard, mirrored direction, unguarded — the
  existing guard's comment ("would preempt ourselves") is true and narrower
  than the actual hazard, which is easy to miss because the comment reads as
  if it covers the general case. Fixed by excluding the victim **by node
  id** (which does differ between predecessor and successor) rather than by
  key or liveness alone, enforced once inside `mxfs_scsipr_fence_node`'s
  shared pre-command section rather than at the one call site that surfaced
  the bug — the other three fence paths funnel through the same primitive.
  General check: when a guard's predicate names *self*, ask what the same
  predicate looks like with any other live member substituted, and whether
  that path is reachable. Test such a guard in both directions — a guard
  that refuses every fence also passes the naive positive test
  ([[trap-a-guard-written-for-the-self-direction-leaves-the-symmetric-peer-direction-open]]).

## PR evidence: a confident read is often a substitution error

Surfaced by a design consult on the D-0950 unmountable-volume defect, whose
stated root chain was plausible but not established by its own cited
evidence:

- `READ KEYS` proves a key is registered *somewhere*, never which I_T nexus
  holds it — only `READ FULL STATUS` carries the transport-identity mapping.
  Any "this key is on our own nexus" conclusion from `READ KEYS` alone is
  unsupported.
- Observing `P305-RESV-SELF-GONE-INSPECT` on a live mounted node has **four**
  equally-consistent explanations (a legitimate fence of the current
  incarnation including a false-positive death call, a stale/unrelated
  fence, an unregister on some other path, genuine PR-state loss at the
  target) — discriminating requires correlating the completed PR OUT
  (issuer, action, RK, SARK, type/scope, status, sense) against the frozen
  victim key and which incarnation was active at that instant. Picking one
  of the four without that correlation is a hypothesis wearing a root
  cause's clothes.
- Three specific overreads: `P302-PR-KEY-RETAINED-FENCE-TARGET` says only
  that our own unregister was skipped, not that a target registration still
  exists; `umount rc=0` together with `log_shutdown=1` is not a
  contradiction — the detach completed cleanly while the slice still failed
  to go durably clean; `holder_key=0x0` under a WE-AR (write-exclusive,
  all-registrants) reservation is expected, not evidence of a foreign
  holder, because WE-AR has no single holder key.
- General shape: never let one of {key selected, registration observed,
  registration confirmed on our own nexus, fence completed, fence
  durably certified} stand in for another — most wrong turns here are one
  silently substituting for another
  ([[trap-read-keys-does-not-say-which-nexus-holds-a-key-and-lost-registration-has-four-causes]]).
  Same family as the generation-snapshot trap already compiled elsewhere
  (`trap-a-pr-snapshot-only-proves-anything-about-the-generation-it-was-taken-at`,
  in `compiled-allocator-campaign-traps`): a PR read is evidence about the
  instant it was taken, nothing later.

## A DLM flag's semantics must be checked in both engines

**sess523**: `MXFS_LKF_DEMAND` was honoured only by `dlm_caw.c` (CASes the
slot's sticky revoke bit); `dlm/dlm.c` (the TCP engine) ignored it at both
NOQUEUE-deny sites, denying with `MXFS_ERR_DEADLOCK` and never BASTing the
holder. Measured on 2/tcp: the pre-acquire poll (demand + retries, 100ms,
inode locks held) expired 84/84 times, turning a 1.5s unlink into 41s across
51 request deadlines, one lap past its 60s bound. Any fix built and verified
only on the CAW rig (`mxfs_ag_dlm_lock_bounded`, D-488) was therefore inert
on TCP — a 2/tcp-only campaign hit a gap CAW-era work never saw. Fixed in
0.75.42 by adding `demand_collect_holders`/`demand_fire` at both TCP deny
sites. Lesson: grep both `dlm/dlm.c` and `dlm/dlm_caw.c` for a lock flag's
handling before relying on it — a flag implemented in one DLM engine is not
implemented in the other until proven so
([[trap-mxfs-lkf-demand-was-caw-only-tcp-noqueue-deny-never-basts-the-holder]]).

## An unbound shell variable can present as a fencing regression

**sess563**: `tests/tcp_death_replay.sh` documented a default for `MXFS_DEV`
in its own header comment but never actually set one; every use sat inside a
conditional arm, so `set -u` didn't fail at the top of the script — it died
mid-arm, at the one line reading the target's PR state after a sole-survivor
restore. The two assertions downstream then compared an empty string against
"exactly one registration" and "WE-AR in force," and both FAILed — reading,
at face value, as a critical fencing regression (the reservation gone after
restore) on a run that in fact never measured it (327/327 files verified,
zero bad/missing). General lesson: `ck "<claim>" "$(measurement)" "expected"`
cannot distinguish "the thing is broken" from "I could not look at the
thing" — assert on emptiness first and report it as a named harness fault,
never let it flow into the record as a defect in whatever was being
measured. Any `set -u` harness whose env vars are read only inside optional
arms carries this same landmine: it passes for months, then dies in the one
arm that matters the day that arm first runs. Fixed in 0.75.89: a real
default for `MXFS_DEV`, and the PR-state block now refuses to compare an
empty reading and says so explicitly
([[trap-set-u-unbound-var-inside-a-conditional-arm-turns-into-two-false-fencing-FAILs]]).

## The shape, again

Every trap above is the same failure at a different layer: an assumption
that something is unique, symmetric, universally implemented, or actually
measured — key per incarnation, a self-only guard, a flag honoured
everywhere it's set, a shell variable actually bound — turned out to hold in
only the tested direction or the tested engine. Check the untested direction
explicitly (self vs. peer, CAW vs. TCP, happy path vs. the arm that only
runs once a defect is already in flight) before trusting silence from it.
