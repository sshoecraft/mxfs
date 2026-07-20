---
name: sess8-CONFIRMED-root-convblk-removal-double-grant
description: sess8 CONFIRMED root of 2/tcp shortform lost-update: conversion-blocked PR→EX frees the holder's GRANTED entry (dlm.c ~2229) → double-grant. Fix desi…
metadata:
  type: project
---

## CONFIRMED ROOT (RULE 4, instrumented) of the rotating 2/tcp shortform-dir lost-update.
Supersedes the "double-grant or transient-read" uncertainty in
[[sess8-FINAL-state-and-next-step-double-grant]].

### Probe: P-CONVBLK-REMOVE (always-on, rate-limited; build AFD6B76A06125A24489A130, dlm.c ~2229).
During dlm_fairness it FIRES on the DIRECTORY inodes: `P-CONVBLK-REMOVE sender=N type=1
ino=131|128|2097280 held_mode=PR req_mode=EX` (~3-6× per 20 runs, even on passing runs — the window
is opened frequently; the lost-update only manifests when a peer's upgrade lands inside it, ~1/16).

### THE BUG (dlm/dlm.c process_remote_request, conversion-blocked branch ~2229-2241):
A node caches the dir lock at PR (from a readdir/lookup), then requests EX to modify (create/rename/
rm all take dir ILOCK_EXCL → DLM EX; with lock caching this is a PR→EX UPGRADE). If the upgrade is
blocked by the peer's PR (conv_compat=0), the code FREES the sender's GRANTED PR entry and re-queues
it as WAITING-EX (fall-through to remote_check_compat). Consequences:
1. The sender is now INVISIBLE as a holder. A different node's subsequent PR→EX upgrade scans only
   GRANTED entries (compat checks at dlm.c ~2211 and ~2254 `continue` on non-GRANTED), sees no
   conflict, and is GRANTED EX → it holds EX while the first node still locally caches the dir (the
   DLM-layer removal does NOT invalidate the xfs-layer cached inode).
2. A WAITER is never sent a BAST, so when the first node is later PROMOTED from WAITING-EX to
   GRANTED-EX, its i_dlm_stale was never set → mxfs_dlm_ilock_begin does NOT reload → it RMWs its
   STALE cached shortform fork (missing the peer's committed dirents) → durable clobber = the
   `shared dir drained got=1` / cc `got=98` leftover.
This is the proven double-grant class ([[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]], fix
direction #2: "never remove a GRANTED holder's entry except via its own LOCK_RELEASE"). The
gen-token fix ([[sess-tcp-DLM-double-grant-FIXED-gen-token]]) closed the request-vs-release race but
NOT this conversion-blocked removal.

### FIX DESIGN (next session — delicate, validate with 30+ dlm_fairness iters since baseline ~1/16):
The naive "keep A's GRANTED PR entry" causes a PR→EX CONVERSION DEADLOCK (both nodes hold PR, both
want EX, neither releases). Options, in order of safety:
(A) CLIENT-side reload-on-promote: when a node is GRANTED EX after having WAITED (was not the prior
    GRANTED holder), FORCE i_dlm_stale=true before the modify so it reloads the peer's durable image.
    This neutralizes the lost-update CONSEQUENCE without touching the deadlock-breaking removal.
    Lowest risk. Need to find where the client transitions to GRANTED-EX from a wait (process_remote_
    grant + the xfs ilock_begin grant-wait path) and set i_dlm_stale for dir inodes. Mirrors how a
    fresh EX acquire already reloads — just extend it to the upgrade-after-wait path.
(B) MASTER keeps A's GRANTED entry visible AND detects/breaks the PR→EX conversion deadlock
    explicitly (choose one side to fully release+reload). Correct DLM semantics but larger change;
    must update compat checks (~2211, ~2254) to count converting entries at their granted mode.
Prefer (A) first; it's the minimal correctness fix at the proven consequence.

## DEPLOYED build = AFD6B76A06125A24489A130 (both nodes) = DA703FD6 (rename guard KEEP + P-SFREL
probe) + the P-CONVBLK-REMOVE marker. Reliably 15/16, no shutdown cascade. Marker NOT written.
Fallbacks: E143DF7B (rename guard only), E8BF16B2 (pre-guard, 15/16 WITH cascade).
</body>
