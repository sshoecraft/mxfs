---
name: trap-a-ruling-that-says-take-path-x-exactly-as-multi-node-assumes-every-premise-of-x
description: TRAP (sess583, D-0955): a consult ruled 'sole survivor takes the partial inode write exactly as multi-node'; landed alone it stranded the survivor's…
metadata:
  type: feedback
tags: [D-0955, sole-survivor, partial-inode-write, consult, harness]
---

# A ruling holds only with its premises; verify them in code before landing it

**What happened (sess583, D-0955, 2 nodes/TCP).** The consult ruled that a sole survivor
should take `mxfs_submit_partial_inode_write()` exactly as under multi-node membership.
I flipped `partial_iwrite_sole` to default 1 and set `ever_multi` at the membership
callbacks. First lap (s583b) clean. Second lap (s583c): the survivor's freshly created
directory (a number the departed peer had freed) was dropped from the cluster write by
`P56-NL-LOGGED-DIR-SKIP` (logged dir at NL, no `MXFS_IF_DLM_RELFLUSH` token), the platter
kept the peer's FREE image, the sole-survivor reload read it and poisoned the directory
(`P34H-INCARN-POISON src=reload disk_mode=0`): permanent ESTALE, 799 of 800 creates failed,
the rejoined peer saw the slot FREE behind a live dirent. The root directory's dinode was
dropped the same way in both laps and only landed because the A/B harness alternated with
the pre-fix whole-write arm.

**Why.** The partial path's authority rule was earned under multi-node, where a logged
directory at NL means "released to a successor" and the release drain sets the token.
On single-node membership `mxfs_dlm_ilock_begin` bypasses the DLM and never sets
`i_dlm_mode`; both new-inode grant paths and the create-time `i_dlm_stale = false` are gated
on `!is_single_node`; the token is set only by the BAST drain. So on a sole survivor EVERY
logged directory is at NL without a token, and the "same path as multi-node" refuses all
of them. The ruling's premise (grants exist) was false for exactly the state it was ruling on.

**The corrected shape (second consult, same defect):** a sole survivor must run the real
ownership protocol — take grants from the master (itself) — so the multi-node invariants
apply unchanged. Predicate `mxfs_v5_dlm_never_multi()` (single now AND never had a peer) is
the only state allowed to modify and publish without a grant. Shape A ("logged this round
is authorised while single") was ruled unsound: A caches dir X, B publishes X+b and leaves,
A modifies its stale X → publishes X+a, b is lost, same generation throughout.

**Lessons.**
- Before landing a ruling of the form "take path X as under condition Y", enumerate X's
  preconditions in the code and check each holds under the state being ruled on.
- An A/B harness that alternates the fixed arm with the pre-fix arm lets the control arm
  RESCUE the treatment arm's omissions (the whole write landed what the partial write
  dropped). Verification of an omission bug needs an all-fixed-path campaign
  (`MXFS_D0946_ARM=1`).
- Sum the workload's own error counters (`cerr`/`derr`) into the verdict; s583c printed
  `cerr=799` on a line nothing read and every READ line said clean.
- Positive durability evidence is a cold-cache readback from the other node
  (`COLD_READBACK`, `STALESRC_READBACK`), not the absence of clobber lines: this regression
  was an omission, and no clobber probe fires on bytes that were never written.
