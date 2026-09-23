---
name: trap-platter-live-memory-free-different-gen-is-not-a-revert-unless-the-slot-is-unheld
description: TRAP (sess583): the clobber probe's 'platter LIVE, memory FREE, different gen = live revert' class fired on the survivor's OWN churn (own free at gen…
metadata:
  type: feedback
tags: [D-0955, D-0957, probe, dino-clobber, generation]
---

# Images alone cannot classify a live revert; tenure can

`mxfs_dino_clobber_probe` (pal/linux/xfs_buf.c) compares the submitted cluster image with
a FUA read of the platter per slot. Its "case the changecount cannot see" — platter LIVE,
memory FREE, generations differ — was meant to catch a peer's reallocation over this
node's old free image (D-0957's platter signature). Three false positives in one session:

1. **A 96-byte detail buffer truncated the generation mid-number.** `mem FREE cc=10
   gen=206` was a generation of 2060535958; `gen=1048` was 104822822. Both were the disk
   generation plus one — the decimal-prefix tell. Buffer is 160 bytes now.
2. **Platter LIVE gen=g, memory FREE gen=g+1, changecount ahead = our own free landing.**
   A free bumps the generation by exactly one (`xfs_inode_util.c` `i_generation++`); a
   fresh allocation draws a random one. Counted as `ownfree`, not a regression.
3. **Platter LIVE gen=P, memory FREE gen=Q+1, P unrelated to Q = our own churn two
   incarnations ahead.** Tight mode frees and reallocates a number twice per round with no
   sync; the platter holds incarnation P, memory freed P, allocated Q, freed Q. Identical
   images to the real hazard (memory BEHIND a peer's P). The discriminator is tenure: an
   in-core inode held at EX or PR was reloaded from the platter at grant time and everything
   since is ours, so the platter image is one we superseded (`ownchurn`). A slot held at NL
   or not in core keeps the live-revert classification.

Read `P-DINO-CLOBBER-REALLOC ... realloc= ownfree= ownchurn=` as the probe's liveness and
`P-DINO-CLOBBER# ... live_revert=` only after those three exclusions. On a pre-0.83.3 sole
survivor every inode sat at NL (no grants on the single-node bypass), so the tenure
discriminator was blind there and every own-churn write read as a revert.
