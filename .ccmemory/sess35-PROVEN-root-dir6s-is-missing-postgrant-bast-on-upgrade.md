---
name: sess35-PROVEN-root-dir6s-is-missing-postgrant-bast-on-upgrade
description: sess35 PROVEN ROOT+FIX of dir_reuse 2/tcp 6s handoff: i_dlm_stale conflates needs-reload + deferred-BAST; reload clears it before post-publish → ACQU…
metadata:
  type: project
---

## sess35 — dir_reuse_coherency 2/tcp ~6s handoff: PROVEN ROOT CAUSE + FIX

### THE ROOT (proven by P37 + P-DIRBAST traces, build 24144BB4):
The slow-path inode-EX acquire (xfs_mxfs_dlm.c mxfs_dlm_ilock_begin) does, in order:
1. ~8816: `ip->i_dlm_stale = true;` (unconditional, signals "reload needed")
2. ~8840: `mxfs_dlm_reload_inode()` which **CLEARS i_dlm_stale** on success
3. ~8906 post-publish: `if (ip->i_dlm_stale) -> state=BAST+drain; else -> CACHED`

`bast_notify`'s ACQUIRING branch (~5512) deferred a peer BAST by setting **i_dlm_stale=true** — the
SAME flag. So when a BAST arrives while this node is ISTATE_ACQUIRING (slow-path EX acquire in
flight), the reload at step 2 clears it, and post-publish at step 3 sees false → goes CACHED → **the
deferred BAST is SILENTLY SWALLOWED**. The holder keeps EX cached idle; the peer's request stalls
the full **6000ms MXFS_LOCK_ACQUIRE_WAIT_MS** until mxfs_dlm_lock's retry (dlm.c ~1344) re-fires the
BAST — at which point the holder is CACHED (state=1) and honors it in ~14us.

### DECISIVE EVIDENCE:
- test2(holder) received 40 P-DIRBAST for ino=131, honored only 31 (P35-DIRHONOR). The ~9 unhonored
  == the **9× `state=4(ACQUIRING) mode=5(EX)`** arrivals. CACHED-state BASTs honor in 14us (what
  sess35 first mis-measured as "H1 refuted"); ACQUIRING-state BASTs were LOST.
- P37 on master(test1=446677888): a 6.02s gap where test1 queued PR + fired BAST to holder
  (test2=3447014361), nothing for 6s, then the retry re-fired and test2 released instantly.
- P34-ACQ-SLOW ino=131 EX dur~6000+, attempts=1, rc=0; P36-RETRY confirms timeout+retry; grants to
  the requester all matched=1 (delivery fine). pin_count always 0.

### THE FIX (build pending, srcversion TBD — was building at relay): dedicated flag
`i_dlm_bast_during_acq` (added to struct xfs_inode in xfs_inode.h next to i_dlm_stale).
- bast_notify ACQUIRING branch sets BOTH i_dlm_stale (reload) AND i_dlm_bast_during_acq (BAST).
- post-publish: `bool acq=ip->i_dlm_bast_during_acq; ip->i_dlm_bast_during_acq=false; if
  (i_dlm_stale || acq) -> BAST+drain`. Reload does NOT touch the new flag, so the deferred BAST
  survives. Logs `P35-ACQBAST-HONOR ino= mode=` when it fires (expect ~9/run; P34-ACQ-SLOW→~0).
- Initialized false at inode setup (~9922, next to i_dlm_pin_count=0).
KEEP the earlier collect_grantee_bast_if_waiters post-grant-BAST additions (dlm.c upgrade/immediate/
reaffirm sites) — harmless, fire rarely; not the root but correct defense. P37/P36/P35 traces all
in tree (always-on, safe).

### REFUTED earlier this session (don't retry): H2 upgrade-grant-without-BAST and H3
immediate-grant-jump (P35-POSTGRANT-BAST fired ~1×/run = not the path).

### VALIDATION: rerun dir_reuse 2/tcp ×3-5. Expect P34-ACQ-SLOW≈0, P35-ACQBAST-HONOR>0, handoffs
in ms. SEPARATE correctness face still open: **P26-DSCAN-MISS scanned~120/200** = reader under-reads
shared dir (acquire-side stale dir-block RMW, xfs_da_read_buf XBF_TRYLOCK-skip xfs_da_btree.c ~3101;
GPT plan item 6 = invalidate whole dir fork at DLM acquire boundary). Both faces must pass for 100%.
[[sess34-6s-dir-handoff-is-LOCK_ACQUIRE_WAIT_MS-deferred-bast]] [[sess34-dirreuse-acquire-side-stale-rmw-trylock-skip]]</body>
