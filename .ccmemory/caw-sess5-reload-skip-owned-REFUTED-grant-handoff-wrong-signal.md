---
name: caw-sess5-reload-skip-owned-REFUTED-grant-handoff-wrong-signal
description: sess5 REFUTED: reload_skip_owned=1 (skip reload stale when grant_handoff shows no cross-node handoff) BREAKS cache_coherency@4=0/4 — grant_handoff gg…
metadata:
  type: project
---

## sess5 REFUTED — the prior-owner reload-skip fix (grant_handoff gate) breaks coherency

### What was built (build B366EA3C, param `reload_skip_owned` DEFAULT 0 = SAFE/inert)
In mxfs_dlm_reload_inode's cluster-stale block (xfs/xfs_mxfs_dlm.c ~14406, the `else` before
`xfs_buf_stale`), added a branch: skip the stale + FUA re-read when
`!(mxfs_v5_dlm_inode_grant_handoff(dlm, ino, &gg) && gg!=0 && gg!=i_dlm_handoff_acted_gen)`
i.e. "no cross-node EX handoff since our acted gen => in-core authoritative". Keeps buffer DONE so
xfs_imap_to_bp cache-hits (no bio). Also `int mxfs_reload_skip_owned` def + `bool reload_owned_skip`.

### REFUTED (empirical, fresh substrate, reload_skip_owned=1)
- **cache_coherency@4 = 0/4 FAIL** (baseline 4/4). strong_consistency@4 = 4/4 PASS (substrate fine).
- ROOT of the refutation: `mxfs_v5_dlm_inode_grant_handoff` returns `gg==0` in TWO different cases:
  (a) self-reused inode this node owns (skip IS safe), AND
  (b) **FIRST read of a PEER-created inode** (cache_coherency cross_write_read: node B reads node A's
      file; B has no handoff history for that ino => gg==0) — here the stale+read is REQUIRED, but my
      gate skipped it => B serves stale/empty => 0/4.
- `genuine_handoff==false` does NOT mean "no peer wrote"; it only means "don't FORCE a superset adopt".
  The reload stale is the DEFAULT coherency action and must happen whenever we may hold unread peer data.
  I wrongly equated `!peer_handoff` with "safe to skip". WRONG.

### CORRECT FIX DIRECTION (for next session)
The distinction needed is "THIS node authored the inode's CURRENT on-disk content and no peer has
written since" — NOT handoff history. Candidate signals:
1. Gate at the reload CALLER, not inside reload: the storm reload fires via the grant callback
   `if (VFS_I(ip)->i_mode==0 || i_dlm_stale)` (xfs_mxfs_dlm.c:405) — the `mode==0` (freed shell) arm
   triggers for a REUSED inode. For a node RE-CREATING its OWN just-freed inode, it is the author;
   reload (which adopts on-disk = the freed/old image) is wrong to run at all on the create path.
   Distinguish create (we author) vs lookup/read (may be peer's) BEFORE calling reload.
2. Or: only skip when `ip->i_dlm_mode==EX` AND we hold it continuously (never released) since our last
   write — a first peer-read holds SH/PR not continuous-EX, so it won't match. But free+realloc DOES
   release EX in the gap, so this needs care (was a peer able to grab it in the gap? the DLM knows).
3. The clean design is still Fable's "PR-lookup caching" — hold PR on shared parents, consume cache
   while held >=PR, re-read ONLY on a real EX BAST — but that is a larger change.

### DO NOT
- Do NOT set reload_skip_owned=1 (breaks coherency). Build B366EA3C is safe ONLY with it off (default).
- Do NOT gate the reload stale on genuine_handoff / grant_handoff gen — refuted here.
See [[caw-sess5-STALER-identified-reload-inode-and-levers-tried]] [[caw-sess5-32node-fresh-baselines-and-fua-read-root]].
