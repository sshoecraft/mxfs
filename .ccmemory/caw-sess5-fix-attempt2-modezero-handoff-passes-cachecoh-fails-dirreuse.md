---
name: caw-sess5-fix-attempt2-modezero-handoff-passes-cachecoh-fails-dirreuse
description: sess5 fix attempt 2 (build 30B29D85, reload_skip_owned=1 = mode==0 arm + !handoff-bit): PASSES cache_coherency@4 4/4 + strong_consistency@4 4/4 (big…
metadata:
  type: project
---

## sess5 fix ATTEMPT 2 — mode==0 + handoff-bit: closer, still breaks dir_reuse

### The change (build 30B29D85, param reload_skip_owned DEFAULT 0 = inert/safe)
In mxfs_dlm_reload_inode's cluster-stale block (xfs_mxfs_dlm.c ~14406), the `reload_owned_skip`
computation now: `if (mxfs_reload_skip_owned && VFS_I(ip)->i_mode==0 && !genuine_handoff) {
reload_owned_skip = !mxfs_v5_dlm_inode_grant_handoff(dlm, ino, &gg); }`. I.e. skip the stale+FUA
ONLY for a mode==0 self-freed shell being re-created, when the CAW `handoff` bit is FALSE (self/none
was the last EX-class holder — mxfs_dlm_caw_grant_handoff returns slot->last_ex_slot != NONE &&
!= self). Dropped the refuted `gg!=0` epoch condition.

### RESULT (reload_skip_owned=1, fresh 4-node)
- **cache_coherency@4 = 4/4 PASS**  (attempt-1 grant-gen version was 0/4 — the mode==0 scope + pure
  handoff-bit correctly leaves first-read-of-peer-data (mode!=0) alone). BIG step.
- **strong_consistency@4 = 4/4 PASS**.
- **dir_reuse_coherency@4 = 0/4 FAIL**  <-- still broken. Cross-node inode-number reuse: a peer
  re-creates a number THIS node freed (mode==0 shell), but the `handoff` bit did NOT flag it, so the
  skip fired and served our stale freed shell instead of the peer's re-created inode (dirent loss /
  0/4). (Not yet confirmed loss-vs-timeout via forensics — cache_coherency passed so not catastrophic
  slowness; likely a coherency skip. Next session: read the dir_reuse forensic + a STALE-INO/skip probe
  to see the exact mis-skip.)

### WHY the handoff bit is insufficient for dir_reuse (hypotheses for next session)
- Timing: peer's re-create advances last_ex_slot, but our grant's observed slot meta may lag / the
  handoff bit is computed against last_ex_slot AT OUR GRANT CAS, which can miss a very-recent peer EX.
- The dir_reuse workload reuses files in ONE SHARED dir concurrently across nodes; the freed-shell
  reuse window overlaps peer creates tightly. last_ex_slot may show self if WE were the last to hold
  EX on that exact ino# even though a peer wrote the current on-disk content in between via a path that
  didn't take EX-class on that resource, or the slot was reclaimed (last_ex_slot reset to NONE) →
  handoff=false → wrong skip.
- CONCLUSION: prior-EX-owner (last_ex_slot) alone is NOT a sufficient "no peer wrote" proof under
  aggressive cross-node reuse. Need a stronger check (e.g. also require the on-disk di_gen matches our
  in-core freed gen, or fall back to a cheap non-FUA plain-bio verify of di_gen before skipping), OR
  move to Fable's PR-lookup-caching (hold PR on the shared parent, re-read only on real EX BAST).

### REGRESSION HANDLING
- dir_reuse@4 FAIL OVERWROTE the recorded 4/caw dir_reuse PASS → 4/caw dropped to 16/17. Restored by
  re-running `./run.sh 4 caw dir_reuse_coherency` with param OFF (default). ALWAYS restore after a
  param-on coherency run that fails, or 4/caw/8/caw regress. (2nd time this session — see also
  [[caw-sess5-reload-skip-owned-REFUTED-grant-handoff-wrong-signal]].)
- Build 30B29D85 is SAFE only with reload_skip_owned=0 (default). Do NOT enable until dir_reuse@4 (and
  @8/@16) are GREEN with it on.
See [[caw-sess5-NEXT-correct-fix-mirror-iget-create-gate]] [[caw-sess5-STALER-identified-reload-inode-and-levers-tried]].
