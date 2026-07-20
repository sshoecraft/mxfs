---
name: sess45-PROVEN-cachecoherency-uv-is-node1-dir-read-cache-staleness
description: sess45 PROVEN (A/B discriminator): cache_coherency uv fail = node1 dir-block READ cache staleness (NOT node2 durability). UV-DISCRIM: peer file prese…
metadata:
  type: project
---

## sess45 — cache_coherency uv root PROVEN (RULE-4 A/B discriminator)

### Reliable repro: reboot clean; `./run.sh 2 tcp cache_coherency` → node1 FAIL 1/2:
`uv gone node2_file21..30` + `uv none remain(exp=0 got=10)`. node1 sees the LAST 10 of node2's 30
just-unlinked files still present, right after the uv_delete MQTT barrier. Deterministic (same 10
both full-suite and standalone runs). node2 PASSES. The dir = $MNT/.cache_coherency/unlink_visibility.

### DISCRIMINATOR (added env-gated MXFS_UV_DISCRIM=1 branch to the uv check, ran, then REVERTED):
`mxfs-UV-DISCRIM rank=1 peer=node2_file21 before=present after_dropcaches=gone`
=> node1 saw the file present, then `sync; echo 3 > drop_caches` and it was GONE. DECISIVE:
**node1's page/buffer CACHE was stale** — node2's unlink IS durable on the LUN; node1 served a STALE
cached dir DATA block. (Side effect: with the discriminator ON the test PASSED 2/2, because
drop_caches refreshed node1 before the `ck` — further proof it's pure reader-cache staleness.)

### MECHANISM: node1's path lookup (`test -e` → xfs_lookup) reads $D's dir DATA block from its cache
without re-validating against the LUN. The dir-block coherency hook (xfs_da_read_buf invalidates a
cached block when b_mxfs_dir_gen < dp->i_dlm_dir_gen) does NOT fire because i_dlm_dir_gen is bumped
ONLY on a SLOW-PATH DLM re-acquire of the dir (xfs_mxfs_dlm.c:9294, S_ISDIR). node1's lookup does
NOT slow-path re-acquire $D after node2's deletes (xfs_lookup igets/locks with lock_flags=0 — the
DLM acquire + gen bump is skipped), so node1 never invalidates → reads node2's pre-delete dir image.
The EVICT-RING-DIRMOD broadcast (peer dir-mod hint) and/or the BAST-driven invalidation is not
reaching node1's cached $D dir DATA blocks for the LAST deletes.

### FIX DIRECTION (next, RULE-4 — instrument before patching): make node1 invalidate/coherent-re-read
the dir DATA block on a cross-node lookup. Options to investigate: (a) bump i_dlm_dir_gen / invalidate
cached dir DATA blocks when the EVICT-RING-DIRMOD hint for $D arrives on node1 (proactive); (b) have
the lookup path do the DLM dir acquire (so the gen bumps); (c) read-time: in xfs_da_read_buf, for a
multi-node non-EX-held dir, FUA-revalidate the cached block (heavy — watch tcp_dlm_scaling perf).
This is the historical cache_coherency ship blocker. crash_consistency wedge already FIXED this
session ([[sess45-FIX-partial-iwrite-skips-fresh-free-inodes-INODE_ALLOC_BUF]]); full suite 14/17
([[sess45-MILESTONE-full-suite-14of17-three-remaining]]). dir_reuse + tcp_dlm pass standalone
(cumulative/flaky). [[sess45-PROVEN-cachecoherency-uv-is-node1-dir-read-cache-staleness]]</body>
