---
name: caw-sess6-cachecoh32-storm-is-dir-reload-NOT-mode0-recycle
description: sess6 RULE-4 PROVEN: cache_coherency@32 storm is mode!=0 DIRECTORY reloads (post_release, ~75% dirs), NOT the mode==0 self-recycle case sess5 chased.
metadata:
  type: project
---

## sess6 (ccloop 12e0d157) — cache_coherency@32 storm RE-ROOTED (RULE 4, mode-split probe)

### THE DECISIVE MEASUREMENT (build B176AE568E, read_attr_probe=1)
Added `RELOAD-STALE-SPLIT` counters at the reload_inode cluster-stale site (xfs_mxfs_dlm.c
~14462): split by in-core `VFS_I(ip)->i_mode==0` vs `!=0`, and subset `ndir` = S_ISDIR.
Ran cache_coherency@32 on /dev/mapper/mpatha. Harvested dmesg:
- test1: `mode0=1 modeN=511 ndir=389 last_mode=0100644 post_rel=1 comm=bash`
- test8: `mode0=0 modeN=512 ndir=384 last_mode=040755 post_rel=1 comm=mv`

### CONCLUSION: H1 CONFIRMED — the storm is mode!=0, and ~75% DIRECTORY reloads
- **mode!=0 dominates 511:1** over mode==0. So sess5's whole `reload_skip_owned` /
  `fua_skip_owned_inode` line (scoped to the mode==0 self-recycle arm) is IRRELEVANT to
  cache_coherency@32 — it can NEVER fire on these reloads (mode!=0). That's why sess5 (which
  measured dlm_scaling@32, a private-subdir self-recycle workload) never moved cache_coherency.
- **~75% of the stales are DIRECTORY inodes** (ndir 389/511, 384/512; last_mode=040755).
  post_release=1 => these come from the **slow-path fresh-DLM-grant dir reload**
  (xfs_mxfs_dlm.c ~19060: `if (mode!=0 || nblocks!=0) mxfs_dlm_reload_inode(ip,...,true)` —
  fired UNCONDITIONALLY on every fresh dir grant, NO gen-gate).
- comm = mv / bash / cat = the test's own file ops on the 4 SHARED dirs
  (.cache_coherency/{cross_visibility,cross_write_read,rename_visibility,unlink_visibility}).

### WHY (mechanism): shared-directory reload contention + idle-demote feedback loop
cache_coherency does NO drop_caches (contra older memory). It does O(T²) cross-node access of 4
SHARED dirs. 32 nodes hold PR on the same dirs; subtests 3/4 (rename/unlink_visibility) do
32×20 and 32×30 create/rename/unlink EX ops in ONE shared dir each. Every EX modify BASTs all 31
PR holders → they drop → re-acquire PR → **slow-path fresh grant → unconditional full dir reload**
(re-read + extent-map rebuild + drain_evict_data_blocks). Plus MHT idle-demote (inode_mht_ms=300)
drops PR on any >300ms pause (frequent under load) → re-acquire → reload. Feedback: contention →
slow → pause/BAST → demote → reload → more I/O → slower. 512+ dir reloads/node × 32 nodes of
FUA re-reads saturate the single iSCSI target (~1319 IOPS) → phase can't finish in TEST_TIMEOUT
(300s) → coord_barrier times out → nodes_pass=0/32.

### FIX DIRECTION (sess6 next — NOT yet implemented/validated)
The storm site is the UNCONDITIONAL slow-path dir reload at ~19060. Two candidate gates:
1. **gen-gate the slow-path dir reload**: reload only if a peer actually modified the dir since
   our last load (`genuine_handoff` OR `i_dlm_dir_gen > i_dlm_dir_loaded_gen`). The FAST-path
   (cached-EX re-grant, ~18100 `dir_ex_stale_refresh`) ALREADY gen-gates ("fires only when a peer
   actually modified the dir ~10x/run"); the SLOW path does not. Mirror it. RISK: false-negative
   gen (lossy evict-ring) → serve stale dir → coherency fail. Validate cache_coherency@4/@16 HARD.
2. **don't MHT-idle-demote PR holds on shared dirs** (GFS2 glock principle): hold PR until a real
   EX BAST, never drop on idle. SAFER (skips no reload; just avoids dropping the lock) but need to
   confirm it doesn't starve EX writers (it won't — EX BAST still forces the drop).
Prefer starting with #1 (targeted, PARAM-GATED default-off) but #2 is the safer principle.
crash_consistency@32 (also FAIL 0/32) is same family (drop_caches + cold re-read). Validate both.

### INFRA GOTCHAS (sess6)
- run.sh DEFAULT DEV = /dev/sda (WRONG for criteria). MUST pass `MXFS_DEV=/dev/mapper/mpatha`
  (the multipath device; single active path now — 2-path synthetic was torn down 07-05).
- Build artifacts (mxfs.ko + tool binaries) got deleted mid-session by a `make clean` at the
  user's terminal (Makefile clean removes both). If prep says "module not found" / "mkfs tool not
  found", rebuild: `make modules && make tools`. Sources are intact.
- dir_reuse@4 recorded FAIL 0/4 is a sess5 ARTIFACT (ran it with the experimental param ON);
  restore = re-run with DEFAULT params. dir_reuse@16, dlm_scaling@32 PENDING (never run).
See [[caw-sess5-NEXT-correct-fix-mirror-iget-create-gate]] [[AAA-sess4-HANDOFF-caw-criteria-unified-readstorm-root]].
</body>
