---
name: caw-4node-cache_coherency-REGRESSION-empty-content
description: HIGH PRIORITY: 4/caw cache_coherency REGRESSED to 0/4 (empty cross-node content reads, got=) on a CLEAN substrate (reservation_conflicts=0) — build 0…
metadata:
  type: project
---

## 4/caw cache_coherency REGRESSION (ccloop 12e0d157, 2026-07-07) — DIAGNOSE FIRST

### Symptom (PROVEN, clean substrate)
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 4 caw cache_coherency`
on FRESHLY-booted test1-4 (LUN PR cleared, **reservation_conflicts=0**, converged clean in 8s) →
**FAIL 0/4**. Reason: `cv node1 content of node1(exp="hello from node 1" got=)` — cross-node file
CONTENT reads EMPTY (88× `got=` empty). NOT a reservation conflict, NOT a wrong-value coherency
mismatch — the writer's committed content is INVISIBLE (empty) to peers. This is the classic
writer-durability / FUA cross-node coherency family.

### Why this matters
criteria.json shows 4/caw cache_coherency PASS at 2026-07-06T03:07 — but that was a PRE-115CCA8
build. The previous session's 16/32 work (which produced 115CCA8, deployed) was NEVER re-validated
at 4/caw. So the "1/2/4/8 caw pass" foundation is currently BROKEN. Fix this BEFORE any more
dlm_scaling perf work — a marginal 32-node perf fix is worthless if 4-node coherency is regressed.

### Isolation plan (NEXT SESSION, RULE 4)
1. Confirm it's NOT the PR-wedge: already done (reservation_conflicts=0, clean fresh boot). Re-run
   2-3× on a clean substrate to confirm it's deterministic, not variance/contamination (memory says
   many suite fails are contamination — but this was cache_coherency ALONE, fresh cluster).
2. Rule out MY changes: my build is 0510FC3E (want_ex plumbing + default-off param, see
   [[caw-32node-dlm_scaling-FIX-progress-and-fable-design]]). They are INERT with the param off
   (dir_release_skip_nonex=0). To PROVE: revert my 5 edits (xfs_inode.h i_dlm_dir_want_ex field;
   xfs_mxfs_dlm.c bast_notify set at ~13176, inode_init clear at ~20408, grant clear at ~18929,
   param+gate at ~5333/6243), rebuild → should be 115CCA8-equivalent, re-test 4/caw. If STILL 0/4
   → regression is in the prev-session 16/32 base (115CCA8), not me.
3. If base regression: the empty-content-read root is a writer-durability / FUA-read-of-uncommitted
   issue — compare current xfs_da_btree.c / xfs_dir2_data.c / the FUA gate against the last known
   4/caw-green state. The prev session edited xfs/xfs_mxfs_dlm.c, xfs/libxfs/xfs_da_btree.c,
   xfs/libxfs/xfs_dir2_data.c (per its resume) — start there.
4. Only after 4/caw (and 8/caw) cache_coherency are GREEN again, resume the 32-node dlm_scaling
   architectural fix (Fable design).

### Substrate note
This session PR-wedged the cluster via ~20 power-cycles ([[pr-ua-register-fence-out-rootcause]]);
recovered by explicit `sg_persist --out --register-ignore --param-sark=0x5eed` + `--clear
--param-rk=0x5eed` on /dev/mapper/mpatha, then destroy all VMs. On the CLEAN substrate the pr-ua
reservation-conflict did NOT recur (reservation_conflicts=0) — so the earlier "coherency 0/4" runs
were a MIX of PR-wedge AND this real empty-content regression; only the clean run isolates the
regression. All VMs currently destroyed; LUN PR clean.
See [[caw-32node-dlm_scaling-FIX-progress-and-fable-design]] [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]].
</body>
