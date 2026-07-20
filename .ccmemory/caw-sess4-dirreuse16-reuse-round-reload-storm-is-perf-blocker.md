---
name: caw-sess4-dirreuse16-reuse-round-reload-storm-is-perf-blocker
description: sess4: persig_flush=2 FIXES dir_reuse@16 hang+coherent, but REUSE rounds (2+) are 16x slower than round1 (264s vs 16s create) from reused-inode reloa…
metadata:
  type: project
---

## dir_reuse@16 — persig_flush=2 fixes hang+coherency; RESIDUAL = reuse-round reload storm

### PROVEN this session (ccloop 12e0d157 sess4, build 6C6D5274, CLEAN cluster)
`MXFS_EXTRA_MODARGS="dir_persig_flush=2" ./run.sh 16 caw dir_reuse_coherency`:
- **persig_flush=2 FIXES the rm-rf hang** (round1 rm-done at 645s, round2 started; no
  hung-task, no xfs_buf_iowait stall). And **COHERENT** (0 RDMISS0, 0 leaf-hash fails).
  The EX-release drain (mxfs_dir_data_durable + flush, sess98 IN_AIL fix) enforces
  durability at handoff, so deferring the per-modify flush is safe. persig_flush=2 =
  flush per-modify ONLY when a peer wants EX (i_dlm_dir_want_ex); the uncontended
  rm-rf (peers at barrier) skips -> no hang.
- Round 1 (FRESH dir): create 16s, verify 63s, rm 63s = ~153s.
- **Round 2 (REUSE round): create phase ALONE >264s and climbing** (16x round1's 16s
  create). rank1 `dd` D-state; storm of `P7B-BASTNOTIFY ino=131` (the reused shared dir,
  state=0 mode=0 ex=0 pr=0) + 1637 "DLM inode lock failed rc=-35"/barrier msgs.

### ROOT of the residual (hypothesis, NOT yet fully instrumented)
The dir is rm-rf'd + recreated each round (rank1) → ino 131 FREED+REALLOC'd with a NEW
generation. In round 2+, 16 peers each cached the OLD ino-131 incarnation; every per-op
access must detect the gen change + RELOAD the reused dir. Under 16-way create contention
(all nodes creating 100 files into the reused dir) this reload/BAST fires REPEATEDLY
(thundering herd), not once → super-super-linear. 8/caw dir_reuse passed ~40s/round; 16 is
~153s (fresh) to >264s (reuse) — far over the 140*N=2240s run.sh budget. RULE 0: a
clustered FS slower than GFS2/OCFS2 FAILS even if correct — so this needs a REAL perf fix,
not a budget widen.

### Where to look NEXT (perf fix candidates, unverified)
1. Reused-inode reload firing PER-OP instead of ONCE per tenure (inode-reuse coherency:
   see sess86-92 d_revalidate gen-check family). Instrument: count reloads of ino=131 in
   round2 — if >>16, it's re-invalidating repeatedly = fixable.
2. Create-wave dir-EX handoff: do nodes create MULTIPLE files per EX tenure, or ping-pong
   per-file (1600 handoffs)? Fairer/batched handoff (hold EX across several creates) would
   cut handoffs O(N^2)->O(N). P7B-BASTNOTIFY storm on ino=131 = thundering-herd EX contention.
3. Verify's cold-read storm (63s, 16 nodes x1600 md5sum after drop_caches) = target
   read-saturation — SAME root as dlm_scaling@32. dir_shared_pr_skip helps the readdir of
   the shared dir but NOT the file-data reads.

### Decision context
This is a FUNDAMENTAL scaling perf problem (reused-inode coherency + N^2 dir contention),
worked across many prior ccloop runs. dir_reuse blocks BOTH 16 and 32. dlm_scaling@32
(shared-parent read storm) is a SEPARATE prepared fix (dir_shared_pr_skip). Both share the
theme "too many coherency reads/reloads under high node count -> shared iSCSI target
saturation". Let pf2 run to the 2240s timeout for the definitive wall (cleaner teardown
than a mid-run kill, which forces power-cycles). See
[[caw-sess4-dirreuse16-root-and-clean-build-params]] [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]].
</body>
