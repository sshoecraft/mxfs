---
name: sess35-fix-result-and-residual-asymmetric-slowness
description: sess35: i_dlm_bast_during_acq fix (build A970F10B) WORKS — test2 creates 6s→1.3s, P35-ACQBAST-HONOR fires. But test still times out: residual asymmet…
metadata:
  type: project
---

## sess35 — result of the i_dlm_bast_during_acq fix + remaining bottlenecks

### FIX WORKS (build A970F10B, KEEP): the dedicated i_dlm_bast_during_acq flag (honor a
BAST deferred during ISTATE_ACQUIRING at post-publish, surviving reload's clearing of i_dlm_stale)
eliminated the ACQUIRING-BAST loss. Evidence: P35-ACQBAST-HONOR fired 11× (t1=3 t2=8); test2's
create phase dropped from slow to ~1.3s; test2 P34-ACQ-SLOW=0 in the (wrapped) tail.

### STILL FAILS — test times out at 300s (both nodes reach round 24/24 but no final RESULT).
Per-round phase durations (from mxfs-DRCph markers, NOT wrapped):
- **test1 (MASTER for ino=131): create ~6.5s, verify ~3.2s, rm ~2.6s**
- **test2 (remote): create ~1.3s, verify ~8.4s, rm ~2.0s**
Barrier-coupled round ≈ max per phase ≈ 6.5(create,t1) + 8.4(verify,t2) + 2(rm) + ~4.6(gap) ≈ 16s
× 24 = ~390s > 300s budget. RULE 0: timeout = FAIL.

### TWO residual bottlenecks (ASYMMETRIC — the key clue):
1. **test1 create ~6.5s** — P34-ACQ-SLOW=3 on test1 (each ~6s) ⇒ still ~1 6s lost-BAST/round on the
   MASTER side. Asymmetry root: test1-as-requester fires a REMOTE BAST (network) to holder test2;
   test2-as-requester triggers a LOCAL BAST on test1 (always delivered → test2 fast). So the
   residual lost-BAST is on the **remote BAST delivery / remote holder honor path** — a state on
   test2 OTHER than ACQUIRING(fixed)/CACHED(14µs), OR the remote BAST msg lost, OR test2's
   LOCK_RELEASE STALEGEN-dropped at master test1. NEXT: tests/drc_run_capture.sh (full dmesg, no
   wrap) → find test2's P-DIRBAST state when test1's lost BAST arrives.
2. **test2 verify ~8.4s** = 200 lookups after `echo 3 >drop_caches` = ~42ms/lookup = cold FUA
   inode/dir-block reads. Native XFS = µs. Candidate: FUA-read over-forced even when the node holds
   the dir grant (cache provably coherent) — read-amortization (sess31 _XBF_FUA_FRESH) not working
   under this test. Investigate xfs_buf FUA gate.

### CORRECTNESS face (independent, also fails): P26-DSCAN-MISS scanned~120/200 = reader under-reads
the shared dir (acquire-side stale dir-block RMW; xfs_da_read_buf XBF_TRYLOCK-skip xfs_da_btree.c
~3101). GPT plan item 6 = invalidate whole dir fork at DLM-acquire boundary.

### TOOLING: dmesg ring WRAPS during a 24-round run (P-DIRBAST etc. scroll out → counts undercount).
Use tests/drc_run_capture.sh (sess35, RULE 3) — starts `dmesg --follow`→/tmp/drc_full.log on each
node (survives prep's rmmod/insmod), runs once, leaves full per-node logs. Builds in tree:
A970F10B = root fix + P34/P35-ACQBAST/P35-POSTGRANT/P36-RETRY/P37 traces (all always-on). Consider
trimming P36/P37 next session (served their purpose) to cut spam.
[[sess35-PROVEN-root-dir6s-is-missing-postgrant-bast-on-upgrade]]</body>
