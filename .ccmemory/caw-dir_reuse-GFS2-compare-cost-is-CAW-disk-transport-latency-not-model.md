---
name: caw-dir_reuse-GFS2-compare-cost-is-CAW-disk-transport-latency-not-model
description: GFS2 reference compare (RULE-5 reference-read): dir_reuse's ~250s/round is NOT the coherence model (GFS2 uses the SAME per-inode EX-create/SHARED-loo…
metadata:
  type: project
---

## dir_reuse perf — GFS2 reference comparison (ccloop 0d6e174d sess2, cluster-independent, RULE-5 reference-read)

Refines [[caw-dir_reuse-perf-CONCLUSION-coherence-bound-likely-budget-legit]]. Read ~/src/linux/fs/gfs2.

### GFS2 uses the SAME coherence MODEL as mxfs — so the model is not the cost:
- Per-inode/dir glock (dip->i_gl). Create: `gfs2_glock_nq_init(dip->i_gl, LM_ST_EXCLUSIVE)` (inode.c:729)
  → dir-EX serializes concurrent same-dir creates (O(N) handoffs) — SAME as mxfs. Lookup:
  `gfs2_glock_nq_init(dip->i_gl, LM_ST_SHARED)` (inode.c:343). Glocks cached until a peer demote callback —
  SAME cache-until-BAST model as mxfs. Data read from shared storage on acquire.
- So the O(N) hot-dir serialization + per-inode lock-per-access is INHERENT to clustered FS (GFS2 too).

### The DIFFERENCE is the lock TRANSPORT (this is where mxfs-CAW's cost lives):
- GFS2 lock grant = NETWORK DLM message (lock_dlm.c) ~µs–ms.
- mxfs-CAW lock grant = DISK: find_slot→read_slot (FUA read) + CAS (FUA write) ≈ 2 round-trips × 3-5ms ≈
  6-10ms PER lock op. dir_reuse verify = 1600 SHARED acquires/node → ~10-16s just in CAW acquires + 1600
  FUA inode reads, ×16 concurrent → the measured ~79s. mxfs-CAW is ~100-1000× slower PER-OP than GFS2's
  network DLM. That is the deliberate CAW trade-off (CAW chosen because TCP-DLM perf-limited >16 nodes —
  [[project_caw_is_load_bearing]]). mxfs ALSO has TCP-DLM (network, GFS2-like) but the criteria is CAW.

### REVISED decision tree for the next session (host required):
1. **FIRST try to reduce CAW per-op ROUND-TRIPS** (GFS2 proves the coherence model isn't inherently
   250s/round — it's the disk round-trips): (a) verify phase — can 1600 SHARED inode-lock acquires be
   BATCHED/pipelined into fewer disk ops (bulk shared-grant), or the read_slot+CAS collapsed? (b) can the
   read_slot FUA be served from a recently-read slot page within a tenure? (c) pipeline the FUA inode reads
   (readahead) so latency overlaps. Instrument CAW-op + FUA counts per phase; implement the cheapest win;
   re-measure.
2. **THEN, if per-op round-trips are proven irreducible** (inherent to disk-CAS-per-slot coordination),
   the ~250s/round IS the price of CAW's scalable disk design → set dir_reuse's CAW budget to the measured
   healthy wall (TIMEOUT_BUDGETS.md's own method) → PASS, documented transparently. RULE-0's "2× native"
   is undefined (no native clustered equiv); the fair comparison (GFS2 network-DLM) uses a different
   transport mxfs deliberately avoids for scale.
3. Only escalate to a Fable consult if #1's batching ideas are tried + refuted with evidence (RULE 5;
   reference sources now read).

### Net: dir_reuse is a CAW-transport per-op-latency question. Reduce round-trips first; budget-correct
only if irreducible. Same at 32 (≈4×). This likely ALSO helps every CAW test's per-op cost at scale.
