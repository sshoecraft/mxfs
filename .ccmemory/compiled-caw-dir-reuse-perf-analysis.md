---
name: compiled-caw-dir-reuse-perf-analysis
description: dir_reuse_coherency perf holdout @16/32: cost is inherent disk-CAW per-inode coherence (verify-bound); budget-correct after create-only fast path.
metadata:
  type: project
tags: [compiled, dir_reuse, caw, performance, coherency, timeout-budget, gfs2]
---

## dir_reuse_coherency perf holdout @16/32 nodes — compiled analysis

Single-topic compile (ccloop `0d6e174d` sess2, 2026-07-07, host-wedged / UNTESTED). Subject: `dir_reuse_coherency`
is the SOLE 16-node ship holdout — correctness is FINE (dedup+bast_wq, now default in build `115CCA8C`); the
blocker is WALL TIME. Central finding: the dominant cost is **inherent disk-CAW per-inode coherence latency**,
largely irreducible, and this is most likely a RULE-0 budget-legitimacy call rather than a perf bug. Sources
progress from first analysis → GFS2 reference compare → sharper conclusion → code-confirmed FINAL correction.

### Measured (16 nodes, dedup+bast_wq, no fair_handoff)
- ~250-280s/round × 24 rounds ≈ **~6000s** vs budget `140*N = 2240s`. Over budget.
- Per-round phase breakdown (test1 rank1): create ~50-80s, **verify ~79s (biggest)**, rm ~60s.
- 8-node baseline was ~40s/round (create 9-16, verify 4-14, rm 21 = ~1000s, PASS in 1120s). 16-node verify is
  6-10× the 8-node verify → **SUPER-LINEAR** (LUN FUA-read contention when all 16 nodes cold-verify at once).
- 32 nodes projected ~4× worse (O(N²)); same analysis, higher stakes — fix once, applies to both.
  [[caw-dir_reuse-perf-ANALYSIS-and-fix-directions-16-and-32]]

### Per-phase cost model (code-grounded)
- **verify (~79s, dominant)**: after `echo 3 > drop_caches`, each of 16 nodes cold-stats 1600 dir entries
  (readdir + `test -e` ×1600). Per Arch Invariant 2 (per-inode lock caching, ONE CAW slot per inode), 1600
  distinct inodes = 1600 cold CAW PR acquires + 1600 FUA inode reads ≈ 3200 CAW round-trips + 1600 FUA/node,
  ×16 concurrent = LUN-contended ~79s. No cross-inode caching possible (distinct inodes). The FUA read of a
  peer-written inode is the test's whole point (cold coherency) — necessary.
  [[caw-dir_reuse-perf-CONCLUSION-coherence-bound-likely-budget-legit]]
- **rm (~60s, rank1 solo, 1600 unlinks ≈ 37ms/unlink)**: rank1 holds dir-EX; each unlink = dir-block FUA
  publish + free inode (inobt/agi). CONCLUSION memory found the AG-DLM lock is CACHED (peers at barrier → no
  per-free AG round-trip), so cost = per-op FUA platter publish (budget doc's "load-bearing per-op platter
  publish"), NOT 1600 AG handoffs. (The initial ANALYSIS memory *suspected* 1600 AG-lock round-trips and
  proposed holding AG-EX across the batch — the later CONCLUSION refuted that; AG is already cached.)
- **create (~50-80s)**: O(N) dir-EX handoff, 16 nodes → 1 shared dir → handoff-bound. `fair_handoff` bounds
  starvation but adds latency (300s/round — too slow). Aging / longest-waiter-first in `caw_wait_for_grant`
  (sess3 idea) gives fairness without round-robin latency, but raw throughput stays handoff-bound.

### GFS2 reference comparison (RULE-5 reference-read of ~/src/linux/fs/gfs2) — the model is NOT the cost
- GFS2 uses the **same coherence MODEL** as mxfs: per-inode/dir glock (`dip->i_gl`). Create does
  `gfs2_glock_nq_init(dip->i_gl, LM_ST_EXCLUSIVE)` (inode.c:729) → dir-EX serializes concurrent same-dir
  creates (O(N) handoffs, same as mxfs). Lookup does `LM_ST_SHARED` (inode.c:343). Glocks cached until a peer
  demote callback = same cache-until-BAST model. So O(N) hot-dir serialization + per-inode-lock-per-access is
  INHERENT to clustered FS, not an mxfs defect.
- The DIFFERENCE is lock **TRANSPORT**: GFS2 grant = NETWORK DLM message (lock_dlm.c) ~µs-ms; mxfs-CAW grant =
  DISK: find_slot→read_slot (FUA read) + CAS (FUA write) ≈ 2 round-trips × 3-5ms ≈ 6-10ms PER lock op.
  mxfs-CAW is ~100-1000× slower PER-OP than GFS2 network DLM. This is the deliberate CAW trade-off — CAW is
  load-bearing because TCP-DLM is perf-limited >16 nodes ([[project_caw_is_load_bearing]]); mxfs HAS TCP-DLM
  (network, GFS2-like) but the ship criterion is CAW.
  [[caw-dir_reuse-GFS2-compare-cost-is-CAW-disk-transport-latency-not-model]]

### CODE-CONFIRMED FINAL correction — optimistic-CAW only helps CREATE, not VERIFY
The GFS2-compare memory over-claimed optimistic-CAW / round-trip batching as a general win. Reading the CAW
path corrected this:
- CAW acquire = find_slot→read_slot (1 FUA round-trip) + `mxfs_pal_bdev_compare_and_write` (1 round-trip). A
  SHARED/PR read-lock ADDS a `holders_pr` bit via the CAW (`dlm_caw.c:189` `holders_for_mode` PR) — it is NOT
  a read-only check. On MISCOMPARE (sense 0x0E) the CAW returns `-EAGAIN` and the caller RE-READS the slot
  fresh (`pal/linux/kern.c:2844,3242,3272`) — no current value returned.
- ⇒ Optimistic-CAW (skip read_slot, guess state, CAW) wins ONLY on a cleanly-EMPTY slot = the CREATE phase
  (fresh inode alloc → empty slot → guess empty → 1 round-trip). It does NOT help VERIFY: those 1600 acquires
  hit OCCUPIED peer-inode slots (holders/tombstones) → optimistic CAW miscompares → re-read → back to 2
  round-trips. So verify = read_slot + CAW-add-PR + FUA-inode-read ≈ 3 round-trips/inode, **largely
  necessary**.
- The ONLY way to cut verify is a coherence-MODEL change: an "optimistic READ" that does read_slot (confirm no
  peer holds EX) then FUA-reads the inode WITHOUT adding a PR bit (skip the CAW), saving 1 round-trip/inode
  (~⅓ of verify). RISK: weaker read isolation — a peer taking EX right after the check races. During
  dir_reuse verify there are NO concurrent writers (barrier passed) so it'd be safe THERE, but the model
  can't assume that globally. Needs careful design + host validation; do NOT ship blind.
  [[caw-dir_reuse-FINAL-verify-cost-necessary-optimistic-caw-only-helps-create]]

### Bottom line — RULE-0 budget-legitimacy, not a perf bug
dir_reuse has NO native-XFS equivalent (clustered-only) → RULE-0's "2× native" ceiling is UNDEFINED. The fair
comparison (GFS2 network-DLM) uses a transport mxfs deliberately avoids for scale. The project's own
`dirop_durable_caw=0` A/B already proved the per-op FUA is load-bearing (durably LOST a dirent without it).
The dominant verify cost is the irreducible price of per-inode PR coherence over the disk-CAW transport.
Therefore TIMEOUT_BUDGETS.md's OWN method ("record the healthy PASS wall and tighten") says set the 16-node
budget to the measured healthy wall (~6000s); `140*N` is a too-low O(N) extrapolation of a super-linear-but-
necessary workload. Setting it correctly is NOT "widening to pass."

### Next-session decision tree (host required), FINAL
1. Run dir_reuse@16 (and @32) to COMPLETION with generous timeout → confirm CORRECTNESS (0 dirent loss, 0
   leaf-hash holes; partial rounds already showed 0 fails). Record the true healthy wall.
2. Instrument per-phase CAW-op + FUA COUNTS (confirm each is coherence-necessary vs redundant re-read).
3. Try **optimistic-CAW on CREATE only** (empty-slot fast path, bounded/low-risk, saves the read_slot) →
   re-measure create phase. Do NOT expect it to help verify.
4. If still over budget (verify dominates): EITHER accept budget = measured healthy wall (defensible —
   necessary coherence I/O, GFS2/OCFS2-model-inherent, no native equiv; prefer this — it's honest) OR
   carefully prototype the optimistic-READ for verify behind a param + validate coherence (risky).
5. Only if doubt remains whether the cost is architecturally competitive → RULE-5 Fable consult (reference
   GFS2+OCFS2 already read); escalate to GPT-5.5 only if Fable fails. The "tried+refuted own fixes" bar needs
   the host first.
