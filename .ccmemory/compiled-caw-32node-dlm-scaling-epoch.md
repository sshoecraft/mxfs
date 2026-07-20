---
name: compiled-caw-32node-dlm-scaling-epoch
description: Compiled: 32-node dlm_scaling root (shared AG-0 reread / CAW epoch inode-reuse handoff) + the dealloc epoch-invalidate fix design.
metadata:
  type: project
tags: [compiled, caw, dlm_scaling, dir-epoch, inode-reuse, 32node, gfs2]
---

## Compiled: 32-node `dlm_scaling` root + CAW dir-epoch inode-reuse fix

Consolidates 9 raw memories on why the `dlm_scaling` ship criterion FAILS at 32/caw and the
authoritative fix design. Two investigation tracks converge here: the **read-saturation symptom**
(ccloop `12e0d157`, build `115CCA8`/`0510FC3E`) and the **code-confirmed root cause + fix** (ccloop
`0d6e174d` sess2). All fix work is UNTESTED — host was iSCSI-wedged; validation is next-session.

### The criterion
`tests/suite/dlm_scaling.sh`: each node runs `OPS=2000` × (`:>f; stat f; rm -f f`) in its OWN private
subdir `$MNT/.dlm_scaling/node$R`. FLOOR=50 ops/s/node, WINDOW=60s, FAIL if any node < floor.
Invocation: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 32 caw dlm_scaling`.
16/caw PASSES alone (~82/s); 32/caw gets ~41-44/s. It is an **aggregate ceiling ÷ N** effect: agg
throughput saturates ~1319/s → 32 nodes get 41 (<50). Need agg ≥1600 (32×50).

### Symptom PROVEN (read-bound, AG-0, peer-induced) — [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]]
RULE-4 instrumented chain on build `115CCA8`:
1. Read-bound not write: SCST vdisk (`/home/steve/disk.img`) served ~2.7GB READ vs ~289MB WRITE (~9:1),
   per `read_io_count_kb`/`write_io_count_kb` under `/sys/kernel/scst_tgt/...:shared/`.
2. NVMe backing store is NOT the bottleneck: iostat nvme0n1 r/s≈24000, r_await 0.04ms (served from clyde
   RAM), %util 46%. Bottleneck = the iSCSI/SCST **command round-trip** at huge aggregate read-command rate.
3. Reads are PEER-INDUCED: node1 solo (peers idle), 200 ops → **0** block reads (`/proc/diskstats`); at
   32-node load → ~100+ reads/op. Concurrency, not the op path.
4. All re-reads land in **AG 0**: ftrace `block_rq_issue` on test1+test16 during live 32-node run →
   31000-41000 read events/3-4s, ≥99.9% in AG 0, same ~400-block region (fsblk ≈18300-18700), each block
   read ~twice. Helper `tests/trace_reads.sh <secs> <agblocks=261653>` (agblocks=ceil(dblocks 13082614 /
   agcount 50)).
5. Inode ALLOCATION affinity WORKS (not the bug): P90-PICK shows `node_slot % m_maxagi` (m_maxagi≈50)
   spread — test1/slot0→AG0, test16/slot10→AG10, test32/slot23→AG23. `xfs_ialloc.c:2106-2164` correct.
6. DLM locks are cached (99% hit, `ag: acq=1 rel=0`), not per-op disk locks. `dir_priv_ex_skip` WORKS
   (fua dir=6). Re-reads are cold cache MISSES (`inc_rc=-ENOENT`), NOT invalidations (P5/P34=0).

Inferred (later confirmed): every node's per-op path resolution of `.dlm_scaling/node$R` re-reads the
shared AG-0 dir/inode buffers of root(ino128,AG0)+`.dlm_scaling`(AG0) from the LUN, though nobody
modifies `.dlm_scaling`. ROOT ino=128 got 1023 P-DIRBAST ≈ 32×31 = the ONE-TIME setup mkdir-race, not
steady-state. A/B confounder warning: `fua_disable=1` gave 15/32 but EXPLODED fua-count (ino=5022
dir=1851) — switches to cached bio reads AND changes coherency; NOT a clean lever, don't use as the fix.

### Eviction is the lever, but eviction-scoping ALONE can't pass — [[caw-32node-dlm_scaling-FIX-progress-and-fable-design]]
Levers measured (32/caw): baseline agg 1319, 0-1/32. `dir_sf_mht_ms=10000` → agg 1504, 9/32.
`dir_release_invalidate=0 dir_force_evict=0` (GLOBAL eviction off) → agg 1642, max 54, **29/32** —
PROVES eviction-driven cold re-reads dominate, but still MARGINAL (3 stragglers). Reads are SEQUENTIAL
within an op (~18 × ~1ms iSCSI RTT = ~18ms/op); SCST is NOT thread/queue starved (threads_num=8
per_initiator, sd queue_depth=32) → infra tuning won't help; reads must be **ELIMINATED**.

Build `0510FC3E` = flag-based experimental fix, param `dir_release_skip_nonex` DEFAULT 0 (== keeper).
New `xfs_inode.h: bool i_dlm_dir_want_ex`, set in `mxfs_dlm_bast_notify` when
`requested_mode==MXFS_LOCK_EX`, cleared at inode init + fresh grant (`xfs_mxfs_dlm.c:18929`,
`i_dlm_dir_gen++`); param gates `mxfs_dir_release_invalidate_data_blocks` (6236) to early-return if
`!i_dlm_dir_want_ex`. Result: +15-18% (agg ~1520-1555, 7-12/32) — still marginal, coherency-safety
UNTESTED, and the flag is racy vs the release path (could serve stale). Fable's verdict: the LOCK must
protect the cache (GFS2-glock: consume cached dir buffers only while holding ≥PR, invalidate only on a
real EX BAST), NOT a flag heuristic. Fable's ranked plan: (1) plumb release_reason+bast_mode_max; (2)
MHT/idle demote dirs EX→PR keeping buffers; (3) **PR-lookup-caching for the shared parent** (all 32 hold
PR⊥PR on root+`.dlm_scaling`; lookup fast path `i_dlm_mode>=PR`→consume cache, replaces forced re-read at
`xfs_da_btree.c:3208/3487`; needs PR-holder bitmap in the CAW lock sector + BAST fan-out); (4) noino drain
precision (skip inodes held ≥PR); (5) generation in the CAW lock sector rides the compare-read free.
Decisive next probe: tag each eviction (daddr, reason∈{BAST_EX,BAST_PR,MHT,NOINO,LRU,SELF}) and bump
`cold_reads_by_reason[reason]` in P-RDPATH's ENOENT hook → exact attribution of the ~24000 reads/s.

### ROOT CAUSE, code-confirmed — [[caw-HYPOTHESIS-dlm_scaling32-epoch-is-slot-aliasing-under-churn]]
(The "slot aliasing" framing in the slug name is REFUTED by its own body — cross-slot aliasing is
correctly excluded by exact-resource memcmp. Real root below.)
1. `struct mxfs_resource_id` (`include/mxfs/mxfs_common.h:60-67`) = {volume, ino, offset, ag_number, type,
   pad} — **NO inode generation.** resource_id for inode N is byte-identical across free+realloc of N.
2. `caw_claim_inherit_epoch` (`dlm_caw.c:717-726`) inherits `dir_epoch`+`last_ex_slot` from a tombstone
   iff `prev->magic==TOMBSTONE && memcmp(&prev->resource, resource)==0` — matches on {volume,ino,type}
   only → a REUSED inode (same ino, NEW di_gen, possibly last owned by a DIFFERENT node) matches the prior
   incarnation's tombstone.
3. `caw_tombstone_slot` (`dlm_caw.c:694-708`) PRESERVES dir_epoch+last_ex_slot into the tombstone — this
   is LOAD-BEARING for genuine cross-node dir coherence across an idle gap; do NOT blindly zero it.
4. Epoch advance (`dlm_caw.c:669/672-678`): on EX claim `handoff = (last_ex_slot!=NONE &&
   last_ex_slot!=my_slot) → dir_epoch++`. A reused inode that inherited a PEER's last_ex_slot sees a false
   handoff on the new owner's first EX → `dir_epoch++` → `i_dlm_dir_valid_epoch>0` (observed 8,5,32 @32) →
   `dir_priv_ex_skip` gate (needs valid_epoch==0) DISENGAGES → private-subdir FUA storm → rate<50 + node
   WEDGE.
5. Why only at 32: 32×2000 create+unlink = ~64k inode lifecycles → cross-node inode REUSE is frequent →
   pervasive false epochs. At 16 it's rare enough that dlm_scaling passes 16/16.

The FUA storm is also what WEDGES nodes → mass virsh-destroy → the clyde host iSCSI wedge (see
[[HOST-WEDGE-clyde-iscsi-cleanup-livelock-2026-07-07-needs-manual-reset]]).

### The epoch is INTRA-RUN, not cross-mkfs — [[caw-CORRECTION-mkfs-DOES-zero-caw-slots-dlm_scaling-epoch-is-intrarun]]
Corrects an earlier claim ([[caw-16node-SESSION-SUMMARY-dlm_scaling-fixed-next-caw-epoch-and-coherency-variance]])
that mkfs leaves stale tombstones. WRONG. Envelope = `[MXFS super 4KB][journal][disklock region][XFS
data]`. Disklock region = `MXFS_DISKLOCK_HB_SIZE` (64 HB slots × 512) + **65536 lock slots × 512** (~32MB).
`mkfs_mxfs.c:1636 zero_region(fd, disklock_offset, disklock_size)` zeros the ENTIRE region (BLKZEROOUT +
read-back verify, `mkfs_mxfs.c:330`). `dlm_caw.c:4017 ctx->lock_region_offset = disklock_offset +
MXFS_DISKLOCK_HB_SIZE`; `slot_offset() = lock_region_offset + slot_index*SLOT_SIZE` — the whole CAW slot
table lives INSIDE the zeroed region. So every slot's dir_epoch/last_ex_slot is 0 after mkfs → any
valid_epoch>0 is intra-run inode reuse, confirming the root above (not stale on-disk state).

### FIX EVOLUTION (chronological, ccloop 0d6e174d sess2)
Two families were considered; the hash-identity family was REJECTED, the dealloc-invalidate family WON.

**REJECTED — gen in `resource_id.offset`** — [[caw-FIX-DESIGN-dlm_scaling32-put-inode-gen-in-resource-id-offset]]
Idea: for inode-type locks, `offset` (extent block) and `ag_number` are unused; stuff `ip->i_generation`
into `offset` so FNV-1a (`dlm_caw.c:169`) hashes the gen → reused inode hashes to a different slot / fails
the memcmp. Killed by the mixed-caller constraint below (FAIL-CORRUPT).

**The constraint that kills the hash approach** — [[caw-dlm_scaling-fix-CONSTRAINT-mixed-ino-callers-hash-consistency]]
`mxfs_v5_dlm_inode_lock(dlm, ino, mode)` has MIXED callers (~17 total in `xfs/xfs_mxfs_dlm.c`, real file
not `.backup`): some HAVE ip (can pass i_generation) — lines 18660, 20252; some have ONLY raw ino (no ip)
— lines 318, 19918, 20154. If gen enters the hash and any caller supplies gen=0 while another supplies
gen=G for the same inode, the two paths compute DIFFERENT slot indices → node coordinates one inode's lock
in TWO slots → lost mutual exclusion / corruption, invisible at 1-2 nodes, rare corruption at scale. A
slot-`pad2` variant (store gen in the slot, compare at claim; `dlm_caw.h:105`) is SAFER because a gen=0
there only DISABLES the optimization (fail-safe) instead of splitting the hash — but the dealloc approach
below is cleaner still.

**BEST / chosen — invalidate CAW epoch at inode DEALLOC (GFS2 pattern)** —
[[caw-dlm_scaling-fix-BEST-approach-invalidate-caw-epoch-at-inode-dealloc-GFS2-pattern]]
GFS2 precedent (`~/src/linux/fs/gfs2`): inode identity = no_addr + **no_formal_ino (a generation)**;
`gfs2_inode_lookup` returns -ESTALE on gen mismatch (`inode.c:120-121,187`); on dealloc
`gfs2_inode_remember_delete(gl, no_formal_ino)` (`super.c:1331`) records the free on the glock, checked by
`gfs2_inode_already_deleted` (`super.c:1261`). GFS2 explicitly distinguishes a FREE from an idle release
and invalidates stale lock state at the FREE. mxfs analog: at inode dealloc (where `ip` is in hand — a
single site, no lock-path plumbing, no hash change, no mixed-caller trap), clear the ino's CAW slot
dir_epoch=0/last_ex_slot=NONE. XFS inobt coordination guarantees node A's free commits before node B can
allocate that ino → B claims a clean slot → no false handoff.

**Implementation refinement — piggyback the clear on the UNLOCK CAS, do NOT sync-FUA at free** —
[[caw-dlm_scaling-fix-REFINEMENT-piggyback-epoch-clear-on-unlock-not-sync-fua-at-free]]
- TRAP 1 (sync per-free FUA CAW op): `mxfs_dlm_caw_purge_node` header (`dlm_caw.c:3501`, sess70) PROVES a
  per-slot FUA read+CAS on a sensitive thread blocked the disklock HEARTBEAT → peers fenced this node (SCSI
  PR preempt) → reservation-conflict → log I/O error → FS shutdown → whole-cluster cascade collapse.
  dlm_scaling does 2000 frees/node → ~4000 extra FUA RTTs/node on the free path = SLOWER + cascade risk.
  DO NOT sync-FUA at free.
- TRAP 2 (pure-async stage-in-eviction-ring): correctness WINDOW — a peer can realloc the freed ino within
  ms (fast churn) before the async clear lands → stale inherit persists. Rejected alone.
- RESOLUTION: the free ALREADY releases the inode's DLM lock, and that unlock ALREADY does find_slot + a
  CAS (via `caw_tombstone_slot`, `dlm_caw.c:694`). Distinguish a FREE-unlock from an IDLE-unlock: on FREE,
  write the tombstone with dir_epoch=0/last_ex_slot=NONE (fresh); on IDLE, preserve them (load-bearing
  idle-gap coherence). ZERO extra I/O, synchronous-correct (the free's inobt update that gates realloc is
  ordered AFTER the release).

**AUTHORITATIVE consolidation** — [[AAB-dlm_scaling32-fix-AUTHORITATIVE-single-reference]]
Current single design of record (supersedes the four evolution memories above for implementation).
- Signal path: `xfs_ifree` already calls `mxfs_dlm_note_inode_freed(mp, ip->i_ino, ip->i_generation)`
  (`xfs_inode.c:3994`) → `mxfs_v5_dlm_note_inode_freed(ctx, ino, gen)` (`v5_mount.c:1592`, has
  {ino,gen,ctx}, explicitly NON-BLOCKING / stages into eviction ring). Wire a "this ino is being freed"
  signal from there to the inode's unlock/tombstone path (an `i_dlm` flag, or
  `mxfs_dlm_caw_mark_freeing(ctx->dlm_caw, ino)` that the next unlock consults).
- CAW ctx = `ctx->dlm_caw`. Model the slot clear+CAS on `mxfs_dlm_caw_purge_dead_nodes` (`dlm_caw.c:3546`,
  batched clear+CAS semantics).
- Param-gate `caw_epoch_free_reset` (default 0 = FAIL-SAFE, == build `115CCA8C` behavior); flip default to
  1 only after validation.
- OPEN for host-side tracing: the EXACT lock-release-vs-`xfs_ifree` ordering (is the DLM lock still held
  at the free hook, or released earlier at inactivate/reclaim?) — trace it to place the clear at the right
  CAS. This is next-session step-1 work WITH the host.

### VALIDATION plan (needs host — currently wedged)
`scripts/dlm_scaling_diag.sh 32 "caw_epoch_free_reset=1"` → op-rate clears 50/s floor + FUA read-IOPS
drops (skip re-engaged); dmesg: private subdirs `valid_epoch=0`; no node wedge. REGRESSION suite (all rely
on idle-gap epoch inheritance for GENUINE releases, which the fix MUST preserve — only clears on a FREE):
dlm_scaling@16, cache_coherency@16/@32, dir_reuse. Never-run-at-32 criteria remain: cache_coherency,
dlm_membership, scaling_curve, rsync_paired, crash_consistency, dir_reuse, fence_during_write,
fault_netpartition, soak, dlm_lock_correctness; plus a final one-build full-ladder re-confirm 1/2/4/8/16/32.

### Infra / substrate caveats (BLOCKING)
- **PR-wedge**: after ~20 power-cycles the cluster PR-wedged (reservation conflict on test2/3/4, all
  reads empty, `files present exp=120 got=0`) — the [[pr-ua-register-fence-out-rootcause]] fence, NOT a
  coherency bug. ANY coherency A/B late that session is INVALID. Recovery that did NOT work: virsh destroy
  all 32 → start 4 fresh → `sg_persist --out --register-ignore --param-sark=0x5eed` + `--clear
  --param-rk=0x5eed` on `/dev/mapper/mpatha` → still re-wedges during the 4-node CAW join (prep_fs clear
  pends a UA the mount PROUT REGISTER consumes → test2/3/4 unregistered → node1 holds WE-RO). The v0.6.1
  CHECK-CONDITION retry (`pal/linux/kern.c`, pr_register 5×) is insufficient under concurrent 4-node join
  after PR churn. Fix direction: strengthen pr-register UA retry (clear UA before register / serialize the
  join) OR full cold recovery (destroy all 32, clear LUN PR, longer settle, join SERIALLY).
- `/tmp/.mxfs_pass` missing after host /tmp wipe → `cp /home/steve/.mxfs/pass /tmp/.mxfs_pass`.
- Boot: 0 VMs at session start → `virsh -c qemu:///system start testN` (all 32) → `scripts/caw_preflight.sh
  32` (assembles mpatha, mounts /src, verifies READY).
- DON'T run heavy shell-fork fan-out probes (ds_probe on all 32) — runaway loops wedge mounts → run.sh
  power-cycles all nodes → 560s timeout. Use run.sh's own workload + single-node/host-side tracing.

### Build markers
- `115CCA8` / `115CCA8C` — baseline, symptom-proven, ship default behavior.
- `0510FC3E` — experimental `i_dlm_dir_want_ex` flag + default-off param `dir_release_skip_nonex`;
  behaviorally == prior keeper; +15-18% but marginal + racy + coherency-untested.
- The dealloc epoch-invalidate fix (`caw_epoch_free_reset`) is DESIGNED, NOT yet built or tested.
