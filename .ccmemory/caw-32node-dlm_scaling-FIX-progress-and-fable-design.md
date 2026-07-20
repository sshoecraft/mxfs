---
name: caw-32node-dlm_scaling-FIX-progress-and-fable-design
description: 32/caw dlm_scaling: eviction-driven cold dir re-reads are the proven bottleneck (eviction-off 0/32->29/32). Flag-based want_ex skip (build 0510FC3E,…
metadata:
  type: project
---

## 32/caw dlm_scaling FIX — progress + Fable design (ccloop 12e0d157, 2026-07-07)

Root PROVEN in [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]]: read-command saturation of the
shared iSCSI target from cold dir-buffer re-reads at 32-node concurrency (0 solo). Aggregate op
ceiling ~1319/s → 41/node < 50 floor. Need agg ≥1600 (32×50). Reads are SEQUENTIAL within an op
(~18 × ~1ms iSCSI round-trip = ~18ms/op); SCST is NOT thread/queue starved (threads_num=8
per_initiator, sd queue_depth=32) → infra tuning won't help, the reads must be ELIMINATED.

### ⚠️ SUBSTRATE CAVEAT (read FIRST): repeated power-cycling PR-wedged the cluster
After ~20 power-cycles this session, 4/caw coherency tests failed with **reservation conflict on
test2/3/4** (all reads `got=` empty, `files present exp=120 got=0`) — the
[[pr-ua-register-fence-out-rootcause]] fence, NOT a coherency bug. So ANY coherency A/B run late
this session is INVALID (param-on AND param-off both failed identically). dlm_scaling RATE results
earlier were still valid (substrate degraded later).
RECOVERY THAT DID **NOT** WORK this session: virsh destroy ALL 32 → start 4 fresh → explicit
`sg_persist --out --register-ignore --param-sark=0x5eed` + `--clear --param-rk=0x5eed` on
/dev/mapper/mpatha (confirmed 0 keys after) → still re-wedges DURING the 4-node CAW join (prep_fs
clear pends a UA that the mount PROUT REGISTER consumes → test2/3/4 unregistered → WE-RO
reservation held by node1 → their writes reservation-conflict). Persistent, not clearing on retry.
The v0.6.1 CHECK-CONDITION retry in pal/linux/kern.c (pr_register 5×) is evidently insufficient
under the 4-node concurrent join after this much PR churn. NEXT SESSION: either strengthen the
pr-register UA retry (more retries / clear UA before register / order the join so clear+register
don't race across nexuses), OR full cold recovery (destroy all 32, clear LUN PR, longer settle,
join nodes SERIALLY not in parallel). This blocks ALL coherency validation until resolved — treat
as the immediate infra blocker before resuming the dlm_scaling fix work.

### Proven bottleneck + levers (32/caw dlm_scaling, "dirwr=1 dirland=1 ...")
- baseline: agg 1319, max 44, **0-1/32**.
- `dir_sf_mht_ms=10000`: agg 1504, **9/32** (+14%).
- `dir_release_invalidate=0 dir_force_evict=0` (GLOBAL eviction off): agg 1642, max 54, **29/32**
  (+24%). PROVES eviction-driven cold re-reads dominate. Still only MARGINAL 29/32 (3 stragglers)
  → eviction-scoping ALONE can't reliably pass; need read ELIMINATION (Fable Q3).

### The fix built (build 0510FC3E, param `dir_release_skip_nonex` DEFAULT 0 = keeper-equiv)
New `xfs_inode.h: bool i_dlm_dir_want_ex` — set in `mxfs_dlm_bast_notify` when
`requested_mode==MXFS_LOCK_EX`; cleared at inode init + on fresh grant (xfs_mxfs_dlm.c:18929
i_dlm_dir_gen++ site). Param gates `mxfs_dir_release_invalidate_data_blocks` (6236) to early-return
if `!i_dlm_dir_want_ex`. Result: +15-18% (agg ~1520-1555, 7-12/32 marginal). **Coherency safety
UNTESTED** — the 4/caw A/B was on the PR-fenced substrate (inconclusive), NOT refuted. RISK: the
flag is potentially racy vs the release path (release may read want_ex before an EX-BAST sets it /
after a grant clears it) → could serve stale. Re-validate on a CLEAN substrate before trusting.
The flag plumbing is inert when the param is off (safe to keep as a base for Fable's design).

### KEY diagnostic facts (P90-PICK, P-RDPATH, P-DIRBAST, ftrace, iostat, SCST)
- Inode alloc affinity WORKS (node_slot%agcount → spread AGs 0-31). Not the bug.
- Re-reads are cold cache MISSES (inc_rc=-ENOENT), not invalidations (P5/P34=0).
- ROOT ino=128 got 1023 P-DIRBAST ≈ 32×31 = the ONE-TIME `.dlm_scaling` mkdir-race at setup, not
  steady-state. relatime (no per-op atime); coord is MQTT (no FS barriers). Steady-state = subdirs.
- Q2 OPEN: WHY private subdirs (owned EX) evict at load. Fable ranks (1) MHT idle-demote feedback,
  (2) noino BAST collateral AG-drain, (3) DLM resource LRU. Do the eviction-provenance probe.

### FABLE's design (claude-fable-5 — correct path to reliable 32/32; NEXT SESSION)
GFS2-glock principle: consume cached dir buffers ONLY while holding ≥PR; invalidate ONLY on a real
EX BAST. The LOCK protects the cache (NOT a flag heuristic — that's why the want_ex approach is
fragile). Steps: (1) plumb release_reason+bast_mode_max; (2) MHT/idle demote dirs EX→PR keeping
buffers (retained PR keeps the BAST channel, so a later EX peer still invalidates → correct);
(3) **PR-lookup-caching for the shared parent** — hold PR on dir inodes across lookups lazily (all
32 hold PR on root+`.dlm_scaling`, PR⊥PR); lookup fast path `i_dlm_mode>=PR`→consume cache, ZERO
disk/CAW; REPLACES the forced re-read at xfs_da_btree.c:3208/3487 (`!owned_ex && dir_gen!=0`, which
exists only because lookups bypass DLM lock_flags=0); needs PR holder bitmap in the CAW lock sector
(EX needs bitmap==0/self) + BAST fan-out; (4) noino drain precision (skip inodes held ≥PR);
(5) generation in the CAW lock sector (rides the compare-read free) so NL demotions skip cold-read.
Decisive probe FIRST: tag each eviction (daddr, reason∈{BAST_EX,BAST_PR,MHT,NOINO,LRU,SELF}) and in
P-RDPATH's ENOENT hook bump cold_reads_by_reason[reason] → exact attribution of the 24000 reads/s.

### NEXT SESSION plan
1. CLEAN-RESET the cluster (PR-wedge) + confirm 4/caw + 16/caw coherency GREEN on build 0510FC3E
   param-OFF (establishes keeper baseline; my inert plumbing shouldn't change it).
2. Eviction-provenance probe → answer Q2. 3. Implement Fable #2 then #3. 4. Validate every change
   vs cache_coherency/strong_consistency/posix_multi/zero_silent_loss/dir_reuse at 4 AND 16.

### Remaining for the full criteria (NOT started)
- 16/caw dir_reuse_coherency (never run at 16). 32/caw NEVER RUN: cache_coherency, dlm_membership,
  scaling_curve, rsync_paired, crash_consistency, dir_reuse, fence_during_write, fault_netpartition,
  soak, dlm_lock_correctness. Final one-build full-ladder re-confirm 1/2/4/8/16/32.
Build: 0510FC3E (want_ex plumbing + default-off experimental param; behaviorally == prior keeper).
See [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]] [[caw-multipath-matrix-progress]] [[pr-ua-register-fence-out-rootcause]].
</body>
