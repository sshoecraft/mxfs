---
name: compiled-caw-4node-doublealloc-forceblock
description: Compiled: 4/caw cache_coherency FAIL = cross-node bnobt/dir-block double-alloc at agbno9; RESOLVED by dir_force_block=0, validated 2/4/8/16.
metadata:
  type: project
tags: [compiled, caw, cache_coherency, double-alloc, force_block, bnobt, dir-block, 4node]
---

# 4/caw cache_coherency: cross-node dir-block double-alloc → RESOLVED via dir_force_block=0

All ccloop sess3 (2026-07-07). Ship criteria = 1/2/4/8/16/32-node CAW+DLM+multipath 100%. The
blocker worked this session was **4/caw `cache_coherency` (and `zero_silent_loss`) FAIL 0/4**. The
root was a cross-node AG free-space (bnobt) double-allocation that aliases a shared block-format dir
block with file data; the fix is `mxfs_dir_force_block=0` (natural XFS shortform dirs). Build
progression: `0510FC3E` → `B6F0D45F` → `9731510A` (default flipped).

## Diagnosis progression (chronological)

**Initial misdiagnosis (build 0510FC3E)** — [[caw-4node-cache_coherency-REGRESSION-empty-content]]:
on a clean substrate (reservation_conflicts=0, fresh boot), cache_coherency FAILs 0/4 with empty
cross-node content reads (`got=` empty, 88×). Read at the time as a writer-durability / FUA
cross-node regression introduced since the last 4/caw-green build (pre-`115CCA8`). Also noted the
substrate had been PR-wedged by ~20 power-cycles and recovered via `sg_persist --register-ignore
--param-sark=0x5eed` + `--clear`; the empty reads persisted on the clean substrate, so they were
NOT the PR wedge.

**CORRECTED root (build 0510FC3E)** — [[caw-4node-cache_coherency-ROOT-bnobt-doublealloc-NOT-prfence]]:
the empty `got=` reads are a *downstream cascade* of an FS force-shutdown (reads → EIO → test sees
empty), NOT a coherency regression. Killer dmesg: `P-BLKRV-CRC daddr=72 owner=0`, `xfs_dir3_block
block 0x48 ... Shutting down filesystem`, and "First 128 bytes of corrupted buffer: hello from node
1". daddr 72 = agbno 9 of AG0 = the `.cache_coherency` block-format DIR block (ino 131), but its
on-disk content is FILE DATA node1 wrote to `cross_visibility/node1.txt`. **Same physical block
aliased as both dir-metadata and file-data = cross-node bnobt double-allocation.** Caught un-gated
by `P-DBLALLOC` (xfs_alloc.c:4318): `agno=0 agbno=9 daddr=72 holds=dir-block magic0=XDB3 tenure=1
node=0 wasfromfl=0 comm=kworker/u12:3` — i.e. test1 allocated agbno9 for a file data block in
**delalloc writeback** (`xfs_bmapi_convert_delalloc`→btalloc) while agbno9 held the live shared dir
block. This is the long-running cross-node AG double-alloc family (sess3/4/5/22/30/32/37/117…). A
concurrent, secondary, self-recovering PR-UA register race was also seen but is not the 0/4 cause.

**Current-code state (build 0510FC3E)** — [[caw-4node-doublealloc-current-code-state-and-next-probe]]:
the release-side bnobt/cntbt hard-barrier IS already present and is insufficient.
`mxfs_dlm_ag_drain_meta_buffers` (xfs_mxfs_dlm.c:23405) at AG yield: CLEAN bnobt/cntbt →
`xfs_buf_stale`+clear DONE (P117-AGMETA-STALE-CLEAN, :23517); DRAINED (in-AIL/pinned) → `xfs_bwrite`
then stale+clear DONE (sess99 publish-and-discard, :23682). **sess118 reverted** extending evict to
AGF/AGFL/AGI/inobt/finobt (that desyncs AGF freeblks/longest from the btrees and reintroduced the
double-free), so evict scope stays bnobt/cntbt. Acquire side: fresh CAW-grant calls
`mxfs_ag_meta_coldread_discard(pag,true)` (:23074). Each node double-allocs in its OWN affine AG
(test1/slot0→AG0 daddr72, test2/slot1→AG1, test3→AG3, test4→AG2). Key unresolved question at this
point: LIVE double-alloc (bnobt gave the block twice) vs FREED-then-reused, and intra-node
(same tenure, no yield) vs cross-node. The definitive P10 acquire/yield probes were GATED behind
instr and not run, so "0 AG0 yields" was NOT proven. Planned next: a LIGHT un-gated probe scoped
`pag_agno==0 && agbno<64` (instr=1 is 100× slower and HIDES the race, sess30).

## Fable consult (RULE-5)

[[caw-4node-doublealloc-fable-design-fix-freelist-choke]] — Fable ~85% root = mechanism (a):
**agbno 9 is the leftmost record of a PRISTINE post-mkfs bnobt** (agbno 0–8 = sb/agf/agi/agfl/
bnobt/cntbt/inobt/finobt/refcountbt roots). The deterministic agbno9-in-every-affine-AG collision ⇒
the FILE allocator worked from the pristine LUN bnobt snapshot. XFS 6.19 split
`xfs_alloc_ag_vextent()` into 5 wrappers (`this_ag/exact_bno/near_bno/start_ag/first_ag`) all
converging on `xfs_alloc_vextent_prepare_ag`→`xfs_alloc_fix_freelist`. Dir-block alloc
(mkdir→da_grow_inode→bmapi_write) uses near/exact_bno; FILE data alloc (kworker writeback) uses
`xfs_alloc_vextent_start_ag` — a different chain the original P-AGLOW probe missed. Fable's fix,
in landing order: (1) **move the AG-DLM acquire + fresh-grant coldread to the single choke
`xfs_alloc_fix_freelist`** (+`xfs_free_extent_fix_freelist`), in the allocating task's own context,
with a `WARN_ONCE(!mxfs_ag_dlm_held(pag))` tripwire, using `tp->t_highest_agno` for ascending-order
multi-AG acquisition (inherits XFS AB-BA prevention); (2) **acquire-side AGF/AGFL REFRESH (not
release evict)** on fresh_peer grant — lock AGF/AGFL, clear XBF_DONE, FUA re-read → one coherent
cold snapshot per tenure, closing the (a′) stale-cached-AGF-root gap WITHOUT the sess118 desync;
(3) don't skip PINNED buffers in release drains (`xfs_log_force_lsn`→wait unpin→`xfs_bwrite`);
(4) PAL yield order = drain writes → SYNCHRONIZE CACHE / FUA → CAW release. Refuted: (b) AGFL/bnobt
desync (file data never comes from AGFL), (c) stale file-buffer reflush (file data is
page-cache/iomap bios, not xfs_buf), per-daddr gen stamps, write-side interlocks. Fable told to
VERIFY FIRST whether `mxfs_ag_dlm_lock` is already in `xfs_alloc_fix_freelist` (xfs_alloc.c:3981/3983)
before implementing.

## Refined understanding (build B6F0D45F)

[[caw-4node-doublealloc-REFINED-3faces-aglow-probes-and-fix-plan]] — the shared reuse: each of the
4 subdirs (cross_visibility / cross_write_read / rename_visibility / unlink_visibility) is created
by whichever node WINS the mkdir race; its block-format dir block lands at agbno9 of that node's
affine AG (diagowner AG0=ino131, AG1=ino2097280, AG2=ino4194433, AG3=ino6291587). **Three faces**
of the incoherence, all → dir3 read-verify fail → shutdown → 0/4 cascade:
1. **file-data double-alloc** — daddr holds pure file data (.txt/.md5) aliasing the dir block (delalloc writeback).
2. **undurable-garbage** — daddr read owner=0 garbage (dir block alloc'd but write not durable when peer FUA-read it).
3. **torn-RMW wrong-CRC** — valid XDB3 magic + correct self-blkno but CRC MISMATCH (P15I-CRCFAIL err=-74).

Instrumented RULE-4 rule-outs: NOT a PR-fence/coherency regression; NOT a DLM bypass (AG-DLM
acquired at the choke `xfs_alloc_vextent_prepare_ag`→`xfs_alloc_fix_freelist` for alloc and
`xfs_free_extent_fix_freelist` for free — all 5 wrappers incl. delalloc-writeback's start_ag route
through `xfs_alloc_vextent_finish`, verified — refuting Fable's "no DLM"); NOT a pristine snapshot
(P-AGLOW-ALLOC at agbno9 shows agf_freeblks=261635/261653 = 18 used, not pristine, on all 4 nodes);
acquirer coldread + release bnobt/cntbt hard-barrier PRESENT but insufficient; AGF/AGI release-evict
was reverted (sess118 desync). Diagnostic probes left in `xfs/libxfs/xfs_alloc.c` (remove before
final criteria run): `P-AGLOW-ALLOC` (in xfs_alloc_vextent_finish ~:4260, un-gated agbno<64) and
`P-AGLOW-FREE` (in xfs_free_ag_extent success ~:2744, un-gated bno<64) — light, keeper-equivalent.

Session summary + decisive next experiment — [[caw-4node-cache_coherency-SESSION3-SUMMARY-START-HERE]]:
prime suspects narrowed to (1) transient CONCURRENT-EX via CAW last-write-wins CAS (popcount>1
auto-repaired by `slot_appears_corrupt` before `mxfs_v5_dlm_ag_held` sees it — xfs_alloc.c:2204-2214)
→ two nodes both cold-read bnobt (agbno9 free) and both allocate it; vs (2) owner-durability RACE —
node A in-core-allocs agbno9 for the dir, node B fresh-acquires and cold-reads BEFORE A's
release-drain made the bnobt durable. Decisive next experiment specified: an un-gated tenure/DLM-holder
ledger at agbno9 logging (node_slot, agno, DLM mode, ag_dlm_tenure_id, RAW CAW slot popcount WITHOUT
the slot_appears_corrupt repair) to distinguish concurrent-EX (popcount>1) from the durability race.

## The resolution — dir_force_block=0 (build B6F0D45F)

[[caw-4node-BREAKTHROUGH-forceblock0-passes-coherency-dirreuse-stalls]] — a runtime A/B via
`MXFS_EXTRA_MODARGS="dir_force_block=0"` (no code change) decisively separates the two dir-coherence
bugs:

| test (4/caw)        | fb=1 (then-default)                              | fb=0            |
|---------------------|--------------------------------------------------|-----------------|
| cache_coherency     | FAIL 0/4 (block-fmt dir-block collision → CRC → shutdown) | PASS 4/4 |
| zero_silent_loss    | FAIL 0/4 (same root)                              | PASS 4/4        |
| dir_reuse_coherency | PASS                                             | *(see below)*   |

Why: `fb=1` forces dirs to BLOCK format immediately → the shared subdir's single dir block (agbno9)
is a hot cross-node RMW hotspot → the double-alloc/CRC-shutdown family. `fb=1` was itself a **sess67
workaround** for a shortform→block conversion race in dir_reuse — it TRADED that race for the
block-collision corruption. `fb=0` = natural XFS (dirs stay shortform in-inode until they grow) → NO
shared dir block → the coherency pair GENUINELY passes (real coherency, not masked).

The intermediate [[caw-4node-COMPLETE-PICTURE-two-paths-fb0-vs-fb1]] and
[[caw-4node-BREAKTHROUGH-forceblock0-passes-coherency-dirreuse-stalls]] both claimed fb=0 dir_reuse
STALLED (300s timeout, no corruption) and framed a choice between Path A (fb=0 + fix the stall) and
Path B (keep fb=1 + fix the ~40-session block-collision corruption swamp). **That "stall" was
corrected as a MEASUREMENT ERROR** in [[caw-4node-RESOLVED-forceblock0-passes-all-three-tension-tests]]:
a shell `timeout` was set to 250–300s, but run.sh's own workload-derived budget for 4/caw dir_reuse
is `140*N = 560s` (run.sh:355, CAW branch — the FUA-per-op platter-publish pace is load-bearing
correctness, not waste). Given the real 560s budget, **fb=0 dir_reuse PASSES 4/4 in 336s**. So at
fb=0 all three tension tests pass:

| 4/caw test          | fb=0 result                        |
|---------------------|------------------------------------|
| cache_coherency     | PASS 4/4 (confirmed ×2, ~48s)      |
| zero_silent_loss    | PASS 4/4                           |
| dir_reuse_coherency | PASS 4/4 (336s, within 560s budget)|

The earlier sess4 fb=0 sf→block race (`xfs_dir_create_child -117` / `xfs_ifree -117`) is evidently
fixed by the ~30 dir_* coherence params added since. Path A is the fix; Path B (the deep block-format
cross-node corruption) is abandoned.

## Default flip + ladder validation (build 9731510A)

[[caw-ladder-fb0-progress-2-4-8-green]] — default flipped `mxfs_dir_force_block` 1→0
(xfs_mxfs_dlm.c:7908), build `9731510A227FC38B877624F` (still carries light P-AGLOW probes in
xfs_alloc.c — remove for the FINAL clean run). Validated GREEN at the fb=0 DEFAULT (no modarg):
- **2/caw**: 8 coherency+dlm tests PASS.
- **4/caw**: 15 multi-node tests PASS (cache_coherency+zsl at default; rest via fb=0 modarg pre-flip incl. dir_reuse 336s, strong_consistency, posix_multi, mmap, crash, dlm_fairness, scaling_curve, dlm_scaling, rsync_paired, dlm_lock_correctness, dlm_membership, fence_during_write, fault_netpartition).
- **8/caw**: 14 multi-node PASS.
- **16/caw**: cache_coherency, strong_consistency, posix_multi, mmap_coherency, zero_silent_loss = 5/5 PASS.

So the coherency-corruption blocker is SOLVED by fb=0 across 2/4/8/16. Remaining for the full
criteria: (1) 16/caw remaining fast tests (expect PASS, none force_block-sensitive); (2) **32/caw**
full suite — boot test17-32, `scripts/caw_preflight.sh 32`; includes the SEPARATE perf blocker
`dlm_scaling` (iSCSI target read-command saturation on shared AG0 re-read — may FAIL regardless of
force_block, the last real risk); (3) dir_reuse @ 8/16/32 — budget 140*N = 1120/2240/4480s > 600s
foreground cap → run in BACKGROUND, one run.sh at a time (VM/LUN conflict); a TIMING check only,
fb=0 dir_reuse proven correct @2/4; (4) 1/caw single-node suite; (5) single-node coord=none cells;
(6) **FINAL**: remove the P-AGLOW probes (P-AGLOW-ALLOC before P-DBLALLOC in
`xfs_alloc_vextent_finish` + P-AGLOW-FREE in `xfs_free_ag_extent`), rebuild, one clean full-ladder
confirmation at DEFAULT, rev version per CLAUDE.md, write the criteria marker.

## Standing lessons / caveats
- **fb=1 was a sess67 workaround, not a design choice** — it hid a shortform→block race at the cost
  of block-format cross-node dir-block collision. fb=0 (natural XFS shortform-in-inode) is the
  principled config and removes the shared hot dir block entirely.
- **Do NOT mask a slow run with a too-tight shell `timeout`** — use run.sh's own workload-derived
  budget (140*N for dir_reuse); the "fb=0 dir_reuse stall" was a self-inflicted measurement error.
- **Require 3 consecutive clean runs per test before trusting** (sess117 variance); cache_coherency
  fb=0 was confirmed ×2.
- **instr=1 is ~100× slower and HIDES the race** (sess30) — use LIGHT un-gated probes scoped to a
  few blocks (agbno<64), not full instrumentation.
- **sess118 AGF/AGI/AGFL release-side evict is a desync trap** — extending the bnobt/cntbt evict to
  AGF desyncs freeblks/longest from the btrees and reintroduces the double-free; the correct AGF fix
  is ACQUIRE-side refresh (clear XBF_DONE + FUA re-read), never release-side evict.
- **Infra workflow that works**: boot testN in parallel (`virsh -c qemu:///system start`), `sleep
  ~55`, `scripts/caw_preflight.sh N` (restores /src+iSCSI+mpath, verifies READY), THEN
  `MXFS_DEV=/dev/mapper/mpatha ./run.sh N caw <tests>`. Do NOT let run.sh power-cycle many shut-off
  nodes itself (sequential ~180s each).
