<!-- sess411-412: -117/false-TORN foreign-replay family — D-527 snapshot fix, D-528 bio_add_vmalloc_chunk, D-530 kvrealloc root cause, D-529 open, D-409 c… -->
# Foreign-replay -117/false-TORN family: root cause and closure (sess411-412, 0.26.12→0.27.4)

Campaign chasing a recurring `-117` (`EFSCORRUPTED`) foreign-replay failure at
`xfs_inode_item_recover.c:373` (bad `ldip->di_magic`) first seen sess409 (slot
12) and sess410 (slot 29, `fln4_hb_churn`). Four distinct bugs turned out to be
stacked under the same symptom; each was proven, fixed, and verified in turn
per the instrument-first loop.

## sess411: instability ruled out as sole cause, snapshot+stabilize lands (D-527)

`docs/history/replay-117-root-cause-live-slice-read-race.md` root-caused
the sess410 fln4 failure: `tools/mxfs_logslice.py` (written this session,
upstream-faithful reassembly) decoded the *same* slice off the platter later
and found it 100% clean — all 25 txns committed, all 5775 inode items
magic-valid, including the ino that failed in-kernel. The kernel's item batch
(`items=100` = `xlog_recover_items_pass2`'s per-batch cap) was ≥17 items short
of the platter's real content at that ordinal. Timeline showed the victim was
still alive and appending log records when the survivor began its slice read,
22ms after the recovery lease — no drain barrier existed. Mechanism: recovery's
ophdr walk silently skips unknown-tid regions ("slack space" tolerance), so a
stale (previous-mkfs-life or in-flight) record inside a multi-record txn span
drops items with no error, and the next current record's regions fill the
wrong `ri_buf` slots → bad magic → false TORN verdict → FSWIDE quarantine.
Both observed `-117`s were `hbpause+churn` arms; `hb_idle` always passed,
consistent with an idle victim having no in-flight writes.

`docs/rulings/unstable-slice-read-snapshot-replay.md`: the design-consult rule
ruling on the fix shape. Safety bar: no home-block replay write unless every
contributing region came from one immutable snapshot, expected incarnation,
passed CRC+structural validation, and belongs to a fully reconstructed
committed txn. Phased plan: (2, land now) snapshot the slice (read A, wait,
read B, require A==B, wait, read C, require B==C, deadline 15-30s) and validate
+ replay from that one immutable snapshot only (no re-read between validate
and replay — TOCTOU); non-quiescing at deadline = new retryable class
`RECOVERY_IO_NOT_QUIESCED`, distinct from TORN. (4, deeper) per-record
mount-incarnation stamp so a previous-life record is detected, not silently
treated as slack. (Phase-3 fence-contract hardening and unknown-tid
instrumentation also specified, not yet due.) Ruled: TERMINAL TORN only when
fence certified + drained/stable + one immutable snapshot + expected
incarnation + repeated reads agree + full validation still fails.

`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`: Phase-2
landed as **0.27.0** (D-FOREIGN-REPLAY-UNSTABLE-SLICE-READ-FALSE-TORN-527,
ledger 134/59 open). `xlog` gains `l_mxfs_slice_snap` +
`mxfs_xlog_slice_snapshot()` (full-slice read + repeated-compare-pass
convergence, 4MB chunks); `xlog_do_io` serves reads from the snapshot once
captured, mirrors writes into it; deadline/alloc-fail/read-fail all map to
distinct retryable `P-FRSTAB-*` reasons, no live-read fallback ever. Captured
after `mxfs_fr_enforce_preflight`, before the one-shot injection consume
(ordering principle from sess359); freed on every `xlog_dealloc_log` exit path.
Verification (fln5, 3 arms) launched at relay boundary.

## sess412 part 1: fln5 storm exposes an unrelated bio-layer bug (D-528)

`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`: the
sess411 fln5_hb_churn run (unobserved after the runner died) got past prep and
containment, then the replayer fell into an **unbounded read storm** —
contiguous 4MB bios marching from the slice base past end-of-device at
~636MB/s / ~31k failing bios/s, starving the node's own disklock heartbeat
(`P278-HB-STALL`, D-state). Root cause (D-BIO-VMALLOC-CHUNK-COMPAT-
INVERTED-RUNAWAY-528, proven static): the <6.16 compat aliased
`bio_add_vmalloc_chunk` to a local shim returning 0-on-success, but upstream's
real contract is bytes-added (0 = bio full). `xfs_rw_bdev`'s do-while chain
loop misread every successful whole-fit add as "bio full" and never advanced,
so it resubmitted and chained forever. D-527's 66.8MB `kvzalloc` snapshot
buffer was the *first* guaranteed-vmalloc `xfs_rw_bdev` caller — prior kmalloc
luck is why 0.26.x never hit this. Fixed as **0.27.1**: upstream-faithful
bytes-added contract restored, all vmalloc-buffer call sites audited (iclog
write, PAL buf paths, recovery I/O). fln6 verification (churn/idle/log_idle)
launched.

`docs/rulings/twin-hole-fix-zeroing-strictness.md`: with
stabilization proven working (P-FRSTAB-STABLE, full replay served from
snapshot) `-117` **recurred from a stable snapshot** —
`xlog_recover_reorder_trans: unrecognized type of log operation (0)` — proving
read-instability was not the (sole) cause. design-consult ruling, implementation
order: (b, first) hard assembly-strictness invariant — no item/txn may be
assembled across an unknown-tid ophdr region; an item may never resume after a
skipped/malformed region; validate region counts/continuation before
dispatch. A discontinuity found from a *proven-stable* snapshot is terminal
for that snapshot+lifecycle-generation (new class `LOG_OPHDR_DISCONTINUITY`,
not retryable, not `TORN`) since a re-read cannot change fixed bytes. (a,
mandatory near-term) durable claim-time slice zeroing: per-(slice,
fs_incarnation) lifecycle record outside the journal payload,
`INIT_REQUIRED→ZEROING(FUA)→READY(FUA, sticky)`, restart-on-crash from
scratch, never zero an adopted/READY slice — because current mkfs
pwrite-O_SYNC zeroing is not durable on the LIO target stack (long-standing
dev note). (c) per-record incarnation stamp remains the deep Phase-4 fix.

## sess412 part 2: four bugs found and killed in one session

`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`:
- **D-528 closed FIXED AND VERIFIED** (0.27.1): 3/3 fln6 arms `P-FRSTAB-STABLE`,
  idle replay complete from snapshot, zero beyond-EOD bios.
- **D-409 closed FIXED AND VERIFIED** (second confirmation): log-error-shutdown
  correctly withdraws.
- **D-529 added**: `ATOMIC-SKIP`/`ADMIT` classification runs per 100-item
  recovery batch, not per txn — a >100-item committed txn with mixed
  authorization gets **partially applied**, a manufactured tear. Fix shape:
  classify once over the full `r_itemq`, cache the verdict, batches consume
  it.
- fln7 (0.27.2, assembly strictness landed): original di_magic signature
  **recurred anyway** — `P-FRSTAB-STABLE unstable_seen=0`, zero
  `P-FRASM-UNKTID` skips, validator silent (every item structurally
  complete). Platter decode of the failing 131-item/th_num_items=390 txn is
  100% clean; failing ino sits ~17 items past the batch-1 boundary — the
  *same* ~17-item shortfall pattern as sess410 slot 29. Not read instability,
  not hole-skips: either a parse-side stream shift or post-commit corruption
  in the batch machinery.
- Own bug found mid-session: **`EUCLEAN` and `EFSCORRUPTED` are the same
  errno (117)** — the new `ASSEMBLY_DISCONTINUITY` class (mapped from
  `-EUCLEAN`) hijacked every TORN verdict, and the publisher's accept-list
  (`dlm/disklock.c:4428`) rejected the new reason code with `-EINVAL`,
  causing publish-retry loops. **Never use `EUCLEAN` as a distinct error
  class in XFS code.** Fix (queued for 0.27.4): validator returns `-EILSEQ`
  instead; `xfs_log.c` maps it to `ASSEMBLY_DISCONTINUITY`; publisher
  accept-list extended.
- 0.27.3 added `P-FRASM-COUNT` (enforce `sum(ri_cnt) == th_num_items`,
  verified 390 on platter) as a discriminator: fires ⇒ parse-side shortfall;
  silent + di_magic bad ⇒ post-commit corruption. fln8 launched to read it.

`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`:
**the real root, D-530.** `P-FRASM-COUNT` stayed silent across 4 replay
attempts while di_magic still fired — assembly was complete and correctly
counted, so corruption happened *after* assembly-append, and the only
content-mutating step after that is the continuation realloc. Found: the
<6.13 compat `mxfs_kvrealloc(p, newsize, gfp)` called `kvrealloc(p, 0,
newsize, gfp)` — 6.8's 4-arg `kvrealloc` copies exactly `oldsize` bytes then
frees the old buffer, so passing 0 **discards the old content and leaves the
new buffer's head uninitialized**. Sole caller:
`xlog_recover_add_to_cont_trans`, hit whenever a log region straddles a
record boundary in *any* recovery (foreign, adopted, or own-crash) on <6.13
kernels. Every prior `-117` occurrence (sess409 slot12, sess410 slot29, fln6
slot27, fln7 slot26, fln8 slot13) is retroactively attributed to this same
bug — record-straddling regions losing their head. Fixed as **0.27.4** (sv
`A4159A783B5977938F7BF9B`): `mxfs_kvrealloc` now takes real `oldsize`,
<6.13 passes it through, ≥6.13 uses the 3-arg kernel-native form. Also folded
into 0.27.4: the EILSEQ/EUCLEAN fix from fln7/fln8, plus the surviving
`P-FRASM-*` instrumentation (kept as diagnosable, terminal, non-retryable
refusals).

`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`: **fln9_hb_churn on
0.27.4 FULL PASS** — victim withdraw +68s, `P-FRSTAB-STABLE`, 19
`ENFORCE-ADMIT` batches applied, zero di_magic/-117/P-FRASM hits, survivor
released the slot +1s after withdraw. First arm in the whole campaign where
every victim-side and cluster-side assertion held. Four ledger closures this
session: **D-528, D-409, D-530 (FIXED AND VERIFIED)**, and **D-527 closed via
D-530** — the unstable-read hypothesis was disproved as *cause*
(`unstable_seen=0` in every recurrence), but the snapshot+stabilization
machinery stays landed as verified hardening; residual Phase-3/4 items moved
to `docs/foreign-replay-slice-snapshot.md` follow-ups rather than ledger
entries. Ledger 58 open / 137 total. D-529 (per-batch not per-txn
classification) remained open, filed for the next queue slot, noted as
dovetailing with ledger #1's ordered per-txn verdict cache design (sess357
ruling). GPT's slice-zeroing ruling (a) design finalized but not started:
`SLICEINIT` envelope region, `MXFS_FORMAT_F_SLICEINIT`, `PROTO_GEN` 7→8,
targeted for 0.28.0 after the di_magic root was nailed (it was).

`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`: session-end state —
D-529's fix (`mxfs_classify_untrusted_txn`, a new full-`r_itemq` classifier
called from `commit_trans` before `xlog_recover_items_pass2`'s per-batch
switch, replacing the old in-batch classifier block) is **edited in the tree
but NOT built** (VERSION still 0.27.4; build as 0.27.5, `make modules` first
to confirm it even compiles — untested). Harness fix also pending
verification: `tests/fence_live_node.sh`'s `WD_RE` now accepts either
`P277-FENCED-SELF-WITHDRAW` or `P-WITHDRAW-QUEUE` (idle victims die via the
fence-notify path ~+79s; fln6/fln10 idle "FAILs" were marker-pattern misses,
not real failures) — fln11 is the first run exercising this. Explicit
do-not-rebuild-mid-run instruction: a rig-runner was mid `run.sh 32 caw`
board + fln11 on the deployed 0.27.4 build; rebuilding splits srcversion
(per `trap-never-rebuild-mxfs-ko-while-rig-run-in-flight`). Next queue after
the board: (1) D-529 fix + ledger #1 (D-FOREIGN-REPLAY-UNGATED-IMAGES)
icreate/dquot tokenization, same code region, designed together per sess357
ruling; (2) SLICEINIT as 0.28.0; (3) remaining criticals per `./defects.sh`.

## Net effect

Four defects were stacked under one repeating symptom (`-117` / false TORN
foreign replay): D-527 (unstable slice read — mitigated by snapshot+stabilize,
closed via root fix), D-528 (bio_add_vmalloc_chunk return-contract inversion —
independent bug the D-527 fix exposed), and D-530 (kvrealloc oldsize=0 —
the actual root of the entire family, present in *any* recovery hitting a
record-straddling region on <6.13 kernels, not just foreign replay). D-409
(log-error shutdown skip) closed as a side verification. D-529 (per-batch
vs. per-txn classification tear hazard) and the SLICEINIT durable-zero design
remain open, queued next. Method note: `P-FRASM-COUNT` (region-sum vs.
writer's own `th_num_items`) was the discriminator that separated "parse-side
shortfall" from "post-commit corruption" and pointed straight at the realloc.

## Sources
`docs/history/replay-117-root-cause-live-slice-read-race.md`
`docs/rulings/unstable-slice-read-snapshot-replay.md`
`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`
`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`
`docs/rulings/twin-hole-fix-zeroing-strictness.md`
`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`
`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`
`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`
`docs/history/docs/history/docs/history/compiled-foreign-replay-117-family-sess411-412.md`
