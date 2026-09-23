<!-- sess461-463: item-5 EFI completion/takeover design (inc1-4 rulings), D-0522 quarantine double-add panic found+fixed, ungated-images closure blocked,… -->
# D-FOREIGN-SLICE-INTENTS-ABANDONED item 5 (real EFI completion engine) — sess461-463 campaign

One continuous design/build arc: item-5 goes from design (inc1 census) through two RULE-5
rulings (inc2 plumbing, inc3+4 completion+takeover) while the same three sessions also land
an unrelated critical defect found via the same rig chains (D-0522) and rule two adjacent
questions that end up gating item-5's own closure path (D-FOREIGN-REPLAY-UNGATED-IMAGES
closure, directory-sharding stage1-2 shape). Tree version climbed 0.61.7 -> 0.62.0 -> 0.62.1
-> 0.63.0 across the arc; each build stayed compile-clean before every chain build per the
"no edits to compiled source between chain builds" discipline established this arc.

## sess461 — item-5 design entry + inc1 landed, D-0517 relmark side-investigation

Parallel to item-5, sess461 disproved one relmark-vacuity hypothesis for D-ICP/D-0517: the
`mxfs_relgate_fault_stage_set` knob setter is not the cause (accepts 0..21, reads back armed
on every chain-85 arm); the surviving hypothesis is that the RELEASING node is always the
kill victim, and volatile node journald (prior trap) destroys the evidence before it can be
read. Landed `TCK_PREKILL_GREP` (bounded pre-kill ssh probe) and `iclus_relmark_faults.sh`
sweep, queued chain 89 to force a cluster release on the armed victim before the kill and
settle H1 vs H2. See `docs/history/docs/history/docs/history/compiled-sess461-463-item5-completion-dirshard-campaign.md`.

Item-5 design question fielded: census keeps only `ag_mask`, not extents or txn verdicts;
`xfs_alloc_has_records` picked as the EMPTY/FULL/SPARSE idempotence primitive. RULE-5 ruling
`docs/rulings/intents-item5-efi-completion-design.md` set the shape for
everything downstream: freeze home = the victim's recovery descriptor (obl_ag_mask, never an
AG-resource hint alone); no persistent per-extent dedup ledger needed given four conditions
(peers can't allocate the frozen AG, local activity can't either, predecessor owner's slice
replayed+flushed before free, F6-check+free serialized under AGF in one txn); completion is a
direct single-txn free with buffer images in the owner txn — **no recursion via a new EFI**;
AG transfer only from the original victim or a dead prior owner whose slice is already
IMAGES_REPLAYED and flushed. Seven STOP-SHIP conditions (SS1-SS7) and a 15-step minimal
protocol were set as the target shape for inc2-4.

Increment 1 landed in tree as 0.62.0 (scratch sv E638B428 clean): `xfs_mxfs_icensus.{c,h}`
keeps per-EFI extents + intent txn verdict + ambiguous-done verdict, `mxfs_icensus_classify()`
implements the SS7 matrix + overlap sweep. Same build folded in the R8 ordering fix: the
ADMITTED line must print from `mxfs_domain_admitted_announce()` *after*
`mxfs_transport_domain_admit` passes, not from `mxfs_durability_domain_admit` before it.
Chain 86 (review #6 conditions) partial harvest found a real harness gap, not a hang: the
`workerhang`/`workerhangheld` arms passed through the quarantine/refusal assertions but the
post-hang remount step ran an *unbounded* umount that produced no output for >180s (arm
rc=124, victim dmesg lost to the next prep) — harness fix deferred until chain 86 finished
executing. See `docs/history/docs/history/docs/history/compiled-sess461-463-item5-completion-dirshard-campaign.md`.

## sess462 — inc2 ruled to plumbing-only; D-0522 found and fixed via the same harness gap

RULE-5 ruling on increment 2 (durable obligation list in the ~60KiB unused rman-slot pad
between the 4KiB header and 64KiB entry area) accepted P2: a durable RECOVER-extent list
beats census-only re-replay on takeover, IF the rman slot is formally partitioned (fence
prover owns header+entries; recovery owner owns [4KiB,64KiB)), the list becomes IMMUTABLE
once referenced by IMAGES_REPLAYED, and the header binds fs/LUN id, victim node+incarnation,
slice id+seal+generation, a stable `recovery_gen`, publication seq/nonce, and a full census
digest (no truncation). Critically: **inc2 must not flip the terminal-quarantine disposition**
— a real open-EFI victim stays quarantined until completion+takeover+prior-owner-replay+
SPARSE-quarantine+durable-completion-proof+OBLIGATIONS_DONE land together in inc3+4; inc2 may
only land format/serializer/validation/state-machine-gate code, optionally writing the list on
the rig pre-emptively if flagged TERMINAL/EVIDENCE-ONLY so it can never short-circuit the
refusal path. Ten ranked STOP-SHIPs recorded, the top three being: IMAGES_REPLAYED must be
durable only after home-write+flush (not the reverse), OBLIGATIONS_DONE must be structurally
unreachable without completion proof, and no disposition flip without the full completion set.
See `docs/rulings/item5-inc2-obligation-record-plumbing-only.md`.

Chain 86 harvest then surfaced an unrelated critical defect through the same
workerhang/workerhangheld arms that sess461 flagged as a harness gap: both victims had
actually **panicked in `mount`**, not hung. Root cause: `v5_retire_worker_stop` runs twice per
unmount (once from `detach_pr_key`, once from `shutdown`); a stuck worker makes both calls
time out, each pins the module and calls `v5_quarantine_add`, producing a self-referential
quarantine list (`ctx->quarantine_next == ctx`); the next mount's `v5_quarantine_reap` frees
the context then revisits the freed pointer (test7 faulted in reap, test5 in the kfree path).
Filed and fixed as **D-RETIRE-QUARANTINE-DOUBLE-ADD-SELF-LOOP-MOUNT-PANIC-0522** (critical) in
tree 0.62.1: stop returns `-ETIMEDOUT` immediately if already quarantined, and
`quarantine_add` refuses duplicates. Also confirmed R8 (ADMITTED-before-REFUSED ordering) as a
real domain-admission-matrix failure, fixed by the same sess461 announce-ordering change; and
fixed two harness bugs in `depart_crash_cuts.sh` (NFS `/src` not restored before
`prep_node.sh` on a rebooted victim; a slot-lookup pipe that discarded stderr under a 20s
timeout into an empty evidence dir). See
`docs/history/docs/history/docs/history/compiled-sess461-463-item5-completion-dirshard-campaign.md`.

Tree advanced to 0.63.0 (D-0522 fix + inc2 plumbing: `dlm/recov_obl.{h,c}`, disklock
obl write/read/publish_refusal_obl + advance gates, verdict-list export, chk_mxfs decoders;
disposition of an open-EFI slice unchanged/terminal per the inc2 ruling). Chains 92 (D-0522
verify: expect exactly one STUCK + one AGAIN, remount admitted, zero serial faults, no oops)
and 93 (inc2 evidence, conditioned on the census actually seeing recover>=1) queued. Harness
edits also landed in `settle_token_arms.sh` (assert STUCK-once + AGAIN in both workerhang
arms; bounded remount; serial-fault check via `sudo -n tail`, never a redirect of the
root-owned serial log) and `d_intents_undischarged_verify.sh`. Build trap recorded: a struct
forward-declared only in `disklock.h`/`recov_obl.h` and referenced in a `v5_mount.h` prototype
needs an explicit `struct x;` forward decl — `v5_mount.h` doesn't include either header, and
omitting it turns "declared inside parameter list" into `-Werror=incompatible-pointer-types`
at the XFS call sites. See `docs/history/docs/history/docs/history/compiled-sess461-463-item5-completion-dirshard-campaign.md`.

## sess463 — inc3+4 ruled STOP-SHIP; item-1 closure blocked; dir-sharding shape ruled

RULE-5 ruling on increments 3+4 (the completion engine + AG takeover itself): core
EMPTY/FULL/SPARSE algorithm accepted as sound, but the submitted design is STOP-SHIP on ten
ranked conditions (SS-A..SS-J). The two structurally hardest: **SS-A** — a node-local scan of
the 64 HB sectors for OPEN cases races every purge path (purge sees no OPEN under a stale
snapshot, strips the AG, and the completing case then finds no holder = false
FREEZE_LOST); the fix must be a cluster-wide publication/purge guard (a CAW/DLM resource, not
a node-local mutex) that every purge path (including new-joiner and mount-barrier) holds
across its full scan+validation+mutation, fail-closed on any unreadable/corrupt sector. **SS-B**
— two OPEN cases can cover the same AG; unlocking at one case's OBLIGATIONS_DONE while another
is still OPEN leaves the AG uncustodied; needs a durable per-AG custodian protocol so unlock
only fires when no other OPEN case still covers that AG. The remaining eight (SS-C generation-
bound transfer with per-AG transfer receipts; SS-D canonical CAW image after transfer; SS-E a
real local-exclusivity credential distinct from "current task == recov_task"; SS-F
OBLIGATIONS_DONE cleanup ordering against a completer that dies before unlocking; SS-G a
durable proof block binding the full authority/transfer chain; SS-H an explicit
F_CENSUS_ZERO discriminator so "no record" can never be read as "zero obligations"; SS-I a
dependency scheduler so a single reap worker can't starve on one blocked case; SS-J a complete
error/release matrix that never lets a read/commit/shutdown failure fall through to FULL or
count-0) are all required in the same change set, plus an RMAPBT feature-gate hard-check (the
!rmapbt assumption behind `ANY_OWNER` isn't otherwise enforced) and a long list of mandatory
takeover crash-edge tests. See
`docs/rulings/item5-inc3-4-completion-takeover-stopship.md`.

Implementation map recorded exact tree anchors for the inc3 rewrite across the recovery
ladder (`dlm/v5_mount.c` 9232-9726), the XFS reap caller, verdict/census export
(`xfs/xfs_log.c`), disklock recovery-advance/obl write, the CAW structural rule that only a
purge-class CAS may clear another node's EX bit (so the AG transfer needs a new
`MXFS_CAW_CAS_F_TRANSFER` flag or a purge-class CAS), and the XFS-side AG lock/BAST/F9-drain
call chain — split into sub-steps 3a (inert structs, no behavior change), 3b (guard resource +
fail-closed OPEN scan wired into every purge path), 3c (the engine itself: credential,
RECOVERY_INSTALLING/EXCLUSIVE, transfer op, receipts, proof, DONE cleanup, dependency requeue,
RMAPBT gate, verdict flip). See
`docs/history/item5-inc3-implementation-map.md`. Ruling banked into
`docs/dlm-protocol.md` "Increments 3+4"; new UNWIRED `dlm/recov_obl_done.{h,c}` written
(128B transfer receipts + 4KiB two-phase completion proof), syntax-clean except a layout
guard requiring `MXFS_RECOV_OBL_MAX_EXTENTS` to drop 3072->2048 at wiring time; hard session
rule was no edits to any compiled source until the chain-89 prod build log existed. See
`docs/history/docs/history/docs/history/compiled-sess461-463-item5-completion-dirshard-campaign.md`.

Separately, sess463 forced a disposition ruling on **D-FOREIGN-REPLAY-UNGATED-IMAGES**: can it
close F&V when the 32-node board is clean except a `crash_consistency` row that fails only as
a RULE-0 timeout (all correctness checks pass) attributable to the separately-tracked
D-32NODE-SHARED-DIR-CREATE-PACE/D-401? Ruled **DO NOT CLOSE** — "board clean" in the closure
criterion is a literal outcome test, not an attribution test; reinterpreting it after a known
failure is exactly the forbidden precedent. Status stays OPEN, labeled "FIX IMPLEMENTED;
VERIFICATION INCOMPLETE — blocked on D-401/D-PACE"; the 10-consecutive-NDR streak resets on
any further relevant build change; closure needs the crash_consistency row to actually pass
inside the *unchanged* 90s budget on the final build. Net effect: the shared-directory
create-pace fix is now on item 1's critical path. See
`docs/rulings/ungated-images-board-clean-literal-verification-blocked.md`.

That dependency immediately pulled in a ruling on the directory-sharding design
(D-32NODE-SHARED-DIR-CREATE-PACE/D-401, symmetric sharding, stages 1-2 concrete shape):
directionally accepted, NOT code-ready as submitted. Twelve ranked STOP-SHIPs, the top ones
being: no global `ILOCK_EXCL`->DLM-PR remap (introduce explicit `MXFS_DIR_PARENT_PIN`/
`_BARRIER` modes instead — chmod/chown/ACL/xattr/repair all legitimately need real parent
exclusivity); routing must sit *above* `xfs_dir_createname`, not inside it, via a resolver
that turns {logical parent, physical shard} into a normal dir2 call; shard container lifecycle
must be transactionally closed (create+manifest-append in one txn, publish atomically, deletion
restartable via {ino,gen} checks); dcache invalidation for shard-keyed events against
visible-parent dentries is unsolved and explicitly STOP-SHIP; rmdir/emptiness needs a true
parent-EX barrier; nlink = 2 + sum(shard_nlink - 1); readdir needs an explicit cookie scheme
reserving 0/1 for logical `.`/`..`. Hash keying: SipHash-2-4 with a per-directory random key in
the manifest, not crc32c. Exposure model: Model A, a narrow opt-in that fails deterministically
`-EOPNOTSUPP` for unsupported ops, default OFF — never a mount-wide "shard everything" switch.
Pre-stage-3 rig evidence gate: N=16/32/64 vs unsharded, hard gate that unchanged production
workloads stay under the existing 90s board budget, explicitly-sharded runs materially faster,
p95 <= 30s at N=32. See
`docs/rulings/dirshard-stage1-2-concrete-shape.md`.

sess463 END relay: chain 87 DONE (NDR 6/6 PASS; board 27 PASS + the expected
`crash_consistency` FAIL confirming the pace block is the only thing standing between
D-FOREIGN-REPLAY-UNGATED-IMAGES and closure); chain 88 running 0.63.0's build clean but its
`guard_race` joiner arm failed with an undiagnosed ~37s window (test2 booted+mounted inside a
180s hold but was declared FAILed at ~100s — suspected harness window bug, not yet a filed
defect). All three sess463 rulings banked; next-session order set as: harvest chain 88's
guard_race gap and chains 89-93, then item-5 sub-step 3a (cap 2048, `F_DONE` flag,
`MXFS_RECOV_F_CENSUS_ZERO` 0x40, Kbuild wiring, chk_mxfs mirror, forge shapes) -> scratch
compile -> 3b -> 3c, with directory-sharding stage 1 (feature-bit audit, manifest format,
container flag, mkfs/chk) proceeding in parallel. See
`docs/history/docs/history/compiled-sess461-463-item5-completion-dirshard-campaign.md`.
