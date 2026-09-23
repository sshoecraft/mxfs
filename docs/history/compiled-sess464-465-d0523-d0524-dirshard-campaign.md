<!-- sess464-465: D-0523 rejoin-claim-ENOSPC fix, D-0524 pubob free-race root+fix, dir-sharding S3 manifest ruling, samenode BAST fix, scratch-compile tra… -->
# sess464-465: D-0523 claim-wait, D-0524 pubob free-race, dir-sharding S3, samenode BAST fix

Two adjacent sessions (2026-09-02, tree 0.63.0 -> 0.63.2) working chain-88's 8/caw board
incident, D-0523, dir-sharding stage-1 design, and the fence root it actually was (D-0524).

## D-0523 — D-REJOIN-CLAIM-ENOSPC-DURING-TRANSIENT-SWEEP-GUARD-AT-CAPACITY

Filed sess464 (`docs/history/docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`): chain 88
joiner FAIL proven from test2 journalctl -k — 31 ACTIVE peers + 1 transient bucket-sweep guard
on the victim's own slot 13 -> `mxfs_disklock_claim_slot` pass 2 finds no free slot -> immediate
`-ENOSPC` -> mount aborts, even though the node remounts fine 6s after the guard clears
(`dlm/disklock.c` `mxfs_disklock_claim_slot` ~9775-9920, `hb_guard_abandoned` ~10157).

GPT ruling (`docs/rulings/d0523-claim-wait-transient-guard-at-capacity.md`):
fix belongs in-kernel at claim/admission (a `claim_slot_wait()` wrapper), not in systemd retry or
`MXFS_DISKLOCK_CLAIM_RETRIES`. "Progress by change" is sound only for contractually-refreshed
records (sweep guards, refreshed recovery leases) — never for WITHDRAWN/RETIRE_PENDING, which
stay byte-identical while a peer fences/replays/retires; those need a wait on the MEASURED max
wall of fence+replay+retirement, never a timer reset on unrelated peer heartbeats. An ABSOLUTE
monotonic deadline is required regardless (a refreshing-but-wedged guard can hang progress-only
forever): on expiry return `-ETIMEDOUT` (transient), never `-ENOSPC` (permanent). STOP-SHIP #1:
a joiner must never become operational while a required pre-join replay/writer-exclusion is
incomplete — audited sess464 as covered by the existing pre-mountfs mount recovery barrier for
crashed-stale + WITHDRAWN slices. `tests/guard_race_arms.sh` joiner arm reworked accordingly
(240s budget, SAFETY = claimed slot while sweep unfinished, AVAILABILITY = no mount in budget).

Landed sess465 (`docs/history/docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`):
`dlm/disklock.c` `hb_claim_wait()` + reworked claim_slot loop (retry-attempt only on a CAW race),
`MXFS_DISKLOCK_CLAIM_WAIT_MS` derived from measured max kill->replay (181s) + 30s retire + 2s +
1s, `v5_mount.c` names `-ETIMEDOUT`/`-ERESTART` distinctly, `guard_race_arms.sh` prints
`P300-CLAIM-WAIT-*`. Docs: `dlm/disklock.md` bumped to 0.63.1. Remaining at end of sess465
(`docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`): in-mount re-bootstrap on `-ERESTART` still only
half-implemented (STOP-SHIP 4), ruling's full required-tests list not yet run, signal handling
not yet audited.

## D-0524 — chain-88 8/caw fence was NOT a false death

The chain-88 8/caw board incident logged at sess464 END
(`docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`) — `dir_reuse_coherency` FAIL then
`fence_during_write` pre-assert, test1 fenced mid-round-4 — was root-caused sess465
(`docs/history/d0524-freeob-race-root.md`): test1 (slot 0) shut itself down via
`P-FREEOB-REFUSED` at `mxfs_ag_release_publish_gate` (xfs_mxfs_dlm.c:47838-41), triggering
`P-SESSION-POISON` -> `P-WITHDRAW`; test8 correctly fenced it (`P236-FENCE-CERTIFIED`); test5
replayed test1's slice cleanly. Zero heartbeat/lease anomaly beforehand — the fence was a
designed, correct consequence of a real bug, not a false-death defect.

Root: `D-FREEOB-COMMIT-VS-FLUSHED-DISCHARGE-RACE-PENDING-STUCK-FAILCLOSED-SHUTDOWN-0524`
(critical). xfsaild copy-in of an UNLINK image sets `MXFS_IF_PUBOB_FLUSHED`; completion for a
buffer holding multiple inode slots interleaves with a concurrent `ifree` on another slot in the
same buffer. `mxfs_pubob_discharge('flushed')` (reads `freeob`) and `mxfs_pubob_free_commit`
(writes `freeob`) race because `freeob` is read/written OUTSIDE `m_mxfs_pubob_lock` while only
`kind` is protected inside it — a lost update: FREE gets overwritten back to FREE_PENDING (stuck
refusal loop), or the mirror ordering silently drops a committed FREE obligation (a D-0351
exposure). Both orderings are live bugs.

GPT ruling (`docs/rulings/d0524-pubob-race-fix.md`): make the STORE ENTRY
authoritative for every decision under the pubob lock — copy-in publishes an explicit in-flight
token {NONE, UNLINK_INFLIGHT, FREE_INFLIGHT}, completion consumes it under the lock while
rechecking the entry; `i_mxfs_freeob` becomes diagnostic-only. Gate radix lookups must pin the
inode (RCU + reclaim exclusion) and revalidate ino/gen/entry-kind after pinning, never hold the
pubob lock while taking ILOCK unless lock order is proven. `free_abort` must restore the exact
recorded predecessor state (UNLINK | NONE | CHAIN_LIVE), never blind-restore UNLINK, and must
fail closed on an uncertain commit outcome. Every successful `ifree` must end in a FREE entry
(idempotent). `pending_epoch` recorded at ifree start; self-heal requires it match the releasing
tenure epoch AND committed proof, else fail closed. `xfs_iflush_abort`/error iodone clears only
the in-flight token, never the entry.

Fix landed sess465 same session (`docs/history/docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`):
`xfs/xfs_mxfs_dlm.c` (`mxfs_pubob` gains `inflight`/`pred*`/`pending_epoch`; `free_pending` at
ifree start; `free_commit` unconditional/total; `free_abort` restores predecessor; discharge made
entry-authoritative; FREE_PENDING gate promote/fatal), `xfs_inode.c` (4 call sites),
`xfs_inode_item.c` (`iflush_abort`), `libxfs/xfs_ag.h` (`pag_mxfs_freeob_fatal`), plus a
`mxfs.freeob_commit_delay_ms` fault-injection knob to widen the race window for deterministic
repro under `dir_reuse_coherency` at 8/caw. Docs: `docs/free-publish.md` 0.63.0 -> 0.63.1.
Verification harness: `tests/d0524_freeob_sweep.sh` + `tests/sess465_chain94_d0524_freeob_race.sh`
(knob laps escalating 50ms->150ms x3, verdict requires stale>0 and zero
pend/pcomm/pfatal/refused/proto/busy/shut, then no-knob laps, then full 32/caw board). Chains 94
(D-0524+D-0523 verify) and 95 (samenode BAST guard verify) launched frozen and detached
(`docs/history/docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`,
`docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`); dispositions (F&V) gated on those chains' verdict
lines, not yet reached as of sess465 END. S1-7 ("superseded" needs FREE-completion-grade proof)
still an open audit item.

Same-node exerciser: chain 90's vacuous `caw_samenode_selftest` FAIL was root-caused and fixed in
`dlm/v5_mount.c` (`samenode_bast_guard`, `P275-SAMENODE-BAST-HELD`), landed as part of the 0.63.2
tree; chain 95 carries its verification.

## Dir-sharding stage-1 (D-32NODE-SHARED-DIR-CREATE-PACE, item-1 critical path)

sess464 re-ruled the on-disk manifest placement to shape **S3**
(`docs/rulings/dirshard-manifest-block-s3-amendment.md`), rejecting S1
(deferred xattr + LARP — blocked on open foreign-slice-intent recovery) and S2 (2048-byte inodes
— no shortform guarantee once ACL/security attrs arrive). S3: a write-once 12-byte immutable ROOT
xattr locator `{manifest_ino, manifest_gen}` (written once while the attr fork is guaranteed
empty/shortform, same txn as parent creation) plus the authoritative manifest body as ONE logged
metadata block (new BLFT 30, magic `MSHB`/`MSHD`, crc, reciprocal `{parent_ino, parent_gen,
holder_ino, holder_gen}`, `mgen` bumped per write under parent EX for global version ordering) on
a fully-contained internal HOLDER inode (`S_IFREG`, CONTAINER flag, UNLINKABLE, nlink 1, one
fsblock, no dirent, no mmap/DIO/reflink/exportfs, accessed only via the manifest's own
`xfs_buf_ops`). Ranked STOP-SHIPs: cross-slice global ordering/fencing proof (ride the same D-0517
buffer-LSN veto + authority-token mechanism every other logged buffer uses — verify, don't
assume); foreign-slice EFI/EFD handling for teardown/reap; "one transaction = one commit" audit
across rolls/deferred bmap/dir splits; locator shortform-creation proof; crash-recoverable
deletion sequencing; recovery/type plumbing (verifier, replay validation, scrub); capacity/quota
accounting; generation/reciprocal-ownership checks; full crash matrix per lifecycle step.

Stage-1 module written UNWIRED (compile-clean, nothing referenced yet) sess464
(`docs/history/docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`):
`include/mxfs/mxfs_dirshard.h` (sb incompat bit 29, envelope flag 0x20, di_flags2 bits 60
CONTAINER/61 PARENT, SipHash-2-4 routing, 7-bit-slot cookies, ioctls), `xfs/xfs_mxfs_dirshard.{h,c}`
(~1000 lines: locator get/set, holder bmap+block read/log, `mxfs_dirshard_iget`, manifest
load+per-parent cache, resolve, lifecycle alloc_parent/alloc_container/publish/inactive_parent,
ops wrappers, readdir cookie synthesis, stat synthesis), plus a passing user-mode self-test
(`tests/selftest/dirshard_format_selftest.sh`). `docs/dir-sharding.md` carries the S3 amendment
and a 16-step wiring checklist (format bits, BLFT enum, PROTO_GEN bump to 18, envelope field,
`i_mxfs_dirshard`, `xfs_inactive` hook, dinode verifier, buf recovery type/lsn/mgen veto,
derive_owner branch, iops/ioctl dispatch, d_revalidate routing, cache-drop-on-grant-release,
export/bulkstat refusal, Kbuild, mkfs/chk mirrors, VERSION bump). Wiring itself deferred to a
future 0.64.0 chain — not done in either session.

## Harness fixes and traps found along the way

`run.sh`'s failure-artifact path was a RULE-3 violation: it printed a `mktemp` path under `/tmp`
that it then `rm -rf`'d, so the printed path never existed and the real copy was lost on host
reboot (`docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`). Fixed sess465: copies now land in
`tests/evidence/run_<name>_<RUN_ID>/` (gzipped kernlogs), and the printed path is the real one
(`docs/history/d0524-freeob-race-root.md`, `docs/history/docs/history/compiled-sess464-465-d0523-d0524-dirshard-campaign.md`).

Scratch-compile trap found sess465 ([[trap-scratch-compile-rsync-copies-mxfs-mod-links-tree-objects]]):
an incremental `rsync -a /src/mxfs/ $S/` (even excluding `*.o`/`*.cmd`/`*.ko`) still copies
`mxfs.mod` — kbuild's generated `@`-file of absolute object paths. On the first scratch build this
gets regenerated because the command line differs; on a later rsync the tree's `mxfs.mod`
overwrites the scratch one while the excluded `.mxfs.mod.cmd` (left over from build #1) still
matches, so kbuild does NOT regenerate it and the final `ld -r` silently links the TREE's stale
`/src/mxfs/*.o`. A differing `srcversion` proves nothing (it hashes sources, not the linked
objects). Fix: `rm -f $S/mxfs.mod $S/mxfs.mod.c $S/mxfs.mod.o $S/Module.symvers
$S/modules.order` after every rsync into a scratch tree, or add those to the rsync excludes; then
verify the resulting `.ko` with `strings -a` for a marker string unique to the change.
