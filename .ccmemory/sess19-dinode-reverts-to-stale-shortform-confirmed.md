---
name: sess19-dinode-reverts-to-stale-shortform-confirmed
description: sess19 DECISIVE: 2/tcp durable dir loss = on-disk dir DINODE reverts to STALE SHORTFORM during concurrent sf→block growth. P62 at acquire: disk_fmt=1…
metadata:
  type: project
---

## sess19 (ccloop 8ddb16a2) — fresh full re-diagnosis of the 2/tcp durable dir-entry loss.

## REPRO (live, build F13B9FB0, dir_force_evict=1 fua_disable=1 dir_force_block=0 dir_merge=0): `tests/cc_blockdir_probe.sh 15 50` loses at iter 2 every run. Both nodes concurrently create 50 data + 50 md5 into ONE shared dir (.ccb_2 ino=1962). Lost entries are node2's OWN md5 sidecars (e.g. f4,f10,f27,f39,f45,f50.md5), missing on BOTH nodes incl. the creator. **PERMANENT** — re-polled 0/10/20/40/60s with drop_caches on both nodes, stayed missing. (sess18's "reappeared minutes later" did NOT reproduce; this is durable loss.) All P-CRNAME-DONE rval=0 (creates succeeded then vanished).

## DECISIVE EVIDENCE (dirwr=1 trace, per-iter dmesg isolated): at test1's dir-EX acquire (P-DIR-SEQ ACQ-SLOW gen=2), the reload P62-RELOAD-FORK-SHRINK shows **incore_fmt=1 disk_fmt=1 disk_size=27 count=1 names=[node2_f45.]** — the ON-DISK dir dinode 1962 is SHORTFORM with ONE entry, even though both nodes had concurrently added ~100 entries each. So the on-disk dir DINODE reverted to a stale shortform image, durably dropping the block-format dir. Then test1 RMWs/creates onto that 1-entry base and re-grows → peer's (and its own later) entries durably lost. The dir format THRASHES sf↔block on both nodes (P62 flips fmt 2→1→2, shrink=1).

## CROSS-NODE TIMING: the [monotonic] bracket timestamps are PER-NODE, NOT comparable across test1/test2 (different uptimes). Use realns (CLOCK_REALTIME) to order cross-node events. test1 node1_f1 at realns…238468 overlaps test2 f50.md5 at realns…250619 (~12s window) → genuinely concurrent.

## WHAT'S RULED OUT (this session + priors, do NOT re-try): release-side drain IS durable (test2 P16-RELEASE-UNDESTAGED at handoff: all 3 data blocks undest=0 lseq==wseq); dir_force_evict=1 already on (modify_refresh DOES P106-MR-EVICT); fua_disable=1 is CORRECT for SCST (coherent cross-initiator cache — plain reads see peer writes, design-intended); block-union merge perf-doomed/wedges; read-side FUA no help; force_block no help; epoch write-guard corrupts (suppresses legit fresh-block/conversion writes).

## THE ROOT IS DINODE-LEVEL: the dir DINODE (format + di_size + extent-root) gets durably written as a STALE shortform-1-entry image over the peer's newer block-format dinode (inode-cluster lost-update for the DIRECTORY inode), during concurrent shortform→block format growth. Data-block coherency (sess83/88/97) is necessary but NOT sufficient — the dinode itself reverts. The reload faithfully adopts the already-clobbered disk; the clobber is WRITE-side (a node iflushes its stale shortform dir dinode over a newer block one).

## NEXT: GPT-5.5 consult composed this session for an architecturally-sound dinode-coherency fix (RULE-0 perf safe, Invariant-1 safe). Candidate untried fix: "inverse merge" (snapshot our in-core dirents in memory, evict, cold-read peer's durable image, replay ours) [[sess18-CORRECTION-transition-redherring-sameblock-rmw-is-root]]; or write-side guard: never iflush a dir dinode whose di_size/format is OLDER than on-disk (careful: enforce-class refuted as corrupting legit conversions). [[sess18-FINAL-insert-time-loss-reconciliation-and-path]] [[sess18-FIX-LOCUS-reload-selfskip-sf-block-format-upgrade]]
