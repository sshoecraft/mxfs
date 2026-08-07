---
name: ccloop-c7ee71c6-sess42-END-c7-shipped-orphan-defect-found
description: sess42 END: C7 version gate SHIPPED+VERIFIED (0.11.351, board 22/22); NEW D-DESTAGE-TEAR-BUCKETLESS-ORPHAN proven on disk; fix (d) orphan scan BUILT…
metadata:
  type: project
---

# sess42 (ccloop session 24) END

## SHIPPED AND VERIFIED — C7 version gate (0.11.351, srcversion 1050E85AD)
Three enforcement layers, ALL verified on the rig (tests/vergate.sh, 6 arms):
1. XFS sb INCOMPAT bit 30 (XFS_SB_FEAT_INCOMPAT_MXFS_PROTOGATE): mkfs sets it; every
   pre-gate kernel refuses via inherited unknown-incompat check — PROVEN: 350 kernel
   refused a gated format ("unknown incompatible features (0x40000000)").
2. Envelope: MXFS_FORMAT_F_PROTOGATE flag + cluster_proto_gen field (mxfs_super.h);
   kernel refuses unknown envelope flags; requires proto_gen==MXFS_PROTO_GEN(1);
   bit-absent cluster RW REFUSED unless mxfs.legacy_rw=1 (module param, logged unsafe).
   chk_mxfs -U / --upgrade-protogate = offline upgrade (O_EXCL + HB-liveness proof,
   envelope first, sb copies primary-LAST; idempotent) — VERIFIED via strip+upgrade loop arms.
3. HB feature block (12B tail of heartbeat record: magic FXFG, proto_gen, feat_flags,
   crc binds fs_gen+node_id+epoch): join gate quarantines (suspects sampled 2x for
   liveness; live incompatible incumbent => WITHDRAW -EPROTO; corpses admitted);
   monitor validates every live record per pass, confirms via prio re-read, PR-fences
   once per (slot,epoch) — VERIFIED: fake live-legacy writer fenced <=35s (fresh slot),
   join refused while it lived (P-VERGATE-JOIN), once-per-epoch held.
   NOTE: slot-REUSE intruder first rides epoch-change->fire_dead->recovery-pending
   (suppresses vergate until pending resolves) — delayed not defeated, ~10-25s extra.
Board 22/22 green on 351 + matrix 9/9 + opener_death PASS + agi REPRO=NONE.

## NEW DEFECT — D-DESTAGE-TEAR-BUCKETLESS-ORPHAN (ledger, critical, OPEN)
unlinker_death FAIL on 351 root-caused ON DISK: B's pre-death PER-BUFFER destage landed
dirent-removal + nlink=0 inode but NOT the same-trans AGI bucket insert; P227 atomic-skip
(correctly) skipped the untrusted 3-item trans (lsn=0x100003380) so replay could not
repair; sweep found bucket empty; retire declined to free. Raw probe: ino=139 mode=100644
nlink=0 next_unlinked=NULL, ALL 64 AGI buckets 0xFFFFFFFF = permanent leak.
Probabilistic (same arm passed 2x on 350 same day). chk_mxfs has NO orphan scan (gap).

## GPT ruling (full text in transcript task k4az1t4lv)
Ship order: (e) chk orphan audit -> (d) survivor orphan-adoption scan (online closure)
-> (c) last-closer fast path on same primitive -> (a) certified replay (architectural:
commit-time authority certificates + retained tenure/release records + applicability
versioning — NOT just release-CAS generation). Reject (b) destage-ordering as piecemeal
WAL. Atomic-skip ruling unchanged. Adoption-before-free mandatory (crash composition).
Authority class: "fenced recovery quiescence + EX + allocated+nlink0+bucketless".

## BUILT THIS SESSION, NOT YET DEPLOYED (srcversion 73507B59995FF428705D124)
mxfs_orphan_scan (xfs_mxfs_dlm.c, called at end of mxfs_survivor_sweep_slot):
inobt walk (xfs_inobt_walk) -> disk-truth candidates (mode!=0,nlink==0) -> per-candidate
iget + trans_alloc(tr_link) + ilock EX (DLM acquire = live-unlinker exclusion via
drain-on-release Invariant 1) -> re-verify -> membership walk of ALL 64 buckets (bounded,
anomaly=fail-safe member) -> i_unlinked_bucket=-1 + xfs_iunlink (durable adopt onto OUR
slot bucket via standard stamping) -> commit -> reap ADOPTED entry (P98-ORPHAN-ADOPT).
Prints P98-ORPHAN-SCAN-DONE cand/adopted/bucketed/changed.

## NEXT SESSION (in order)
1. Bump VERSION 0.11.352, deploy, VERIFY the orphan fix: rerun unlinker_death repeatedly
   (tear is probabilistic ~1/3) — with fix, torn shape must yield P98-ORPHAN-ADOPT ->
   P89 free (alpha outcome). Both shapes must pass. Then board.
2. chk_mxfs orphan audit (e): detect allocated+nlink0+bucketless; repair = insert into
   bucket (offline); wire into normal check flow.
3. Residual triggers: mount-time orphan scan (everyone-crashed case) + (c) fast path.
4. Ledger: C7 progress recorded under D-CROSSNODE/D-AGI entries still pending this
   session's update; sess42 investigation notes for D-CROSSNODE already written.
5. P-LKERR tripwire (350+) still armed cluster-wide — check after every run (0 so far).
6. Then: C9 TCP open tracking, D-FOREIGN-REPLAY certified-replay arc (a), remaining OPEN.

## Rig lessons (cost real time)
- tests/vergate.sh loop arm's fallocate 4G FILLED test32's 6.1G root -> every NFS ko
  copy truncated -> prep NODE_PREP_FAIL "staleness" cascade. Fixed: truncate (sparse) +
  rm at end. If prep fails md5 on ONE node: check df / first.
- Aborted board chunk leaves 30+ nodes with wedged-module refcounts -> rmmod fails ->
  manual recovery = virsh cycle those nodes + parallel prep_node with /src mount bootstrap
  (worked 31/31 first try, faster than run.sh escalation under host load 17).
- vergate hb arms leave fake-member death-pipeline residue: ALWAYS re-prep before board.
- Host load >15 (game server): prep escalation misfires (known memory); manual
  prep_fs+prep_node path is the reliable route.

## Version/state
Tree VERSION=0.11.351 but mxfs.ko is the NEWER orphan-scan build (73507B...) — bump to
352 before deploy. Cluster: 32/caw on 351 (1050E85AD), all green, orphan ino=139 present
on current fs (harmless; next prep re-mkfs wipes). 9 OPEN defects in ledger.
