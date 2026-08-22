---
name: ccloop-c7ee71c6-sess344-GPT-ruling-clean-release-monitor-fix
description: sess344 RULE-5 ruling #92 D-CLEAN-RELEASE-...-526: EMPTY clean-departure arms APPROVED + mandatory claim provenance (seq+chain lineage) for missed-EM…
metadata:
  type: project
---

# sess344 RULE-5 ruling — #92 D-CLEAN-RELEASE-TREATED-AS-DEATH-PHANTOM-RECOVERY-526 fix shape

GPT (gpt-5.6-sol) APPROVED arm A + b; REJECTED putting EMPTY into hb_still_dead_stamp;
RULED the missed-EMPTY reuse race (d) is NOT deferrable — needs claim-time provenance.

## Mandatory build-1 list (GPT)
1. Shared record classifier (ACTIVE / EMPTY-clean-candidate / WITHDRAWN / GUARD /
   foreign / garbage) so every route into expire_cb classifies identically.
2. Monitor EMPTY arm BEFORE the :1343 inactive arm: monitored + magic OK +
   FLAG_EMPTY + !hb_gen_foreign -> FUA confirm -> EXACT stamp match
   (node==victim_node snapshot, epoch==nt->last_epoch, inc_valid degrade to
   node-scope) -> clean retire: un-monitor, reset node_track, distinct probe,
   NO fence/expire_cb/pending.
3. check_dead FUA confirm must classify matching EMPTY as CLEAN_DEPARTURE —
   today it only cancels on ACTIVE+advanced-ts, so a release landing between
   plain read and confirm still fires death.
4. Pending-block EMPTY arm: EMPTY + pending victim stamp (node==pn,
   inc_eq/degrade pe) -> FUA confirm -> DEDICATED unlatch (clear_recovery_pending
   + unwind election/reap state) — do NOT run recovered_cb/P163 purge path.
5. hb_still_dead_stamp semantics unchanged (or multi-state enum, never bool-false for EMPTY).
6. recovery-begin must reject EMPTY — ALREADY TRUE: recovery_begin() retired
   (-EPROTO), fence_intent :4461 accepts only ACTIVE|WITHDRAWN -> -ESTALE(116)
   on EMPTY = exactly the observed P238-FENCE-NOINTENT rc=-116.
7. Claim provenance ON DISK: claim record carries proof it consumed a clean EMPTY.
8. Epoch-change arm consumes provenance: proven-clean predecessor -> clean retire +
   rebase successor; else conservative fire (unchanged).
9. Multi-cycle miss needs seq+lineage, not just prev-stamp.

## Layout plan (sess344)
Record is fully packed (40B hdr + 416B union + 44B mepoch@456 + 12B feat = 512).
Carve: evict ring 25->23 entries (416->384; recov_body pad 200->168), insert 32B
`struct mxfs_hb_provenance { u32 magic; u32 prev_node; u64 prev_epoch; u64 slot_seq;
u32 chain_len; u32 crc32c }` between union and mepoch (mepoch stays 456; update
static asserts). crc binds to {fs_gen,node_id,epoch} like feat block.
Ring shrink changes body layout -> MXFS_PROTO_GEN 4->5 (vergate fences old nodes).

Claim rules: own-stamp reclaim -> seq=old.seq+1 (or fresh random), chain=0 (dirty
predecessor). Fresh claim from valid EMPTY+valid prov -> prev=EMPTY stamp,
seq=prev.seq+1, chain=min(prev.chain+1,cap). From zero/garbage -> RANDOM 64-bit seq
(entropy like hb_draw_incarnation), chain=0. Random restart makes cross-generation
seq collision negligible.
Monitor: node_track += last_seq (recorded from valid ACTIVE prov). Epoch-change
clean test: tracked seq in [S'-chain, S'-1] of new record -> predecessor tenancy
ended cleanly.

## v5/XFS-side unwind needed for arm 4 (unlatch)
Survivor livelock state = XFS reap loop (xfs_mxfs_dlm.c:~46600-46710) retrying off
m_mxfs_dead_slots bit; acquire refused (-EPERM/-ESTALE) forever. recovered_cb
(v5_recovered_cb v5_mount.c:2263) does note_dead + lease_unregister + purge_node +
refresh + beacon. Clean-depart needs a NEW cb that clears XFS dead-slot bit +
torn latch + election duty AND removes the departed node from membership
(note_dead/lease_unregister/refresh ARE probably still needed — the node did leave)
— open question: is purge_node safe here (node-keyed; rejoin race window microsec,
same race exists in P163 path today)? Decide next session.

## Verification
Trigger: tests/d513_lone_mount_torn.sh 32 <mounted> <helper> step-1 mass unmount
(31-way). PASS = zero "no longer responding" for released slots, zero
P163-RECOVERY-PENDING on survivor. Budget ~330s, timeout 420s. Cluster currently
DIRTY (test2 livelocked, harvest complete in
tests/evidence/sess343_mass_unmount_false_death/) — safe to re-prep.
GPT test list also: EMPTY between read+confirm; dirty ACTIVE still fences;
stale cached EMPTY then fresh ACTIVE; EMPTY wrong epoch/node/gen; EMPTY racing
GUARD CAS; ACTIVE->EMPTY->ACTIVE missed; multi-cycle reuse.

Version: on-disk layout + proto_gen bump -> minor rev (0.13.0).
#93 D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B stays separate (root-ino EX chain).
