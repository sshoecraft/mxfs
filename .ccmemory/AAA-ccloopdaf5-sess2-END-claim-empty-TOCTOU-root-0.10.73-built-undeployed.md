---
name: AAA-ccloopdaf5-sess2-END-claim-empty-TOCTOU-root-0.10.73-built-undeployed
description: sess2 END: ROOT=claim-empty TOCTOU (re-read launders CAS; P135-FOREIGN-STRIP ×3 proven). 0.10.73 DA3FB01B BUILT NOT DEPLOYED. Deploy+storm next.
metadata:
  type: project
tags: [ccloop-daf50d34, handoff, claim-race, dirent-loss, 0.10.73]
---

# ccloop daf50d34 sess2 END (relay, 2026-07-12 ~18:40Z)

## THE PROVEN ROOT (RULE-4 complete: instrumented, caught red-handed)
**mkdir-storm dirent loss = claim-empty TOCTOU in `mxfs_dlm_caw_lock` (dlm/dlm_caw.c ~2224)**:
- find_slot_skip returns -ENOENT + empty_idx (tombstone). Between the probe and the "Bug 93" `read_slot(empty_idx)` re-read, a PEER's fresh claim of the same tombstone lands.
- The re-read returns the peer's LIVE image → our CAS(compare=live-image, write=memset-fresh gen=1 hex=own-bit) **SUCCEEDS** — compare matches current medium. The re-read *launders* the race.
- Peer's holder bits wiped + gen reset→1. Peer still believes it holds EX → double-EX → its op-side/release destage hits P-ICD-TENURE-REFUSE (held=0) → committed dirent never destaged → later holder loads pre-add base → durable loss.
- **Evidence**: storm5@0.10.72 (72MB, $SP/storm5, SP=/tmp/claude-1000/-src-mxfs/d49e53f4-da39-4651-b02e-670b4545bf9c/scratchpad): `P135-FOREIGN-STRIP ×3, all caller=mxfs_dlm_caw_lock+0x459` (= the claim CAS ret-addr; disasm-verified: it's the arm with the AG-print+EAGAIN-check after caw_slot). stripped=8 on r5 parent ino=25167954 at 18:22:00 (node1's loss round), stripped=400000/8000 on other inos. Gen "saw-tooth" (61→6) = fresh claims write generation=1 (2239) — NOT broken CAW; SCSI CAW itself verified fine.

## Fixes in tree (BUILT, NOT YET DEPLOYED): 0.10.73 srcversion DA3FB01B756616D9A0FDF3E
1. **dlm_caw.c claim-empty guard** (main arm ~2245 + batch peer-join arm ~5000): after the empty_idx re-read, `if (cur_slot->magic == MXFS_CAW_MAGIC) { P-CLAIM-RACE-LOST print; ea_claim++; sleep 1ms; continue; }` — never claim over a live slot; re-probe.
2. **0.10.71 fixes (deployed, validated dlm_scaling@32 PASS ×2, KEEP)**: (a) `i_dlm_acq_inflight` u16 (xfs_inode.h ~139, init xfs_mxfs_dlm.c ~23016): ++ at slow-path entry (~21027, under i_dlm_lock), -- at 4 exits (EDEADLK-livelock return, goto-restart, rc-shutdown, success-completion after holders++). bast_notify NONE-idle branch + CACHED-immediate branch defer via i_dlm_bast_during_acq when >0 (P-ACQWIN-DEFER, fired 23×, P-NONE-HELD-IDLE-RELEASE went 26→0); P135 NL-orphan arm parks (P-ACQWIN-PARK); dwork busy-check includes it. (b) pipeline exits only write state=NONE over DEMOTING/BAST (P-BP-EXIT-KEEP, fired 21×). (c) pre-unlock LIVE-SKIP extended: `mode != NL` defers ALL anchored unlocks (not just reaps) + P6ZC arm. Livelock-safe: waiting acquires have mode==NL.
3. **0.10.72 (deployed)**: P135-SLOTWR/HELD-MISS ungated from ino<=256 → all inode resources (still caw_instr_on()-gated). THE decisive instrumentation — keep.

## Sess2 storm history (scripts/mkdir_storm.sh 32 30; ~10s/round; runs on standing cluster)
- storm4@0.10.71: r2 HIT node3 (test3 EX granted 2ms after EDEADLK with no GRANT-WAIT; expop=1; bit 0x40000 never in any unlock read; TENURE-REFUSE rel=0 state=1 mode=5).
- storm5@0.10.72: r5 HIT node1 + the FOREIGN-STRIP conviction above.
- storm3@0.10.70 analysis (sess1 leftovers): test15 release ran mid-create (bast_notify NONE-idle on fresh grant, state trampled) → fixed by 0.10.71 items.

## NEXT (exact steps)
1. Deploy 0.10.73: `nohup setsid ./scripts/revalidate_cell.sh 32 t:dlm_scaling > $SP/r78.log 2>&1 &` then poll for CELL-GROUP; PREP FAIL(bad node build) happened once (test8 rebooted mid-prep — transient; just relaunch).
2. Enable instr: `for i in 1..32: ssh echo 1 > instr; echo 1 > dirwr; dmesg -C`.
3. `nohup setsid ./scripts/mkdir_storm.sh 32 30 > $SP/storm6.log &` — expect NO HIT ×30 AND P135-FOREIGN-STRIP==0 cluster-wide. If HIT: harvest dmesg ALL nodes, grep FOREIGN-STRIP/P-CLAIM-RACE-LOST first (P-CLAIM-RACE-LOST>0 with no strip = guard working).
4. Then the criteria ladder on the FINAL build: g1@32 (dlm_scaling done via deploy), g2@32 (`revalidate_cell 32 g2`), dir_reuse@32 (`32 dr`), then 16 (nodr+dr), 8/4/2/1 (full), `scripts/matrix_check.py --since <build-epoch>` = the YES gate (criteria.json).
- dlm_scaling@32 rate-marginality (test17 rate 45-60 vs floor 50) seen on r76 run=1 failure — was PREP FAIL actually; watch for rate FAILs recurring (playbook: caw_epoch_free_reset stale-slot-inheritance designed-never-implemented; also check my ACQ-WAIT 2s stalls).
- Deeper design debt (NOT fixed, watch): resource_id lacks inode generation (reused inos inherit slots — P-SELF-STALE-EDEADLK family); unlock gen-anchor reads lossy grant_meta; fresh-claim resets slot gen (weakens unlock_gen anchoring).
- Cluster: 32 nodes on 0.10.72 66187E16, instr=1 dirwr=1 LIVE (storm5 aftermath — rings full of P135 traffic). test8 rebooted once at ~18:16Z (rmmod-window crash, uninvestigated).
