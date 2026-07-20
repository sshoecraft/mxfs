---
name: caw-v064-prebump-epochconsume-fixes
description: v0.6.4 two proven 4/caw fixes: grant_seq PREBUMP before bit-adding CAS (phantom-EX closure) + CAW epoch-CONSUME at P65 when self-clean (uv resurrect)
metadata:
  type: project
---

# v0.6.4 fixes (sess4 ccloop 186320ae) — both RULE-4 proven on 4/caw mpath

## FIX A — caw_grant_seq_prebump (build 3AAFAEEF…, dlm/dlm_caw.c)
Residual hole in v0.6.3 unlock-vs-regrant closure: every slow-path grant did
`caw_slot CAS → caw_check_exclusion → caw_verify_grant_persisted (FULL SCSI
READ, ms!) → caw_grant_meta_store (seq bump)`. Fresh bit live on disk for ms
with grant_seq un-bumped → concurrent unlock's find_slot sees the bit, passes
entry/in-loop/last-instant seq checks, CAS-clears the NEW tenure. Proof: iter12
test2 ino=133 P106-EXGRANT expop=1 @.538467 → P106-STALE-EX held=0 @.539723
(1.26ms), P-UNLOCK-REGRANT-ABORT count 0 on test2 (fired on test1's parallel
instance where the store HAD landed); CAW-DUP-SLOT=0 (no slot-move false-pos).
Fix: `caw_grant_seq_prebump(ctx,resource)` immediately before EVERY
holder-bit-adding caw_slot: waiter-promote, fresh-claim, compat-add, convert
up/down, flush_held_to_disk ×2. Failed-attempt bumps are safe-direction
(spurious unlock abort → BAST re-arm self-heals). After: P106-STALE-EX = 0
across all iterations; abort now fires where clears used to slip.

## FIX B — CAW epoch-consume at P65 gate (build BD8746D8…, xfs_mxfs_dlm.c ~13645)
uv dangling-dirent root (run 20260705T232526Z, FAIL 3/4): dir shrink storm →
test4's EX grants at :19.913/:20.042 consumed NO freshness signal: P63 one-shot
handoff bit is ~80% lossy, P65 level-triggered epoch was OBSERVE-ONLY
(mxfs_dir_epoch_adopt=0 after sess49 8/tcp regression). test4 valid_epoch froze
@14 vs cluster 27 → P68-EVDECIDE kept stale dir block (b_epoch==stale
valid_epoch) → every unlink re-logged stale 18-entry image (P35E-DIRWR ledger)
→ release-drain durably resurrected node2_file28 → sf conversion crystallized
it → dirent→freed inode (P26-IGET-FAIL err=-2); disk=[node2_file28] confirmed
by P56-RELOAD-MERGE on ALL 4 nodes. Two independent block→sf conversions
(t4 ~:19.93, t2 ~:19.99) = divergence smoking gun.
Fix: at the P65 gate, on CAW + post_release + epoch!=valid, set
genuine_handoff=true when SELF-CLEAN (pin==0 && !ili_fields && !in_AIL) —
sess49's regression config (TCP + dirty grow) excluded on both axes.
genuine_handoff drives existing plumbing: P33/P43 guard bypass + P68-PREEVICT
block eviction + adopt + valid_epoch stamp (~15190). Log now has adopt=/clean=.

## Validation state (loop: MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 4 caw precond_readiness cache_coherency)
- v064b (BD8746D8) iters 1-7 PASS 4/4, STALE-EX=0, adopts firing (84+ on t1 by i3).
- iter8 TIMEOUT(240s): test1 wedged mid-uv, harness virsh-destroyed it →
  volatile journal lost the evidence. Secondary on t2: benign PR-clear -52
  burst + PRE-EXISTING mxfs_ili slab leak on rmmod-after-log-error-shutdown
  ("BUG mxfs_ili Objects remaining"). Wedge cause UNKNOWN — not attributable
  to fixes yet; 7 clean fast iters argue against adopt-storm.
- Mitigation installed: persistent journald on test1-4 + scripts/klog_tail.sh
  (clyde-side dmesg -TW collectors, /tmp/klog_testN.log, start N/stop/status).
- NEXT: resume loop to 12 green; on wedge repro, read /tmp/klog_test1.log.
[[caw-phantom-cached-ex-dirent-loss-rootcause]] [[caw-multipath-matrix-progress]]
