---
name: ccloop-c7ee71c6-sess152-p248-owed-path-leak-ROOT-PROVEN-fix-design-ready
description: sess152: P248 verify run: 30/32 clean, test16/23 leak 1 entry (ino 128 PR) via OWED path. Root PROVEN: !running kills CAS retry → owed; drain never r…
metadata:
  type: project
tags: [mxfs, sess152, P248, release_all, owed-drain, lreq_gc, tenure, ESHUTDOWN, unit-attention, clyde-dstate]
---

, # sess152 — P248 verification: main path VERIFIED, owed path leaks; root proven, consult+fix next

## Verification run #2 result (`./run.sh 32 caw prep_cluster`, 178s/300s budget, teardown ON 0.11.454)
- **30/32 nodes: ZERO new P248** (main release_all retire path works at scale).
- **test16 + test23: exactly 1 leaked entry each — root inode** (`P248-LREQ-LEAK-ENT type=I id=128 tenure=0/0/0/1/0/0 pub_seq=1 attempts=0 writers=0 pin=0 clr_active=0 owed_pend=0 busy=0 oq=0`), aggregate `entries=1 guard=2 owed=5`. Both preceded by `P109-CLR-RELEASE-ALL type=I id=128 cas_rc=-108` + `P257-RELEASEALL-RESIDUE owed=1 lost=0`. No P254 (drain succeeded). kept=0 (no churn declines).
- **test29 delta -1 = dmesg ring wrap** (earliest entry 91293s vs 298920s uptime); its last leak timestamp falls in run #1's window → CLEAN in run #2.

## Timeline trap resolved (do not re-derive)
sess151's run #1 actually ran **06:27:09Z** (transcript timestamps; not the marker's 05:40). The "mystery teardowns" at 05:53 + 06:27 were prior-session/sess151 rig activity. **Old-build (≤0.11.453) teardowns print NO ENT line** — that signature distinguishes builds in dmesg history. My session started 06:29:44Z; run #2 = 06:33:24→06:36:23Z (marker mtime).

## ROOT CAUSE (RULE 4: proven from live probes + code, no guessing)
1. `stop()` sets `ctx->running = false` at the STOPPING election (dlm_caw.c ~11896/11907) **before** release_all runs.
2. `caw_slot()` retry loop refuses retries when `!ctx->running` (~line 802) → during release_all **any first-attempt I/O error is terminal** → returns -ESHUTDOWN (=-108, the observed cas_rc; original errno swallowed — the !running check precedes the retry log).
3. 32-node teardown storm generates one-shot SCSI UNIT ATTENTIONs (peer PR churn; test16 dmesg: `key=0x6`, `Parameters changed` in-window) → transient first-attempt CAS failure is guaranteed occasionally (2/32 this cycle).
4. Not-cleared → `caw_owe_residue()` → owed; sess151 fix deliberately does NOT retire owed entries. Teardown drain (`caw_owed_worker_fn` post-loop, arm at `drain_armed`) cleared the slot bits (no P254). Dispatch-success → `caw_owed_release` → `lreq_gc` — **but `lreq_gc` (dlm_caw.c:2036) refuses any entry with `tenure[m] != 0`, and NOTHING in the owed path clears tenure** → entry survives destroy = the leak. ENT dump matches exactly (owed_pend=0, tenure PR=1, all else quiescent).

## Fix design (RULE 5: CONSULT GPT FIRST — this is cycle 2 on this defect)
- **(A) necessary**: retire tenure when a TEARDOWN obligation completes. After `ops_closed` + `release_all_done`, no publication can land (pub_seq bumps only in `lreq_finish`; attempts need admission) → anchor peek at drain-success time is safe; do tenure memset + lreq_gc there (or `lreq_release_all(ctx,&res,current_peek)`). MUST scope to teardown (`release_all_done`), NOT mid-run owed completions (live holders unlock normally later).
- **(B) cause-killer, consider**: allow bounded CAS retry during the teardown pass (lc==STOPPING) so one-shot UAs don't fail confirm-clear at all. The !running guard exists for mid-run abort; release_all IS the shutdown path — refusing its retries defeats clean departure. B alone doesn't cover persistent I/O failure → still need A.
- Verification after fix: owed path fires ~2/32 per cycle → run **≥3 prep_cluster cycles** (96 node-teardowns), require zero new aggregate+ENT lines fleet-wide, kept=0, P253/P255/P257-P262 delta zero, departures clean 32/32.

## Operational gotchas (cost this session real time)
- **census_p.sh empty output**: 11 sequential `dmesg|grep` per node at 32-way fanout exceeds the 12s/node timeout → ALL nodes empty. Use ONE dmesg pass + awk multi-pattern count (worked instantly). Pattern in sess152 transcript.
- **clyde host wedge (NOT MXFS, do not diagnose FS from it)**: 2 ext4 `mount` procs stuck since Aug 5 (jbd2_write_superblock wait; 2nd queued on super_lock; ffmpeg collateral in folio migration) → **ps/pgrep hang** (522 D-state pile-up). Scan `/proc/[0-9]*/stat` fields directly instead. RULE 2: never reboot clyde; user informed via summary.

## State
- Ledger: D-RELEASEALL-LREQ-RETIRE-MISSING stays OPEN (29 open). Task #1 in_progress (fix iteration next), task #2 compile-memories overdue (191 unfolded).
- Build 0.11.454 deployed fleet-wide, cluster healthy 32/32 converged, marker 06:36:23Z.
