---
name: ccloop-c7ee71c6-sess156-p248-moot-root-found-disk-geometry-proven
description: sess156: c4 mystery SOLVED by code: lreq_plan holder_moot on tenure≠0 makes teardown drain vacuous. Disk-read geometry PROVEN; experiment ready.
metadata:
  type: project
---

# sess156 — P248 drain vacuity: root mechanism found (H-MOOT); disk-evidence rig proven

## THE ROOT (code-read, needs RULE-4 disk proof — experiment fully designed below)
`lreq_plan` (dlm_caw.c ~2240): `if (e->tenure[giveup_mode]) { plan->holder=false; plan->holder_moot=true; }` — the sess122 "corruption-class save" whose rationale is "its owner's unlock will clear it". **At TEARDOWN that is inverted**: the owner will never unlock; the tenure IS the leaked record. Chain in c1/c4: owe_residue publishes MAXIMAL mask (all 5 modes+waiters, ~9827) → drain dispatch per-mode (4141-4184) → CR/CW/PR/PW: plan.holder=true, image has no our-bit → proven-absent rc=0, per-mode retract → EX (and PR in c4): tenure≠0 → holder_moot → drop_own_waiter reads slot, do_h=false (plan refused), do_w/do_wx=false (no waiter bits) → "proven" rc=0 → moot-retract EX from mask WITHOUT CAS (retract at 2292 clears giveup_mode on holder_moot) → mask empty → retire fires (P263) + memset tenure = evidence destroyed → **clean departure with EX holder bit still on LUN**. Matches ALL sess155 observations: no P6H, K5 unconsumed, drain <1ms (5 reads 0 writes), P263 tenure=0/0/0/0/0/1 (c1) 0/0/0/1/0/1 (c4), c6 orthogonal (tripwire). ALSO applies to real-world (non-injected) release_all failures → 0.11.455 leaks disk bits AND suppresses the P248 report 0.11.454 would have made. Mid-run moot is CORRECT (live tenure's unlock clears in-line); only teardown context is wrong.

## Disk-evidence geometry (PROVEN this session — do not re-derive)
- Envelope super at LUN byte 0: magic 0x5346584D@0, journal_offset@48, **disklock_offset@64 = 67117056**, disklock_size@72=33587200 (=64×512 HB + 65536×512 CAW).
- CAW slot table base = disklock_offset + 32768 = **67149824**. slot N at byte 67149824+N*512. ino-128 slot = **39847** (from P109; stable across c1-c6).
- Slot struct offsets: magic@0(u32, live=0x4D584357 MXCW, tomb=0x4D58444C MXDL), gen@4, resource@8(32B), holders_ex@40, pw@48, pr@56, cw@64, cr@72, waiters@80, granted_mode@88, waiters_ex@120, open_holders@152, ex_grant_epoch@160.
- Device: /dev/mapper/mpatha on nodes (iSCSI 2 paths → clyde SCST).
- **STACK TRAP: single-sector dd (bs=512 skip=171003 iflag=direct) returned ZEROS while bs=1M scan (skip=64 count=34 iflag=direct) returned TRUTH at the same byte** (multipath/SCST read incoherency — the reason mxfs uses SCSI-FUA reads). ALWAYS use the 1MB-scan: dd to /dev/shm/cawscan.bin then python3 struct scan; slot i at file offset 40960+i*512.
- Verified: scan found 65 tombstones whose indexes EXACTLY match the c1-c6 P109 slot numbers (39847 among them) → math confirmed. Current state: slot 39847 = TOMBSTONE (post-c6 remount re-acquired+released ino 128 → healed; current disk CANNOT prove the leak — remount destroys evidence).

## THE EXPERIMENT (next session, first thing)
1. test1+test2 mounted 0.11.455 (sv A559A52088F7FC1BF400138), knobs zero (current rig state).
2. On test1: fresh subdir workload in / (tenure on ino 128) → arm caw_inject_ra_casfail=2 → umount test1. **NO remount.**
3. From test2: 1MB-scan method → read slot for ino 128 (locate by resource match if index moved; expect 39847). PROOF = magic MXCW + holders_ex bit set (test1 = node_slot 0 = bit 0 usually, it's first mounter/MDS — confirm via 'MDS-IDENTITY node_slot=' in test1 dmesg) after clean-departure claim (P263/P267 in window, no P259).
4. Control: repeat with no knob → expect tombstone/zero holders.
5. Then: ledger the defect (new entry or refute-extend D-RELEASEALL-LREQ-RETIRE-MISSING #26), RULE-5 GPT consult on fix design: teardown context (ops_closed && release_all_done) must NOT moot tenured holder bits — drain must CAS them clear; retire then follows legitimately. After fix: c4 non-vacuity (K5 consumed + P6H present) becomes the regression assert; c1 should also show P6H.
6. Remaining bar after that: c5/c3/c2 cases, 3× 32-node fleet census, ledger disposition, docs, memory compaction (COMPACTION DUE ~195).

## Rig state at handoff
test1+test2 mounted 2/caw 0.11.455, knobs zero, test3-32 down. /dev/shm/cawscan.bin on test2 (34MB scratch, /dev/shm clears on reboot).
