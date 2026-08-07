---
name: ccloop-c7ee71c6-sess172-pw-selftest-ALL-THREE-PASS-on-rig
description: sess172: 462 DEPLOYED 32/caw; caw_pw_selftest.sh basic+wrap+kill ALL PASS on rig. Seq survives purge (3474 after death@~3473). Next: full board, ledg…
metadata:
  type: project
---

# sess172 — 0.11.462 deployed, PW selftest ALL THREE CASES PASS on rig

## Rig state
All 32 nodes on 0.11.462 (F185ED4495CCC5DCEED0914) via `./run.sh 32 caw prep_cluster` (72s). NOTE: run.sh REFUSES filtered test runs on srcversion mismatch — explicit prep_cluster first. Cluster mounted; NO board run yet on 462 — that is the next step.

## Harness landed: tests/caw_pw_selftest.sh (modes basic|wrap|kill|all)
- Single-ssh node script via `$SSH node "bash -s -- args" <<<"$SCRIPT"` (stdin passes through mxfs_sshpass).
- **printk-finalization lesson (measured 2/2 on 6.8.0-101)**: the LAST printk record is INVISIBLE to dmesg until the next record is reserved — a verdict line 9μs after its predecessor was deterministically missing from a dmesg run ms later. Fix: write an END marker to /dev/kmsg right after the trigger; finalizes the verdict record. Any future dmesg-harvest harness needs this.
- Kill-mode rejoin: fresh boot has no NFS /src (prep_node.sh lives there) — mount NFS first (run.sh:517 idiom), then prep_node.sh caw → NODE_PREP_OK.

## Evidence (all on rig, 0.11.462)
- **basic(test1)**: rc=0, 1 PASS verdict, preserve=3, p109=1. Runs 1..3 on same key: t=(1,2,3),(4,5,6),(7,8,9) — durable per-resource sequence, monotonic across tombstone recycle, zero reuse.
- **wrap(test1)**: GEPWRAP-INJECT consumed by our rk, prev=~0 → t1=1 (zero-skip wrap guard live), knob self-cleared.
- **kill(test2 victim, test1 observer)**: pre-kill PASS t1=1699; tight loop minted to ~3473; virsh destroy mid-hold; observer selftest PASS during window (its own seq 7,8,9 untouched); rejoin NODE_PREP_OK; EXPLICIT same-key re-run PASS **t1=3474** — sequence CONTINUES across node death + purge + rejoin, no reset to 1, no reuse. This ANSWERS the sess171 'epoch continuity across purge' #15 question affirmatively (continuity holds).
- No P23x purge-anomaly probes in observer window (empty report line).

## Next queue
1. Full board `./run.sh 32 caw` (task #3) — 461's edge-mint + 462 selftest never board-tested.
2. Ledger rewrites (task #4): #15 D-EX-GRANT-EPOCH (sess108 steps + sess169 edge-mint + sess170 vehicle + THIS selftest evidence; 2^64 wrap math doc Q4) + #1 cross-refs (historical-record-lifetime blocker, Q6).
3. Compaction still due (184 unfolded).
