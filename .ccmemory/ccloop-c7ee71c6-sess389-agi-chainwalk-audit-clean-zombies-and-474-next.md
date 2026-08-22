---
name: ccloop-c7ee71c6-sess389-agi-chainwalk-audit-clean-zombies-and-474-next
description: sess389 END: on-disk AGI chain-walk (chk_mxfs -v, quiesced 32 nodes) CLEAN — 3 members all nlink=0 = cross-node open-unlink zombies (P89-REAP-UNMOUNT…
metadata:
  type: project
tags: [sess389, AGI, chk_mxfs, open-unlink, zombie, 474, ailstuck_probe, handoff]
---

# sess389 final notes (after the 25-AG retest)

## On-disk AGI chain-walk audit (ruling item for D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN)
Procedure (works, ~3 min): age with tests/d385_publication_verify.sh laps -> `sync; umount /mnt/shared` on all 32 nodes (parallel, 60s each) -> `tools/chk_mxfs -v /home/steve/disk.img` on clyde (read-only on the LUN image; rc=0 in <1s) -> MXFS_FORCE_PREP=1 prep restores (mkfs). chk_mxfs -v now prints every unlinked-chain member (0.20.0, tools/chk_mxfs.c orphan_walk_chain).
Result on sv 4411027355A6F7FDD3BAF6F after 2 aged 64-AG laps: 'filesystem clean', 14644 inodes, 3 on unlinked buckets, all nlink=0 next=NULL (no split) — tests/logs/chk_aged64_sess389.log. The 3 = cross-node open-unlink zombies: test1 unlinked (P88-REAP-RETRY owner), peers held open (P87-OPEN-DEFER open_holders=0x800000 etc.), test1 unmounted first -> P89-REAP-UNMOUNT-PENDING 'zombie stays durable in our bucket; next mount of this slot re-drives it'; peers' last closes (P91-OPEN-EAGER-CLEAR) free nothing. Leak until that slot remounts (ledgered under D-CROSSNODE-OPEN-UNLINK-DATA-LOSS next_step: verify the re-drive; cleanly-departed-slot sweep question).

## #474 under AG sharing — next RULE-4 step
The 25-AG wedge capture (tests/logs/ag25_incident_sess389.txt) has P-AILMIN lines (many inode items at one LSN 0x100001479, liflags=0x1) but NO owner stacks because `ailstuck_probe` was NOT armed this session (sess388 armed it at deploy: `echo 1 > /sys/module/mxfs/parameters/ailstuck_probe` on every node). Next: re-prep with MXFS_MKFS_OPTS="-d 50G" (25 AGs), arm ailstuck_probe=1 fleet-wide, run tests/rsync_stall_stacks.sh during d385 laps 1-2, and read the P-AILMIN owner stacks / P87-TARGET-TIMEOUT stage=ilock ocomm holders to name the ILOCK-across-CAW-poll site(s) for the shared home AG; then fix per sess388 ruling 2/3 (no ILOCK held across a contended-AG CAW poll). Expect prep escalation (power-cycles) after wedges: never cap prep under 300s; wait for /tmp/mxfs_run.lock holder.

## Board at session end
32/caw: 26 PASS, rsync_paired FLAKY (the 25-AG FAIL recorded), open_defects POLICY. Ledger 52 open. Rig: 64 AGs, sv 4411027355A6F7FDD3BAF6F, 32/32 mounted. CRITERIA NOT MET.
