---
name: trap-a-drbd-test-that-releases-the-fenced-peer-before-the-survivors-witness-confirms-freezes-the-survivor
description: TRAP (0.90.106→107): drbd_rig fence/split tests released the loser's inhibit 1-2 s after the fence; MXFS's witness saw 'running, none', never recover…
metadata:
  type: feedback
tags: [drbd, rig, fence, witness, release-verify]
---

With MXFS mounted, a DRBD survivor recovers its dead peer's slice ONLY after its witness (tools/mxfs_drbd_witness.py → authority `status <peer>`) sees the peer **off AND inhibited under the episode the fence receipt names**. Release the inhibit earlier and the peer boots, reconnects DRBD (Connected, Primary); the exclusion can then never be shown, so the survivor keeps the slot unreplayed with grants frozen — fail-closed, by design — and its next unmount blocks on those locks forever.

Seen 2026-10-08 in tests/drbd_release_verify.sh: scripts/drbd_rig.sh fence-test and split-test called `rig_fence_virsh.sh release` right after DRBD settled (clyde `journalctl -t mxfs-rig-fence`: fenced 10:03:06, released 10:03:08). Survivor kernel log: `P-DRBDW-REPORT ... auth=paused/none` (lab_power restarting the loser) then `running/none`, `P-DRBD-EXCL-NOT-YET ... inhibited under episode 'none', the receipt names '<ep>'`, then `P238-DRBD-FENCE-NOT-YET ... link is 'Connected'` forever. The next step: `test1 would not release mxfs`. On 0.90.106-pre-fix the same frozen survivor's unmount also tripped the put_super/log-worker use-after-free (Oops).

Fix (0.90.107): `wait_mxfs_recovered` gates every release on the survivor's `P163-RECOVERY-COMPLETE` + `P238-DRBD-FENCE-WITNESSED` (after `dmesg -C` at the test's start). Recovery then took ~12 s. Rule of thumb: any harness that fences a DRBD peer with MXFS mounted must wait for the survivor's recovery before releasing it — the product guard (mxfs-drbd-guard) already does; `rejoin_node` documents it.

Diagnosis shortcut: `journalctl -t mxfs-rig-fence` on clyde gives fence/release timestamps; compare with the survivor's first P-DRBDW-REPORT after P-DRBD-EXCL-NOTICE.
