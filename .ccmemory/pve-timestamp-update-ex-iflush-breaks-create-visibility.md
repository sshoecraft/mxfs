---
name: pve-timestamp-update-ex-iflush-breaks-create-visibility
description: CORRECTED: the fio_perf-fix "dir_reuse regression" was a CONFOUNDED A/B (load asymmetry), NOT deterministic. Fixed build passes dir_reuse 11/11 under…
metadata:
  type: project
tags: [dir_reuse_coherency, update_time, create-visibility, P13-VISNUDGE, proxmox, tcp, RULE4, confounded-ab, flaky, CORRECTED]
---

# mtime/ctime update_time on multinode + dir_reuse flakiness — A/B WAS CONFOUNDED

Found 2026-07-20, Proxmox 2-node TCP (pve1/pve2, 6.17.2-1-pve), while fixing the
fio_perf O_DIRECT -EAGAIN bug ([[pve-fio-odirect-write-eagain-after-dropcaches]]).

## ⚠️ CORRECTION — read this first

An earlier version of this memory claimed the fio_perf fix (restoring mtime/ctime
`->update_time` on multinode) **deterministically** regresses
`dir_reuse_coherency`, "A/B PROVEN" (buggy PASS ×2 / fixed FAIL ×2). **That
conclusion was WRONG — the A/B was CONFOUNDED by rig load**, and better data
refutes it:

- On the **buggy** build, `fio_perf` writes NOTHING (the EAGAIN bug → seqW=0),
  so "dir_reuse after fio_perf" ran on an essentially IDLE rig.
- On the **fixed** build, `fio_perf` does real ~110-154 MiB/s writes, so the two
  original dir_reuse FAILs both ran on a HEAVILY-LOADED / freshly-perturbed rig.
- So the A/B compared idle-buggy vs load-adjacent-fixed — not a clean isolation
  of the timestamp mechanism.

**Controlled re-test on the FIXED build `C7287111`: dir_reuse PASS 11/11** —
3× standalone-idle, 4× on the probe build, 2× immediately after a heavy fio_perf
(153 MiB/s), 2× on a fresh cold FORCE_PREP. The failure did NOT reproduce under
any controlled condition. It is also a documented Heisenbug: adding a
non-executing probe inside the nudge function (binary-layout change only) flipped
FAIL→PASS.

## What actually happened

The 2 original failures (suite run + its immediate standalone re-run, early in
the session) were the **known, rare, pre-existing dir_reuse create-visibility
flaky class** — the leaf-hash / P-IGET-ENOENT race documented in
[[compiled-tcp32-dlm-correctness-campaign]] (it fired once on 0.11.35 too).
Timing/load-sensitive; wider on the slower QNAP iSCSI rig. NOT a deterministic
consequence of the timestamp fix.

Whether the fix *raises the probability* of this flaky race (via the added
mtime/ctime EX+iflush contention) is UNPROVEN — 2 early fails vs 11 later passes
is consistent with either a low-probability timing race or coincidence, and
distinguishing them needs a large statistical run on both builds under identical
load, which was not done. Do NOT assert causation either way without that.

## The real failure signature (when it does fire)

```
drc round=1 rank=1 readdir=128/128 lookup_fail=1 missing=[node2_f1]
P-IGET-ENOENT ino=0x284180 incore_mode=0 buf=NOT-CACHED-or-ATOMIC reclaimable=1 dlm_stale=0
P13-VISNUDGE ino=... — dirent-resolved iget failed; retrying iget   (spins to 120s timeout)
```
Reader sees the peer's just-created file's dirent (readdir 128/128) but `iget`
cache-HITS a stale **reclaimable mode-0 dead shell** (reused inode from a prior
round) and ENOENTs before reading disk; the P13-VISNUDGE retry loop doesn't evict
the shell, so it spins. This is the reader-side dead-shell class (xfs_icache.c
~830 mode-0 path; FIX-D v2 dead-shell reload in xfs_mxfs_dlm.c). The decisive
unanswered question (masked by the Heisenbug): at the ENOENT, is the on-disk
dinode valid (reader stuck on stale shell) or reverted-to-free (creator/buffer
overwrite)? Could not capture — the FUA-read probe's binary change made it pass.

## Bottom line for the fio_perf fix

The fio_perf EAGAIN fix (gate `6.90.0`) is CORRECT and has NO reproducible
dir_reuse regression (11/11 pass). It should ship. dir_reuse's create-visibility
flakiness is a SEPARATE, pre-existing, rare, timing-sensitive class that predates
the fix — investigate it on its own with deliberate race-amplification (inject
delay between a node's create-publish and its content-write ts update to widen
the window deterministically) rather than relying on incidental repro, since
observation perturbs it. GPT's bug-2 analysis (task kqixfve9z) is preserved but
was predicated on the (refuted) deterministic-regression premise; its
create-visibility-invariant guidance still applies IF that flaky class is
pursued.

## GPT's still-valid invariant (if pursuing the flaky class)

"Once a remote node can observe a directory entry, the referenced initialized
dinode must already be visible under the same or earlier publish generation, and
no stale inode-cluster buffer may subsequently overwrite it." Decisive evidence
to get (with amplified repro): raw on-disk dinode at the reader's -ENOENT
(di_mode==0 ⇒ whole-inode-cluster-buffer overwrite; valid ⇒ reader stale-shell
not evicted). Fix candidates: serialize owner ts updates behind create-publish;
no stale iflush when acquiring DLM EX (flush belongs to old owner before unlock);
P13 must invalidate BOTH the stale in-core shell AND the cluster buffer.

## Related

[[pve-fio-odirect-write-eagain-after-dropcaches]] (bug 1, verified fix),
[[compiled-tcp32-dlm-correctness-campaign]] (the create-visibility / dead-shell /
P13-VISNUDGE flaky class this belongs to),
[[pve-agi-buf-hold-leak-umount-wedge-not-sess76-readahead]] (the one genuinely
open PVE kernel bug, from fence_during_write).
