---
name: ccloop-c7ee71c6-sess37-armgate-sweep-313-engaging
description: sess37: 0.11.313 class fix for DWORK-TEARDOWN-LASTREF (arm gate at 25 sites + put_super s_inodes sweep) ENGAGING (cancels=1 refs=1 per umount, 0 leak…
metadata:
  type: project
---

# sess37 (ccloop c7ee71c6) — teardown-leak class fix

## Discoveries
1. **xfs_io -x shutdown NEVER worked on mxfs** — its FSGEOMETRY probe gets ENOTTY (whole xfs ioctl surface is stubbed in xfs/xfs_stubs.c) so it exits before sending GOINGDOWN. Every prior scripted "shutdown -f" (incl. sess36 teardown_leak_repro cycles) was a silent no-op. Fix: XFS_IOC_GOINGDOWN (0x8004587d) now handled in the xfs_file_ioctl STUB (0.11.312); `tests/mxfs_shutdown.sh <node> [mnt] [flags]` issues it raw (flags 2 = -f). Repro script updated.
2. Shutdown on mxfs → **P-WITHDRAW voluntary death** (peers fence+replay+purge) → post-shutdown drains fail imapf EIO → bast_process aborts BEFORE release eval → P6G site unreachable post-withdraw-fence. Natural strand = tiny window (shutdown set, unmounting not set, withdraw incomplete). 310's P6G gate covers 1 of ~25 arm sites.
3. **Class fix (0.11.313, srcversion 32AEF975)**: GPT-reviewed design. (a) m_mxfs_arm_lock spinlock + m_mxfs_arms_off in xfs_mount.h; (b) static mxfs_bast_arm_queue()/mxfs_bast_arm_queue_delayed() wrappers in xfs_mxfs_dlm.c — ALL 14 dwork + 11 work per-inode arm sites route through (queued-false = caller drops ref, existing contract); (c) put_super: gate close → pr_sweep cancel + flush → **s_inodes sweep**: igrab pin, cancel_work_sync + cancel_delayed_work_sync OUTSIDE locks, xfs_irele per canceled arm (P204-style BADREF guard cnt<2), iput pin, restart scan (terminates: gate closed ⇒ pending can't return). Prints P6S-ARMSWEEP cancels= arm_refs_dropped= / P6S-ARM-REFUSED / P6S-SWEEP-BADREF.
4. **Verification so far**: repro 8 nodes × 2 cycles on 313: P6S-ARMSWEEP cancels=1 refs=1 on EVERY surviving node's umount (7 engagements) — armed works survive the entry flush ~every cycle; leak was the rare last-ref+timer tail. Zero P142-LASTREF, zero P202-AT-UNLOAD, zero BADREF. Plus 4 earlier cycles (310, no-op shutdown) zero leaks.
5. rel_stale_inject knob (311) — forces strand verdict when shutdown/unmounting; never fired (drain aborts first, see #2) — harmless, default 0, kept.

## In flight
- 32-board on 313 = regression gate for the 25-site gating + sweep (collateral check). Then ledger disposition D-DWORK-TEARDOWN-LASTREF-LEAK → FIXED AND VERIFIED (mechanism-engagement + zero-signature evidence), CHANGELOG 311/312/313.
- Then: shared-dir pace redesign (D-32NODE-SHARED-DIR-CREATE-PACE + D-READDIR-PEER-CACHED-DIR-PACE + D-DIR-REUSE-COHERENCY-32-FLAKY, the only board FAIL) and authority family (D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-RELEASE-BARRIER-OPEN); D-MATRIX-UNMEASURED rig-blocked; D-DIRVIEW-NONCONVERGE-SESS25.
- 9 OPEN at session start; criteria NOT met.
