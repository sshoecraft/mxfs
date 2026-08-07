---
name: ccloop-c7ee71c6-sess48-REUSE-FOSSIL-ROOT-createfix
description: sess48 ROOT #2: fossil nu SURVIVES INODE REUSE (iflush stamps new gen around it → all gen-keyed defenses blind); fix = P-CREATE-NUFIX at xfs_inode_in…
metadata:
  type: project
---

# sess48: the reuse-carried fossil — 393-c3 fatal fully decoded

## Evidence chain (ring test2:/root/c3_393_t2_*.dmesg)
- 4 P53s: first 3 = benign IDEMPOTENT shape (absorbed). 4th FATAL: ino=0x20011c INSERT expecting old=NULLAGINO, dinode held 0x11b, dip_gen==i_gen (4244561793), bli_dirty=1 uncp=1.
- NEW P-IUNLSTORE-QUERY diag: **NO-RECORD, store count=0/1 mount-wide** at every P53 — the store was empty; overlay had nothing to graft. 
- Post-shutdown withdraw release: P-IUNLSTORE-RELLEAK ino=2097435 (=agino 0x11b — the exact chain value in the fatal dinode!) committed=NULLAGINO wr_epoch=0 — its remove never made it home.

## Mechanism (RULE 4 complete)
1. Prior incarnation of ino chained (nu=0x11b on platter).
2. Its remove (nu:=NULLAGINO) COMMITTED; home write LOST (teardown/shutdown family). Record existed then.
3. Ino FREED then REUSED: create → iflush stamps NEW di_gen around the slot — **iflush never writes di_next_unlinked** → fossil chain value now sits under a CURRENT gen.
4. Every gen-keyed defense goes blind: overlay GENSKEW keep-and-skip refuses (gen mismatch vs old record); my 389 "gen-mismatch stamps retire" rule retires the old record when the new-gen image destages (the reasoning "different gen ⇒ hazard extinguished" is WRONG for nu: **nu is SLOT state that rides across the gen bump**, not incarnation state).
5. Next unlink of reused ino: INSERT expects NULLAGINO, finds fossil → EFSCORRUPTED at __xfs_trans_commit → shutdown. (c2-392 fatal = same shape.)

## Fix (0.11.394, deployed, guards clean)
P-CREATE-NUFIX in xfs_inode_init (libxfs/xfs_inode_util.c tail, multi-node only): a just-allocated ino PROVABLY cannot be on any unlinked list (dialloc returned it free) ⇒ if dinode nu != NULLAGINO it is a fossil by proof — clear + xfs_dinode_calc_crc + xfs_trans_inode_buf + 4-byte xfs_trans_log_buf (exact iunlink-item idiom) inside the create transaction. Kills the entire reuse-carried fossil family regardless of which write was lost. O_TMPFILE ordering safe (its iunlink precommit later sees NULLAGINO as expected).

## Also this stretch
- 393-c1 rig event: nodes test3/4/5/24/25 hard-hung mid-cycle → external NMI injections (unattributed; drc_autocapture-style tooling exists in tests/ but no daemon found) → panic+reboot → heartbeat fencing cascade (slots 17/31/19 replayed by survivors). Wedge evidence lost to reboots. Fleet re-armed: kernel.sysrq=1 + /etc/sysctl.d/99-mxfs-sysrq.conf on all 32 → next wedge gets virsh send-key ALT-SYSRQ-W stacks. All 32 recovered; full re-prep; guards clean.
- 393-c2 CLEAN cycle with agpurge=59 ALIVE proofs (purge hooks ARE on the release path), relleak=0 mid-run (drain holds during healthy operation — losses concentrate at shutdown/withdraw, which foreign journal replay is supposed to cover; open q: does foreign replay handle buffer-logged nu ranges?).
- Sweep: tests/iunl_soak_sweep.sh now counts rl/gp/lk, bounded scan (tail -60000; NOMARK possible if node's dmesg outgrew that since mark — restamp marks each cycle).

## Next
Soak 394 (mark 394-cN): expect P-CREATE-NUFIX firings (each = a healed fossil, count them), P53=0. If P53 recurs with NUFIX active: QUERY line decides (record present ⇒ install-coverage gap; NO-RECORD + non-reuse shape ⇒ new mechanism). Then: RELLEAK-at-withdraw + foreign-replay-of-nu-ranges audit (crash-consistency leg). 11 OPEN of 39 (4 crit).
