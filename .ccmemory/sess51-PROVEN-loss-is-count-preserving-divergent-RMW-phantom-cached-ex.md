---
name: sess51-PROVEN-loss-is-count-preserving-divergent-RMW-phantom-cached-ex
description: sess51(ccloop) PROVEN via P50-WR content-fingerprint timeline: dir_reuse loss is a count-preserving block-level divergent RMW (concurrent phantom cac…
metadata:
  type: project
---

## sess51 (ccloop) — PROVEN ROOT via dir-block content-fingerprint timeline (build B3957326, dirwr=1)

### Method: ran 8/tcp dir_reuse with `MXFS_EXTRA_MODARGS=dirwr=1` (enables P50-WR write-submit + P50-RD read-complete fingerprints: owner daddr cnt sum incarn fua bdirty in_ail realns comm) streamed to /src/mxfs/tests/tcp/drc_cap/stream_rank*.log. Loss round 2 = node4_f15.md5 (all 8 nodes agree, readdir=799/800, lookup_fail=0). dir ino=131, incarn=694013010.

### What the content timeline RULED OUT (each by direct evidence):
- **Master handoff-miss / shadow eviction**: test7 is SOLE stable master for ino131 (P64 only on test7, 129x); epoch MONOTONIC 1→616, NO reset → no eviction, handoff detection works. P-STALEMASTER-GRANT=0 all nodes (no mastership split). P-DOUBLEGRANT=0 at this loss.
- **Stale-base RMW during create**: ZERO create-phase (comm=dd/md5sum) writes ever wrote a block with cnt < the cross-node running max for that daddr+incarn. In-core RMW growth is strictly monotonic.
- **ABA writeback**: ZERO comm=xfsaild writes went below running max either.
- **grant_gen=0 (sess51 fix B3957326)**: REFUTED — loss persists identically (round 6/20 single-dirent, round 2 here). The P51-HANDOFF-UNDERFIRE signal is NOISE: grant_gen is a GLOBAL counter (dlm_next_gen), so hgg jumps ~200/grant from the 800 file-inode grants, not ino-131 handoffs.

### THE PROVEN MECHANISM: count-preserving block-level divergent RMW.
No write ever decreases the block count, yet the durable block is short by 1. The ONLY way: TWO nodes RMW the SAME dir-data block from the SAME base count concurrently — node A reads base (cnt=K), adds entry α (→K+1, sum incl α); node B reads the SAME base (cnt=K, STALE — lacks α), adds entry β (→K+1, sum incl β, NOT α); last writer (B) is durable → block has K+1 entries with β, WITHOUT α. α (node4_f15.md5) lost, count preserved. Both adds collided at the same count so the block never reached K+2. (count-based + xfsaild detectors are blind to this; only a per-entry-name or sum-diff-at-same-cnt trace sees it — the sum-diff consecutive detector found none because the two K+1 writes are not globally consecutive.)

### ⇒ ROOT = concurrent divergent EX = PHANTOM CACHED-EX (confirms sess42/sess50 suspicion).
Two nodes serve dir-EX and RMW concurrently. Master never sees a double-grant because the PHANTOM node serves the FAST-PATH (cached i_dlm_mode=EX) WITHOUT consulting the master — master only ever has one grant outstanding. The phantom node kept i_dlm_mode=EX after it should have downgraded (released the grant so the master could grant the peer). The local held-check (mxfs_dlm_held_mode / P-TCPEX-REACQ at xfs_mxfs_dlm.c:13965) reads the LOCAL mirror = the same stale state, so it CANNOT detect the phantom.

### NEXT FIX DIRECTION: stop the fast-path serving EX when not truly the holder.
The phantom = node released dir EX (master granted a peer) but in-core i_dlm_mode stayed EX → keeps fast-path serving. Find the release/demote path that frees the DLM grant without downgrading i_dlm_mode (suspect: MHT bast_dwork mxfs_dlm_bast_dwork_fn:10504-10508 — sets DEMOTING, spin_unlock, THEN bast_process; a fast-path create in the unlock→release window can serve EX while the peer is being granted), OR add a guard: dir-EX fast-path must NOT serve while i_dlm_state==DEMOTING or i_dlm_bast_pending. Verify with a probe that logs when a fast-path EX modify runs with bast_pending/DEMOTING set at a loss.

### INFRA: every run leaves 1-2 nodes wedged on teardown (D-state [mxfs-worker] kthread pins module, won't rmmod) — pre-existing (baseline too), NOT from sess51 change. Recover: virsh destroy+start. Full 8-node clean reboot before each run (tests/sess51_drc_reliability.sh updated to full_reboot per iter). The earlier 0/8 'cascade' results were partial-reboot MASS-isolation artifacts, NOT a coherency cascade (repro5/6 with full reboot show clean single-dirent losses).

### build B3957326 deployed (carries the refuted grant_gen fix — consider reverting). Marker NOT written.
See [[sess51-ROOT-local-immediate-grant-gen-zero-evades-fastpath-gates]] [[sess50-LOCALIZED-grantee-phantom-cached-EX-stale-local-dir_epoch-master-sends-correctly]].
