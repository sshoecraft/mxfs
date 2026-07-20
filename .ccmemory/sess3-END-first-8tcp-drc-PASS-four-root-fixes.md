---
name: sess3-END-first-8tcp-drc-PASS-four-root-fixes
description: sess3 END (build 754883887E): FIRST 8/tcp drc PASS 8/8, 24rds, 0 corruption (run67). Four root fixes: EEXIST-wait, release dir-inode flush, !DONE-und…
metadata:
  type: project
---

# sess3 (ccloop a9a03929) END — run67 = FIRST clean 8/tcp dir_reuse_coherency PASS (8/8, 24 rounds, 435s wall incl prep, ZERO corruption/shutdown events)

READ WITH [[sess2-END-road-b-barriers-off-t6-silent-eio-blocker]].

## HEAD = build `754883887E2463678C69F0B` — all changes IN TREE

Four ROOT FIXES this session (each RULE-4 proven from run61/60/62/64/65 evidence before patching):

1. **-EEXIST wait-out** (dlm/v5_mount.c mxfs_v5_dlm_inode_lock): run61 t6 shut down (SHUTDOWN_CORRUPT_INCORE) because a local EX hit its own in-flight PR's WAITING entry (dlm.c:1270 EEXIST) and ilock_begin's 3x50ms retry gave up. Session 2's "silent imap_to_bp rc=-5 sweeps" were POST-SHUTDOWN fallout (xfs_is_shutdown → -EIO at xfs_trans_buf.c:320, alert suppressed by xlog_is_shutdown) — sess2 missed the 119.7s shutdown line. Fix: retry EEXIST every 20ms up to ~60s (the in-flight request's own budget). P3A-EEXIST-WAIT print. Also P3A-DEMOTER-SLOWACQ probe (ilock_begin demoter-bypass issuer) — never fired since.

2. **Release-path dir-INODE-cluster destage** (xfs_mxfs_dlm.c): sess1's Road-B gate `mxfs_dirop_durable_needed()` was INSIDE mxfs_dlm_dir_inode_durable, no-op'ing not just per-op barriers but ALSO the bast_process sd-stage call → dir blocks landed but the DINODE never did → run60/61 all-node `xfs_dir3_block_verify daddr 0x48` (platter dinode nx=1/XDB3-era while block 0 already XDD3 from block→leaf convert). Fix: split `__mxfs_dlm_dir_inode_durable` (ungated body, called at release) from the gated per-op wrapper (xfs_inode.c callers keep the TCP gate = Road B pace). Format-tear family: 0 occurrences since.

3. **!DONE+undestaged re-land** (mxfs_dir_data_durable + mxfs_dir_flush_one_daddr): run62 (data blk 0x3fe1c70) + run64 (leaf 14654552) = dir blocks whose extent was in the DURABLE dinode but content NEVER submitted by anyone (P3W-DIRWR=0 cluster-wide; platter = prior-life garbage → EFSBADCRC/EFSCORRUPTED cluster kills). Proof: t6 grew leaf 369.88, own P-DE-BLK at +120ms showed done=0 dirty=0 in_ail=0 pin=0; P42-RELDUR bad=0 undest=-1 at its release. The sess47 undestaged term was DONE-gated ("evict-invalidated stale") — but lseq>wseq means NEVER-LANDED (a real sess33 stale image landed at its tenure's release → lseq==wseq). Fix: undestaged unconditional in both predicates + before bwrite of a !DONE buf validate magic+owner (garbage → P3F-UNLANDED-LOST, no write, no verifier shutdown) then set XBF_DONE (P3R-RELAND). P3R fired 1-7×/node in run66/67 = actively saving blocks. CRC-garbage family: 0 since.

4. **MAPDIVERGE dirty-inode guard** (xfs_mxfs_dlm.c ~6106): run65 t2 died 13ms after its own block→leaf convert — the modify-prelock P68-MAPDIVERGE hook (no ILOCK) compared in-core nx=2 vs disk nx=1 DURING the concurrent local conversion, "adopted" the stale disk map over the in-flight grow (P68-PREEVICT shrink=1, OWNEVICT evicted=1) → conversion's next block-0 read = XDB3-under-XDD3 → dirty trans_cancel → shutdown → 7/8 nodes died reading half-converted state. Fix: skip the adopt when own inode item is dirty/pinned/in-AIL (in-core authoritative by definition).

## Probes added (all always-on, capped, keep)
- P3W-DIRWR (xfs_buf_submit_bio): every write submit of owner<=256 dir bufs — the write-lineage instrument that cracked run62/64.
- P3B-UNLOCK-UNDESTAGED (bast_process, after p2s_d): invariant-1 audit at unlock.
- P3D-RELINVAL (sess29 relinval arm): the release stale+DONE-clear tracer (fired 150-214/node — structs die often; the seq pair resets on rebirth → P3L).
- P3L-DIRLOG-BIRTH (xfs_trans_log_buf): first log of a dir buf struct (rebirth = seq-blindness window).
- P34C-DIRGROW/DIRSHRINK ungated for ino<=256.
- comm added to ilock_begin "unrecoverable" print.

## Infra
- tests/suite/console_capture.sh (start/stop): host-side serial capture; guests now have console=ttyS0,115200 loglevel=3 + panic=15 + panic_on_oops=1 (grub + sysctl.d/99-mxfs-debug.conf on all 8). Restart capture after every VM cycle (pty per qemu process). Run detached: `nohup ... start DIR 8 > log 2>&1 < /dev/null &` (plain invocation hangs the Bash tool on inherited fds).
- run63: t1 triple-fault-class crash (login prompt, no oops captured pre-serial-console) during round-2 inactivation storm; recovery machinery worked (lease expiry → purge → journal replay elect). NOT yet reproduced/diagnosed — watch consoles67+ if it recurs.
- run66 post-mortem trap: a rejected tool call had STARTED a run; its remote leftovers made run66's dmesg a two-run sandwich (unmount uuid-A @498 + fresh mkfs uuid-B @547) and node-ids from grep -m1 were stale → the "ghost grant 921236023" scare was FALSE (it was t5's second-mount id). ALWAYS map node ids from the CURRENT mount's "DLM init: node_id=" line.
- Cycle verification: after virsh destroy, check `virsh list --name | grep -c test[1-8]` == 0 before start; after boot check `uptime -p` ≈ 0 min + no-module.
- Budget (RULE 0): fresh-cluster prep ≈ 100-150s; 24 rounds × <20s = 480 internal; wrapper 700s detached + foreground until-loop poll (`until grep -q "=== done:" out`). run67: 435s total, PASS.
- P34-ACQ-SLOW: ~30×/node 1-2.1s dir-EX acquires per run — pace tax, not yet diagnosed (fairness/handoff latency). Rounds 16.6-17s avg vs 20s budget — margin thin.

## NEXT (ladder unchanged)
1. Repeat 8/tcp drc: need clean ×5 consecutive (run67 = 1/5). Watch: P3F-UNLANDED-LOST (must stay 0), rc=-17, tears, the run63 crash class (consoles).
2. Then 4/2/1-node drc, then full `./run.sh N tcp` suites N∈{1,2,4,8} → criteria "1/2/4/8 node tcp dlm test working 100%" → only then write the ccloop marker.
3. If pace degrades past 20s/rd: the P34-ACQ-SLOW 1-2s dir acquires + P138 sd-stage growth are the levers.
