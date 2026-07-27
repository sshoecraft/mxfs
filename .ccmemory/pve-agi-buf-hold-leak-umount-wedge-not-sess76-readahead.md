---
name: pve-agi-buf-hold-leak-umount-wedge-not-sess76-readahead
description: 2/tcp on Proxmox: post-shutdown umount wedges forever in xfs_buftarg_drain on ONE xfs_agi buf (hold=2). Flags prove it is NOT the sess75/76 readahead…
metadata:
  type: project
tags: [umount-wedge, xfs_buftarg_drain, agi, buffer-hold-leak, proxmox, tcp, RULE4, open-front]
---

# AGI buffer hold leak wedges umount after forced shutdown — distinct from the sess75/76 readahead family

Found 2026-07-20 on the Proxmox rig (pve1=192.168.1.80 / pve2=192.168.1.81,
kernel 6.17.2-1-pve, build `CA76C3FF2BAD7C39813BE5C`) during the first-ever
2-node TCP run there. Dossier: `tests/logs/pve2_agi_drain_wedge_20260720/`
(`dmesg_pve2.txt` 2119 lines, `state_pve2.txt`).

## Symptom

`umount /mnt/shared` never returns; task sits in **D-state forever**, unkillable.
Module refcount stays 1, so `rmmod` fails and the node cannot rejoin. The mount
is already gone from `/proc/mounts` — only superblock teardown is stuck:

```
[<0>] xfs_buftarg_drain+0x1a4/0x200 [mxfs]
[<0>] xfs_log_unmount+0x72/0xd0 [mxfs]
[<0>] xfs_unmountfs+0x81/0x130 [mxfs]
[<0>] xfs_fs_put_super+0xa6/0x100 [mxfs]
[<0>] generic_shutdown_super  -> kill_block_super -> xfs_kill_sb
[<0>] deactivate_locked_super -> cleanup_mnt -> task_work_run
```

890 identical `P-DRAINSTUCK` prints, **all naming the same single buffer**:

```
P-DRAINSTUCK daddr=2093226 ops=xfs_agi hold=2 flags=0x200030
             state=0x0 pin=0 li_empty=1 has_bli=0 delwri=0
```

`xfs_buftarg_drain_rele` (pal/linux/xfs_buf.c:8826) returns `LRU_SKIP` for any
buffer at `b_hold > 1`, so one leaked hold loops the drain forever.

## The standing suspicion is REFUTED for this instance

The probe's own comment says "suspected: the same stolen-readahead whose async
ioend never ran to drop its hold" — i.e. the sess75 (`bt_readahead_count`) /
sess76 (orphaned readahead HOLD, fix at pal/linux/xfs_buf.c ~1134-1160) family.

Decoding the flags rules that out:

```
0x200030 = XBF_ASYNC (0x10) | XBF_DONE (0x20) | _XBF_KMEM (0x200000)
           XBF_READ_AHEAD (0x4) is NOT set.  No unaccounted bits.
```

So the sess76 `_xfs_buf_read` stolen-readahead path cannot be the leaker here —
that path is gated on `bp->b_flags & XBF_READ_AHEAD`. **This is a different
acquisition path with the same end state.** Do not re-apply the readahead fix.

## What the buffer state says

- `ops=xfs_agi` — the AG inode header, not a data or dir buffer.
- `XBF_ASYNC` still set **and** `XBF_DONE` set — an async op that completed.
- `pin=0`, `li_empty=1`, `has_bli=0`, `delwri=0`, `state=0x0` — no log item, not
  pinned, not on any delwri queue. Nothing in ordinary XFS machinery owns it.
- `hold=2` — exactly one reference above the LRU's own.

## Trigger context (how it got there)

It followed a forced shutdown on pve2 during `fence_during_write`:

```
mxfs: DLM inode lock failed: ino=2638210 mode=5 rc=-35   (x6, -EDEADLK)
mxfs: P-WITHDRAW-QUEUE — FS shut down; scheduling cluster DLM withdrawal
mxfs: P-WITHDRAW — FS shut down; leaving cluster DLM
mxfs: P-WITHDRAW-RELALL released 9 held/queued grants
XFS (sdb): Corruption of in-memory data (0x8) detected at
           xfs_trans_cancel+0x15c/0x170 [mxfs] (xfs/xfs_trans.c:1069).
           Shutting down filesystem.
```

`xfs_trans_cancel` of a **dirty** transaction — the same forced-shutdown
signature as the 32/tcp fio cascade (see
[[compiled-tcp32-dlm-correctness-campaign]], where a starved AG EX produced the
identical `xfs_trans.c:1069` shutdown). Note `P-WITHDRAW-RELALL` fired and
worked: pve1 did **not** cascade, which is the sess10 withdraw fix doing its job.

## Hypothesis (H1, NOT yet instrumented — RULE 4 step 1)

An async AGI buffer op was in flight when the FS force-shut-down; the shutdown /
withdraw path abandoned the completion so `xfs_buf_relse()` never ran, leaving
the hold outstanding. `XBF_ASYNC` still set alongside `XBF_DONE` is consistent
with a completion that partially ran or was short-circuited by the shutdown
check rather than completing normally.

Next step: instrument the AGI acquisition sites and the ioend/completion path
for the shutdown case — log who takes the hold on an `xfs_agi` buf and which
completion arm runs (or is skipped) once `XFS_FORCED_SHUTDOWN` is set. Prove the
site before patching; do NOT patch on this hypothesis alone.

## Operational consequence

A node in this state needs a **reboot** — the D-state drain never yields, so
`umount -f`, `umount -l`, `fuser -k` and `rmmod` retries all fail. On a
libvirt test VM `virsh destroy/start` clears it. On an external node
(MXFS_NODE_LIST: Proxmox, bare metal) there is no auto-recovery — `run.sh`'s
`power_cycle_node` now refuses loudly for those rather than pretending to
recover (it previously ran `virsh` against an IP, silently no-opped, and let
prep march on into a split cluster).

## GPT consult (RULE 5, task kkxkr30ds) — mechanism + fix direction

- My sync-credit hypothesis is PLAUSIBLE but not uniquely proven: `XBF_ASYNC`
  set + `b_hold==2` + no BLI only proves ONE non-LRU reference survived, not
  which. `ioend_seen - relse_seen == 1` is NOT valid proof (counters lose
  ownership/ordering).
- **Leading candidate: `xfs_trans_bhold`/`XFS_BLI_HOLD` on the AGI.** AG buffers
  are retained across transaction rolls during inode alloc/free/unlinked
  processing; a `bhold`'d buffer is NOT released by `xfs_trans_cancel` (caller
  owns it) — a missed error/shutdown-path release leaks EXACTLY this state
  (no BLI, not pinned, not in-flight, hold = LRU + 1 retained). CHECKED: the
  upstream `xfs_dialloc_roll` (xfs_ialloc.c:1958 bhold → roll → 1978 bjoin) is
  CORRECT (re-joins even on commit error so cancel releases it) — so the leak
  is NOT there; look at MXFS-specific AGI holds (per-AG DLM drain
  `mxfs_dlm_ag_drain_meta_buffers`, bast_work_fn Phase 2) or another bhold/roll
  whose shutdown unwind skips the release.
- **DO NOT fix in `xfs_buftarg_drain`** (force-relse on b_hold>1 is a
  double-free/UAF risk — a slow waiter/owner may still relse). DO NOT use a
  counter-based reaper. **Fix the path that owns the leaked reference.**
- Decisive instrumentation: reason-tagged HOLD/RELE/RELSE history (per
  submission generation) — reasons: lookup / trans-join / trans-release /
  trans-bhold / sync-waiter / io-submit / io-complete / dlm-wrapper / lru —
  dumped at drain. The leaked reference's reason+caller names the site. Also
  capture bjoin/bhold/brelse/roll + BLI flags (HOLD/DIRTY/STALE) around the AGI.
- **Sync-credit protocol redesign (GPT-recommended, general):** it overloads
  ONE reference for two jobs (keep-alive-for-async-completion + keep-alive-for-
  sync-waiter). Robust model: caller takes a DEDICATED extra `xfs_buf_hold(bp)`
  before submit; completion drops ONLY that via raw `xfs_buf_rele` (NOT relse —
  must not unlock the waiter's buffer); waiter owns the original locked ref and
  does `xfs_buf_relse` on EVERY exit path. Make ownership an explicit one-shot
  token (IO_REF_OWNED consumed exactly once by completion-or-submit-failure,
  never both). Don't infer hybrid mode from persistent `XBF_ASYNC`.

## Related

[[compiled-tcp32-dlm-correctness-campaign]] — the `xfs_trans.c:1069` dirty-cancel
shutdown signature and `mxfs_dlm_withdraw_release_all`.
[[runsh-ssh-node-pipeline-swallows-remote-exit-status]] — other harness fixes
landed in the same session.
