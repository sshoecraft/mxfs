---
name: sess9run-FIX27-edeadlk-recursion-stack-overflow-panic
description: sess9 FIX-27 (build A5DB8292): test1 panic = ilock_begin EDEADLK tail-recursion x35 -> stack overflow; FIX-26 abort fed the loop. CACHED-on-gen-moved…
metadata:
  type: project
---

# FIX-27 — ilock_begin EDEADLK recursion stack-overflow panic (test1 mid-dir_reuse death)

## Evidence (serial log /var/log/libvirt/qemu/test1-serial.log, suite run 20260703T145525Z)
- test1 kernel PANIC at uptime 208s (~14:58:25, dir_reuse round 3): "BUG: TASK stack guard page was hit" → "Fatal exception in interrupt", comm=bash (the test's create loop), RIP virtqueue_add_split (virtio-net xmit at stack bottom).
- Call trace: **mxfs_dlm_ilock_begin+0x1b14 repeated ~35 times** (tail recursion), interleaved with __queue_work (bast_process queued per lap), deepest frames dlm_lock_impl → v5_dlm_send_cb_tcp → mxfs_pal_tcp_send → TCP xmit → stack blew.
- This is very likely the recurring "rank1 rebooted, fatal round's trace lost" dir_reuse killer noted in the test script (sess17 comment) — first time captured (serial log survives, journald does not).
- In-suite effect: t1 died mid-md5-phase → node1_f26.md5..f50.md5 never created + node4_f1..f46 unreplayed → 71-name RDMISS round 3 + suite timeout kill.

## Loop mechanism (with FIX-26 v1)
EDEADLK self-demote retry (xfs_mxfs_dlm.c ~17283): acquire returns -EDEADLK (upgrade conflict) → state=BAST, self_demote, queue bast_process → **tail-recursive mxfs_dlm_ilock_begin(ip, mode)**. Each lap: the pending re-request is granted MID-DRAIN (gen+1) → FIX-26 v1 abort keeps grant but left state=BAST → woken waiter can't fast-path (dir state-gate) → slow path re-request → EDEADLK again (already holding) → recurse. Unbounded recursion; each lap +~450B stack; ~35 laps + TCP send = 16KB gone.

## Fixes (both in build A5DB8292)
1. FIX-26 v2: in the release-abort branch, `state = gen_moved ? CACHED : BAST`. A mid-drain grant is OURS and LIVE — CACHED lets the waiter fast-path on it; peer re-BASTs via ACQUIRE_WAIT retry (≤6s). Plain holders-race abort keeps the proven BAST re-arm.
2. Recursion → `goto restart` bounded loop at function top: constant stack, lap counter, msleep backoff after 4 laps (50ms*laps capped 1s), hard cap 64 laps → xfs_force_shutdown (a shutdown beats a panic).

## Crash-capture lesson
- test VM serial consoles DO capture panics: /var/log/libvirt/qemu/testN-serial.log (append=off — truncated at each domain START, so read it BEFORE cycling VMs after a suspected crash!). journalctl -b -1 does NOT persist on these VMs.
- A guest kernel panic auto-reboots (~10s panic timeout), so "uptime -s newer than expected + tiny dmesg" = panic happened; go read the serial log.
