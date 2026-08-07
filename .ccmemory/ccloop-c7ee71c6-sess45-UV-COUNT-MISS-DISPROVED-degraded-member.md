---
name: ccloop-c7ee71c6-sess45-UV-COUNT-MISS-DISPROVED-degraded-member
description: sess45: D-CACHE-COHERENCY-UV-COUNT-MISS-2332 DISPROVED — one degraded member reproduces rank1 654/653/1 uv-count signature exactly; 10 OPEN of 37
metadata:
  type: project
tags: [ccloop, disproved, cache-coherency, degraded-member]
---

# sess45 — UV-count-miss DISPROVED by accidental-but-perfect fsdown landing

## The experiment that decided it
Three deliberate attempts to land a mid-body mount drop failed (script's own
STATUS caveat: the trigger window is hard to hit; my on-node nohup watcher was
believed killed by sshd session teardown). It was NOT dead: its 180s-expiry
`umount -l` fired at 13:24:05 — after the next run's pre-assert (~13:23:4x),
before its body (13:24:10-13:24:34). Perfect incident ordering, by accident.

## What the (sess43-fixed) instrumentation recorded
- rank1 (test1): checks=654 passed=653 failed=1, reason
  `uv all files present pre-delete(exp=128 got=124)` — THE incident check,
  missing exactly one member's FPN=4 files.
- victim (test32): 343 failed checks — cv reads of every peer returned empty
  (detached mount); its own uv creates ran detached → never durable.
- 30 healthy nodes: 653/653 PASS. faildist[1x1,343x1].
- Aug-1 all-32-small-fail delta: harness-level-sick member (root full + NFS
  stuck) delays barrier arrivals; coord_barrier counts as a per-node check.
  FS-only degradation (mine) keeps MQTT alive → only rank1+victim fail.
  Freeze arm (sess43) = NO_TERMINAL — third distinct signature, consistent.

## Healthy-fleet non-reproduction (all 0.11.361, 32/caw, one day)
23× cache_coherency green (board + 10 + 10 + 2 post-restore), 11× zsl green.

## Operational lessons (cost real time)
- `nohup bash -c '... &' ` via tools/mxfs_sshpass.sh SURVIVES ssh teardown
  (log looked empty due to buffering — it was still looping). Never assume a
  remote watcher died; pkill it explicitly, and prefer clyde-side watchers.
- run.sh@32 pre-assert alone takes >22s; a fixed-delay drop keyed to launch
  hits the pre-assert, not the body. Key drops to per-node dmesg CCph phase
  markers (`mxfs-CCph rank=N PHASE=cv-write-done` etc.) with a timestamp
  floor, polled FROM CLYDE.
- degraded_member_cascade.sh needs >600s wall at N=32 (baseline+degraded+
  remount) — split it or drive the arms manually (baseline is satisfied by
  any same-day green history).

## Ledger: 10 OPEN of 37. Rig: 32/caw on 0.11.361, all green post-restore.
Session tally: P195 FIXED+VERIFIED (0.11.361) + UV-COUNT-MISS DISPROVED.
Next queue: INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY (critical),
FOREIGN-REPLAY-UNGATED-IMAGES (critical, architectural), CROSSNODE-OPEN-
UNLINK C9-tcp (critical, rig-blocked), DIRVIEW-NONCONVERGE (high),
2x pace + CRASH-CONSISTENCY-32-NOTERMINAL (major), 2 minor, 1 unknown.
