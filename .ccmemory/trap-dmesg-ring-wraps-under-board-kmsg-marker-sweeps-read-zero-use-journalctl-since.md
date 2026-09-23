---
name: trap-dmesg-ring-wraps-under-board-kmsg-marker-sweeps-read-zero-use-journalctl-since
description: TRAP (sess429): the node dmesg ring wraps within minutes under a 32/caw board — kmsg-marker-bounded sweeps (sed '/MARK/,$p') silently read ZERO. Swee…
metadata:
  type: feedback
---

# TRAP: dmesg ring wrap makes marker-bounded sweeps read zero

Measured sess429 (s433 chain, 0.39.0): after the 22-minute 32/caw board, test1's dmesg ring held
22,703 lines starting at monotonic 1353 s (~last 2 minutes); the `S429-…-board` kmsg marker written
before the board was gone, so `dmesg | sed -n '/MARK/,$p'` printed nothing and every verdict counter
read 0 on all 32 nodes ("shutdowns=0 settled=0 …") — a FALSE clean sweep. Nodes rebooted by
node_death_replay (test3, test5) lose the marker too (rc=255 / short ring).

The board chain's own gate-3 sweep (tests/sess416_board_0286.sh, BMARK) had the same flaw since
sess416: its "absent = zero" lines were unmeasured for every board that wrapped the ring.

journald on the nodes retains the kernel facility persistently: the same window on test1 was
79,010 kernel lines via `journalctl -k -q --since '2026-08-28 14:01:00'` and contained the
P55C-FREE-HOME / P55C-FREE-HOME-SETTLED evidence the ring had lost.

RULE: record the mark TIME (`date -u '+%F %T'`; node clocks are UTC) and sweep with
`journalctl -k -q --since "$MARKTIME" -o short-monotonic`; print JOURNAL_LINES per node so a
short window (rebooted node) is visible. Fixed in tests/sess429_chain.sh, tests/sess416_board_0286.sh,
tests/free_home_settle_repro.sh. Also: a reproducer must verify the mxfs MOUNT before its workload —
after node_death_replay the cluster is torn down and /mnt/shared is a plain root-fs directory, so
dd/rm "succeed" and every dmesg assertion passes vacuously (free_home_settle_repro first run).
