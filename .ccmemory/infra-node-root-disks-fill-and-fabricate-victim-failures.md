---
name: infra-node-root-disks-fill-and-fabricate-victim-failures
description: CRITICAL: test9-32 root disks are 6.1G; triplicated kernel logging (rsyslog syslog+kern.log+journald) fills them → harness dd/tmp breaks → fake "cohe…
metadata:
  type: project
---

# Node root-disk-full fabricates mxfs "coherency" failures (ccloop46ef sess2)

## The trap
test1-4 have 20G+ root disks; test5-32 only ~6-8G. mxfs marker floods were logged THREE times per line (rsyslog → /var/log/syslog AND /var/log/kern.log, plus journald persistent /var/log/journal). Days of instrumented runs filled the small-disk nodes (9-32 hit 100%, 0 bytes free).

## Failure face it fabricates (looks EXACTLY like an mxfs coherency bug)
- cache_coherency cwr: `dd if=/dev/urandom of=/tmp/cwr_N` writes 0 bytes (ENOSPC, stderr swallowed) → node copies+md5s an EMPTY file → every peer reads size 0 / md5 d41d8cd98f00b204e9800998ecf8427e (= md5 of empty) → "cwr size exp=1048576 got=0". Victim node ∈ 9..32 every time (small disks).
- Any /tmp-using harness step (mktemp, sort, barriers writing local state) can silently break the same way.
- DIAGNOSTIC TELL: .md5 file containing d41d8cd98f00b204e9800998ecf8427e = the md5-of-empty — the SOURCE was empty at write time (local /tmp failure), NOT an mxfs read-coherency bug.

## Fix applied (all 32 nodes) + prevention
scripts/node_disk_hygiene.sh N — disables+masks rsyslog (journald alone suffices; tests harvest via journalctl/dmesg), removes syslog/kern.log+rotations, caps journald (SystemMaxUse=200M, RuntimeMaxUse=400M), vacuums to 150M, removes /root/drc_* dumps. Post-run: all nodes ≥1.2G free.
RE-RUN THE HYGIENE (or at least df check) whenever victim-shaped failures appear, and BEFORE trusting any multi-node FAIL: `for i in $(seq 1 32); do tools/mxfs_sshpass.sh test$i /tmp/.mxfs_pass 'df -h / | tail -1'; done` — any node ≥90% is suspect.
run.sh could add a prep-time free-space assert (not done yet).

## Related contamination sources this session
- scripts/live_marker_harvest.sh leaves /tmp/mxfs_harvest.cap on nodes — small (≤1M) but rm in hygiene.
- The floor=0 A/B run scored 3020/3021 with the ONLY failure = this artifact ⇒ effectively PASS. Prior 0/32 runs (3×) are ALL suspect: disk-full victims + one panic run. The 30E6BF7F tenure build may be fine — clean-disk baseline pending.
