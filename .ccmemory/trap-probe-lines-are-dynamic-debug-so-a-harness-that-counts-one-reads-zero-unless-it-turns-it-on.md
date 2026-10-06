---
name: trap-probe-lines-are-dynamic-debug-so-a-harness-that-counts-one-reads-zero-unless-it-turns-it-on
description: TRAP (0.90.48): mxfs_probe lines (P201-, P95B-…) are pr_debug, off by default; a storm counted 0 events three times. Enable via /proc/dynamic_debug/c…
metadata:
  type: feedback
tags: [harness, probes, dynamic-debug, mpath]
---

`mxfs_probe*` (pal/mxfs_probe.h) is `pr_debug`: nothing prints unless dynamic debug is on
(`echo 'module mxfs +p' > /proc/dynamic_debug/control`, or `module mxfs format "P201-" +p` for one line).
The path-fault rows (tests/mpath/lib.sh) turn every probe on; a harness written from scratch does not.

What bit (tests/mkdir_mutex_storm.sh, 0.90.48): three control runs reported relookup=0 flipwaits=0 and were
read as "the window was not reached". Nothing could have been counted. Two more things hid it:
- `nohup sh -c '… exec dmesg -w' | grep … > file &` inside an ssh command: the grep is not nohup'd and dies
  with the session, so the file is 0 bytes. Follow the whole log (`nohup dmesg --follow < /dev/null > file &`,
  as kmsg_follow_start in tests/lib/rig.sh does) and grep afterwards.
- A path row deletes its followed kernel log (/run/mxfs_pf_kmsg.<run>.<row>) when it PASSES. Anything to be
  counted from it must be counted inside pf_done before that, as an INFO line.

Also: a zero from a counter is evidence only after the same counter has been seen non-zero on a run known to
contain the event (here: the kept log of a failed row showed 6-9 P95B lines per node).

Related: type-flip events (INODE-REUSE-EVICT, P95B) come with path-fault stalls; a plain mkdir/rmdir/churn
storm on a healthy cluster produced none in 600 s. The test knob `typeflip_force_unresolved=2` sends the first
pass of every flip down the re-read path (P201-RELOOKUP); value 1 alone does not force it, because the peer
flush just before the resolver often resolves the flip by itself.
