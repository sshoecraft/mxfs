---
name: dmesg-follow-ringbuffer-staleness-trap-drc-cap2-fix
description: TRAP: drc_cap2.sh `dmesg --follow` dumped the whole stale ring buffer (prior runs' P108/P91/drc-FAIL) → false timestamp correlation. sess42 fixed: no…
metadata:
  type: reference
---

## dmesg --follow ring-buffer staleness — a recurring diagnosis trap (sess42 fixed)

### THE TRAP
`tests/drc_cap2.sh` started the per-node capture with `dmesg --follow` WITHOUT clearing first. `dmesg --follow` prints the ENTIRE existing kernel ring buffer at stream start, THEN follows. So `tests/_cap/<host>.log` contained the TAIL OF PRIOR RUNS (previous drc_loop iters, prior captures) interleaved before this run's lines. Kernel timestamps are monotonic-since-boot, so stale entries look identical to live ones.

### COST (wasted effort, mine + prior sessions)
- sess41 explicitly noted "6 failed rounds were STALE dmesg ring-buffer entries from the PRIOR failing run."
- sess42: P108-REACQUIRE "old format" lines (52×) were ALL stale (pre-reload, ts < this-run round1); the NEW held_raw format fired 0× — I nearly misread the fix as not-deployed. And P91-RELOAD-PROTECT ino=0x83 (=131) fired at ts 28223 which looked like it matched failing rounds 20/23, but those were at ts 29108/29148 (this run); 28223 was the PRIOR run → P91 correlation was a false positive.

### THE FIX (sess42, build-independent — it's the harness): tests/drc_cap2.sh line ~28 now runs `dmesg -C 2>/dev/null; dmesg --follow` so the capture contains ONLY post-clear (this-run) lines. Prep (rmmod/insmod/mkfs/mount) runs AFTER the stream starts, so prep+test are captured; nothing prior.

### RULE for ALL future dmesg-correlation work
1. Confirm the capture cleared dmesg (`dmesg -C`) OR a fresh boot preceded it.
2. ALWAYS anchor correlation to THIS run's round-1 timestamp: `grep 'DRCph r=1 .* PHASE=create-start'`. Any P-line with ts < that is STALE — ignore it.
3. A FAIL's RDMISS round# is authoritative; bracket by that round's create-start..verify-done PHASE markers and only trust P-lines inside the window.
</body>
