---
name: AAA-ccloop46ef-sess6-END-dirreuse16-clobber-agenda
description: sess6 END: dir_reuse@16 FAIL 0/16 root-cause chain — post-rmmod bio panics, ino=131 i_dlm clobber (h_ex=800 frozen), P36 rearm spin; fix agenda a-d
metadata:
  type: project
---

# sess6 END state (ccloop 46efd8b6) — dir_reuse@16 root-cause agenda

Build at end: **v0.10.30 srcversion DEA32227** deployed test1..16. 16/caw board: 16/17 PASS, only dir_reuse_coherency@16 PENDING/FAIL. 32/caw cache_coherency 31/32 (uv ghost, suspect dirent-analogue skip `|= XBF_DONE` resurrect in pal/linux/xfs_buf.c ~4112-4128).

## dir_reuse@16 failure chain (evidence, two runs)
1. **Post-rmmod bio-completion panics** (netconsole-captured, multiple nodes): `Oops: 0010` instruction-fetch at module-space addrs in `blk_done_softirq` = bio end_io callback into UNLOADED mxfs.ko text; multipath retry windows make completions minutes late. Partner evidence: chronic "BUG mxfs_inode/mxfs_ili: Objects remaining on __kmem_cache_shutdown" at rmmod = unmount leaks inodes.
2. **ino=131 one-shot memory clobber** (test9 wedge, run 135111Z): `SESS50-STARVE ino=131 h_ex=800 waiters=c7c7 waiters_ex=c2c3` from boot+78s; h_ex FROZEN at 0x320 for 900+s while gen advances; neighbor fields garbage ⇒ xfs_inode i_dlm region stomped once. Suspect: small-buffer overflow in shortform-dir if_data memcpy (mxfs_dir_merge / P43-ADOPT block→shortform / from_disk literal-area copies). ino=131 = the shared dir (starts LOCAL/shortform round 1).
3. **P36-MHT-REARM unbounded spin** every 8ms forever, holds iget ref ⇒ unmount inode leak ⇒ feeds (1).

## FIX AGENDA (order)
a) Find/fix the clobber (audit memcpy into if_data/dinode literal area in merge+adopt for missing clamps; else slub_debug=FZP or KASAN on a VM).
b) Bound P36-MHT-REARM re-arm (must strike out; today spins forever holding iget ref).
c) rmmod safety: module exit waits for in-flight bios/armed callbacks (counted-barrier infra from v0.10.25 can back this).
d) Re-run dir_reuse@16 with correct budget: `timeout 2900` (workload 140s×16 + prep).

## Run command
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1" timeout 2900 ./run.sh 16 caw dir_reuse_coherency`

## Infra
- netconsole → clyde UDP:6666 via systemd unit mxfs-netconsole.service on test1..16; listener socat on clyde (restart if dead: `socat -u UDP-RECV:6666 OPEN:<scratchpad>/netconsole.log,creat,append`).
- kallsyms snapshots per node in session scratchpad (refresh after each prep).
- VM ssh: `tools/mxfs_sshpass.sh <host> /tmp/.mxfs_pass '<cmd>'` (3 args).

## Ladder vs criteria (1/2/4/8/16/32 caw multipath 100%)
16: dir_reuse pending. 32: cache_coherency 31/32, rest unknown. 1/2/4/8: presumed green historically, re-verify after 16 closes.
