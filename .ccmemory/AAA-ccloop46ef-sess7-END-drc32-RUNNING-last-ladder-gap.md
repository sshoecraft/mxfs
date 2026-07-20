---
name: AAA-ccloop46ef-sess7-END-drc32-RUNNING-last-ladder-gap
description: sess7 END: 32/caw cc=32/32 PASS, dlm_scaling=32/32 PASS; dir_reuse@32 RUNNING (pid 2828039, run 183952Z, r2/24 healthy) = LAST ladder gap; then crite…
metadata:
  type: project
---

# sess7 END — dir_reuse_coherency@32 running = the LAST gap on the whole ladder

## Ladder vs criteria (1/2/4/8/16/32 caw dlm multipath 100%)
- 1/2/4/8/16 /caw: **17/17 PASS each** (showstat verified this session).
- 32/caw: cache_coherency **PASS 32/32** (run 181910Z), dlm_scaling **PASS 32/32** (run 182945Z) — both cured by today's v0.10.31-33 fixes, no extra changes needed.
- dir_reuse_coherency@32: **RUNNING** — pid 2828039 on clyde, `timeout 5200 ./run.sh 32 caw dir_reuse_coherency`, run_id 20260710T183952Z, log `/tmp/claude-1000/-src-mxfs/938bd26a-ebc3-4d12-81c8-916887c062ad/scratchpad/run33-drc32.log`. At relay: r2/24 done (~85s/round pace ⇒ finish ~19:45Z), CRC=0 P81=0 OOPS=0 on test3. Suite logs land in `/tmp/run_dir_reuse_coherency_20260710T183952Z/`.

## Next session actions
1. Wait/poll run33-drc32.log for `PASS|FAIL dir_reuse_coherency`. Health probes: per-node dmesg `CRC error`, `P81-BMBT` (each = real lost delta = fence leak), `Oops`, DRCph round pace.
2. If PASS → `./showstat.sh 32 caw` should be 17/17 → ALL of 1/2/4/8/16/32 green → criteria met → `echo YES > /src/mxfs/.ccloop/runs/46efd8b6-3dd3-477c-b004-14362c80d8e8/criteria-met` (verify each board first with showstat).
3. If FAIL → forensics per sess7 memories (AAA-ccloop46ef-sess7-*): kcore findino/rdbuf technique, watch_daddr→bp→b_iowait.done, O_DIRECT-only reads of /home/steve/disk.img (+196688 sectors envelope), kprobe caller=$stack0.

## Build = v0.10.33 srcversion 7395C3ECCCDD5B07DE5A2EB deployed everywhere this session.
All fixes documented in: sess7-ROOT-broot-bytes-oops-and-wedge-chain, sess7-FIX-CDE-bmbt-stranded-leaf-v01032, sess7-STALE-IOWAIT-TOKEN-v01033, sess7-MILESTONE-16caw-COMPLETE-17of17.
