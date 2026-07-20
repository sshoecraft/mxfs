---
name: AAA-ccloop46ef-sess7-MILESTONE-16caw-COMPLETE-17of17
description: MILESTONE: 16/caw board COMPLETE 17/17 (build 7395C3EC v0.10.33, dir_reuse 16/16 PASS run 174235Z); ladder 1/2/4/8/16 all 17/17; only 32/caw left (cc…
metadata:
  type: project
---

# sess7 MILESTONE — 16/caw COMPLETE (17/17), ladder = only 32 left

## dir_reuse_coherency@16/caw: PASS 16/16 (run 20260710T174235Z, build 7395C3ECCCDD5B07DE5A2EB = v0.10.33)
Was 0/16-with-panics at session start. Three stacked roots fixed today (all RULE-4 proven):
1. v0.10.31: `xfs_idestroy_fork` stale `if_broot_bytes` → NULL-broot create oops → dd killed in place holding dir locks → node wedge + cluster starvation. + P36 dwork strikeout (2500).
2. v0.10.32: bmbt release-fence blind to !XBF_DONE undestaged leaves (missed landings = durable delta loss); skip arms never staled superseded buffers (40Hz resubmit walls, manufactured CRC on in-place verify). Fence predicate fix + skip reconcile (P82 certify / P81 loss+stale) + no verify_read on in-place completions (b_mxfs_inplace_read).
3. v0.10.33: stale `b_iowait` completion token (kcore-proven done=1 at rest) → sync reads verified pre-DMA content → perpetual EFSBADCRC → readdir=0/1600 on rank1. Fix: reinit_completion at sync submit (lock-held ⇒ any token is stale).

## Ladder vs criteria (1/2/4/8/16/32 caw multipath 100%)
- 1/2/4/8/16 /caw: **ALL 17/17 PASS** (showstat verified).
- 32/caw: 14/17 — FAIL cache_coherency (31/32, v0.10.30-era), FAIL dlm_scaling (29/32), PENDING dir_reuse_coherency.
- cache_coherency@32 rerun with v0.10.33 LAUNCHED (timeout 1400, log sess7 scratchpad run33-cc32.log). Then dlm_scaling@32, then dir_reuse@32 (budget 140*32=4480s+prep ⇒ timeout ~5200).
- 32-node uv-ghost suspect if cc@32 still fails: dirent-analogue skip arm sets `|= XBF_DONE` (P33/P37/P50-RELEPOCH arm, pal/linux/xfs_buf.c ~4180) — sess6 planned dropping the resurrect like the bmbt arms; today's stale-token fix may also have cured the read side.

## Beware (forensics on clyde)
- /home/steve/disk.img is SCST o_direct=1 — buffered reads on clyde ALIAS (stale page cache). ALWAYS `dd iflag=direct`.
