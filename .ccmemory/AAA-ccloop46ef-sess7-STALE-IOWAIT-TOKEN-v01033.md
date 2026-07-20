---
name: AAA-ccloop46ef-sess7-STALE-IOWAIT-TOKEN-v01033
description: sess7 part3: run 164056Z 15/16 — residual = stale b_iowait token (done=1 kcore-proven) makes sync reads verify pre-DMA content → perpetual EFSBADCRC;…
metadata:
  type: project
---

# sess7 part 3 — v0.10.32 run 164056Z verdict (15/16) + the stale-completion-token root + v0.10.33

## Run 164056Z (v0.10.32, D0A20A10): FAIL 15/16 — massive step
- Fixes C/D/E held: P81=0 P82=0 fleet-wide, rm phases back to ~0.1s, all 24 rounds in budget, soft prep sufficed (no power cycles!), 15 nodes PASS all 145 checks.
- Residual: test1 (rank1) r19-24 `readdir=0/1600` (6 failed checks): its bmbt leaf reads fail EFSBADCRC forever.

## Root (kcore + ftrace + block-trace proven, live on test1)
- Failing image = test1's OWN pre-DMA b_addr (12-era, current-fs uuid); platter + BOTH sd paths hold valid nr=16 (verified via O_DIRECT dd — **buffered reads of /home/steve/disk.img on clyde are a STALE ALIAS, SCST is o_direct=1; ALWAYS use iflag=direct for backend forensics!**).
- block_bio_queue: real bios ARE queued (RS 12756152+8) but `xfs_buf_iowait` returns EARLY: **b_iowait.done=1 at rest (kcore, bp=via watch_daddr PW-DADDR print)** — a stale completion token. iowait's `while (!__xfs_buf_ioend)` then CRC-verifies the PRE-DMA content → EFSBADCRC → ls fails; the late bio's completion deposits the NEXT stale token → perpetual.
- Token sources: mxfs emulated-skip arms call full `xfs_buf_ioend()` (deposits token for sync buffers), readahead-steal conversion (P-RAFIX, xfs_buf.c ~800-838) flips XBF_ASYNC between deposit/consume. Fix-E was ALSO defeated by double-__ioend (arm consumed the inplace flag; iowait's second __ioend re-verified) — with pairing fixed, arm's __ioend clears XBF_READ so the second pass skips verify (Fix-E now effective).

## v0.10.33 fix (srcversion 7395C3ECCCDD5B07DE5A2EB)
`xfs_buf_submit` entry: `if (!(bp->b_flags & XBF_ASYNC)) reinit_completion(&bp->b_iowait);` — I/O owns the buffer lock until ioend and we hold it at submit ⇒ any token present is stale by definition. Safe vs waiters (reinit before our bio; no concurrent completer).

## Debug toolkit additions (test1 techniques, reusable)
- kprobe caller resolution: `p:x fn caller=$stack0:x64` + kallsyms bisect → exact return addr (found __xfs_buf_ioend+0x228).
- `watch_daddr` module param → PW-DADDR prints bp pointer → kcore-read bp fields (b_iowait.done at +184, flags +28, error +280, b_addr +144).
- block:block_bio_queue tracepoint for did-a-bio-really-go-out.
- multipath per-path divergence: dd each sd slave directly.

## Ladder state after this
16/caw: dir_reuse 15/16 (was 0/16 sess6). If v0.10.33 → 16/16: 16 board COMPLETE → 32-node (cache_coherency 31/32 uv ghost = dirent-analogue XBF_DONE resurrect at xfs_buf.c ~4180 P33/P37/P50-RELEPOCH arm sets `|= XBF_DONE`; sess6 planned dropping it) → 1/2/4/8 re-verify → full ladder.
