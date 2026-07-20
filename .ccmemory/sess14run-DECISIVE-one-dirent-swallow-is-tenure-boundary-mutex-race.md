---
name: sess14run-DECISIVE-one-dirent-swallow-is-tenure-boundary-mutex-race
description: sess14 DECISIVE (r10 drc r4, victim node4_f9): ms-exact capture — N4's add+publish executed 3-9ms INTO N6's EX tenure (N6 FUA-read 73 @+3.6546, N4 74…
metadata:
  type: project
---

# sess14 FINAL FINDING — the one-dirent durable swallow, captured to the ms

## Artifact: /tmp/run_dir_reuse_coherency_20260704T201007Z (iter r10, 8/tcp,
## build 4D677327). Round 4, dir ino=540021, block daddr=534408 (block-fmt),
## victim node4_f9 (799/800 all nodes, LOOKUP_ENOENT durable).

## The captured fork (P-DIRWR count+crc timeline, /tmp scratchpad wr_timeline.txt)
- +3.6546  N6 EX-granted FUA-fresh read of base: cnt=73 (fresh=1 fua_fresh=1)
- +3.6579  N4 writes count=74 crc=cac556ea (includes ITS f9 add; P11-DATALOG
           f9@off=1800 prints ~+3.66, comm=dd)
- +3.6647  N6 writes count=74 crc=45fb2864 (73-base + N6's own add, NO f9)
- Chain continues from N6's lineage → final 168 vs 169 → f9 durably gone.
Duplicate count=74 with different CRCs 7ms apart = the stale-base fork.

## Interpretation
N4's add/publish executed ~3-9ms INTO N6's tenure (N6's grant + base-read
precede N4's DATALOG+write). Either:
(a) N4's op ran under a stale cached EX after its release completed
    (mutual-exclusion break at the unhold/release boundary — the trans-pin
    i_dlm_pin_count is supposed to block release across multi-step ops;
    sess12 FIX-A made release-abort pin-aware; check whether the dd's add
    window is actually pin-covered, esp. WITH the sess14 tenure-floor
    keep-path (bpend kept + dwork release at expiry — dwork checks
    pin/holders, but the admit-to-commit window of a fast-pathed op may
    slip between the dwork's quiescence sample and trans commit), or
(b) N4's earlier release completed without waiting for this CIL-pinned dir
    data buffer (invariant-#1 drain hole) and the write landed late.
Timing favors (a): the DATALOG (trans commit of the add) itself is INSIDE
N6's tenure, not merely a late writeback of an older commit.

## Next-session plan (RULE 4)
1. Instrument the boundary: on P-DIRWR of a watched dir under mode!=EX (or
   grant-held=false via mxfs_v5_dlm_inode_held), print holders/pin/state —
   catches the phantom-EX writer red-handed. Also log pin_count in
   P11-DATALOG.
2. Inspect: mxfs_dlm_ilock_begin fast-path admit vs dwork quiescence
   sample vs trans-pin acquisition ORDER for xfs_create/dir-add: is there
   an admitted-but-not-yet-pinned window? (i_dlm_bast_dwork fires, sees
   holders=0 pin=0, DEMOTES+releases while an admitted op is between
   ilock_end and trans-pin? or between admit and holders++?)
3. Fix candidate: make the dwork/unhold release recheck ATOMIC vs admits
   (grant-era token: ops stamp the tenure gen at admit; release aborts if
   any admitted-op token outstanding — extend P15 holders-recheck).

## Column status on 4D677327 (+ lineage) at handoff
- 8/tcp: r8 17/17 (11FAB23A+sf40 args), r9 17/17 (8E654A57 default),
  r10 15/17 (this face + tds aftermath-slow 107-116s).
- 2/tcp: s14a 13/17 (test2 shutdown → FIX-G destage-then-reload, gap≥3),
  s14b 17/17 (pre-FIX-G), s14c 16/17 (FIX-G v1 too hot: destage storm),
  s14d 17/17 (gap≥3 gate, build 4D677327).
- 4/tcp: 17/17 ×1 (8E654A57). 1/tcp: 16/16 ×1 (8E654A57).
- Criteria marker NOT written: the tenure-boundary race fails ~1-in-2-3
  8-node iters; fix it, then accumulate repeats on all four columns.
- WATCH: FIX-G gap threshold (≥3) may sit inside 8-node jitter — destage
  fired only 1-3×/node in r10 (fine), but if tds slows again check
  P14-DESTAGE counts first; consider gap ≥ N+2.
- tds in-suite is BIMODAL: 17-31s when drc passes, 66-116s when drc
  fails/forensics-floods before it. Fixing the face fixes tds's bad mode.
