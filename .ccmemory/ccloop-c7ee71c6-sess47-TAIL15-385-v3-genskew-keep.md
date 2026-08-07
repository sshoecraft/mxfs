---
name: ccloop-c7ee71c6-sess47-TAIL15-385-v3-genskew-keep
description: sess47: 0.11.385 fleet = A-prime v3 (GENDROP→GENSKEW keep-and-skip; 384's drop-on-mismatch destroyed live coverage — rec_gen=img_gen+1 autopsy). Soak…
metadata:
  type: project
---

# A-prime v3 (0.11.385, BA8561A4499591809C9E292, fleet-wide)

## The v2→v3 delta (384 cycle-2 fatal autopsy, ring /root/c2_384_t2_*.dmesg)
GENDROP lines showed rec_gen=img_gen+1: a gen MISMATCH also occurs when the platter image is PRE-REUSE STALE (record newer than image) — and with randomized fresh-create di_gens the ordering is undecidable. v2 dropped the record on any mismatch = destroyed live coverage exactly when the platter was time-traveling = cycle-2's fossil (victim 0x24000ad old_ptr=0xac). v3: keep-and-skip (P-IUNLSTORE-GENSKEW, ratelimited) — never graft cross-incarnation, never drop; true-reuse records self-clean via re-record + flush retire.

## Store lifecycle now (complete)
record@precommit (update resets wr_epoch) → write-completion stamps wr_epoch=flush_epoch → drops only when flush epoch ADVANCES past stamp → overlay at both installs, gen-equal only, keep-on-skew.

## Verified on deploy: repro CLEAN ×2, matrix 9/9.
## Proof soak RESTARTS at v3: ≥8 cycles (lap→idle 250s→lap→matrix→sweep), success = P-IUNLSTORE-OVERLAY present + P53=0 + no shutdowns. History: v1 0 overlays (fatal), v2 13-15 overlays but drop-hole (fatal), v3 = both holes closed. If P53 STILL recurs: overlay-present ⇒ race between overlay and buffer use (audit locking at install sites); GENSKEW-storm ⇒ leaked records (audit retire); neither ⇒ unhooked fill path (P34D src=plain / raw readers audit).
Rings: test2 ×6 now. Rig 32/32 green, ship config.
