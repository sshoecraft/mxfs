---
name: ccloop-c7ee71c6-sess355-monitor-blind-knob-races67-pass-0134
description: sess355: monitor_blind knob landed 0.13.4 sv 58DCECD6; #92 races 6+7 PASS all variants (blind C1 2/2, C2 1/1, suspend 1/1); 2 test artifacts fixed
metadata:
  type: project
---

# sess355 — monitor-blind knob, #92 races 6/7 all PASS on 0.13.4

## GPT RULE-5 ruling (revises sess349 "no kernel change" for race 7)
Race 7 is ARITHMETICALLY IMPOSSIBLE under virsh suspend: B's cycle-1
mount blocks 62s in P225 SETTLE-VERIFY (barrier samples = dead_threshold,
same variable as the 64s death threshold), so A always crosses the fence
line before cycle 2. Ruling: test-only monitor-blind knob is a FAITHFUL
realization (a stretched monitor interval); suspend variant kept for
race 6 corroboration only. Requirements implemented: gate whole peer
scan at scan boundary with acked generation; own hb CAS + self-fence +
conflict relay stay live; 120s auto-clear (reason=timeout|shutdown) =
INVALID run; counters skips/hb_ok in the CLEAR line.

## Landed 0.13.4 sv 58DCECD6554D8C9F8FD68E6
- dlm/disklock.c: hb_blind_gate() + hb_blind state above disklock_hb_fn;
  gate before MXFS_HB_STAGE_MONITOR, goto hb_blind_sleep label; shutdown
  clear at thread exit. Probes P163T-BLIND-ACK gen=/-SKIP/-CLEAR
  reason=user|timeout|shutdown skips= hb_ok=.
- dlm/v5_mount.c: module_param monitor_blind (0644, #ifdef __KERNEL__,
  extern int convention like evict_ring_monotonic).

## Results (32/caw, test5=A observer, test6=B departing)
- blind CYCLES=1: PASS 2/2 (post-fix). blind CYCLES=2: PASS — range
  arithmetic PROVEN: tracked seq 674 in [S'-chain,S'-1]=[672,675],
  single P163-CLEAN-DEPART-LINEAGE, zero deaths cluster-wide.
- suspend CYCLES=1: PASS (window 2s — umount+reclaim fit inside one
  2s poll, P225 never engaged; that IS the race, valid).

## Test artifacts burned this session (both fixed in the script)
1. caw_slotdump zero-pads slots ("hb[04]") but kernel logs "slot=4" —
   normalize with $((10#$BSLOT)) and grep with trailing space.
2. VM journal clocks skew 1-2s vs clyde: an event can stamp BEFORE a
   same-instant `date -u` T0 and be excluded by journalctl --since
   forever (poll loops don't help — the stamp is fixed). Fix: backdate
   T0 by 5s; safe because runs are >=20s apart.

## Remaining for #92 disposition (sess349 ruling)
Pass-2 reruns of blind C=2 + suspend; then race 5 mixed run, GUARD loser
audit, pre-FUA gate knob + hb_forge for races 1/3/4.
