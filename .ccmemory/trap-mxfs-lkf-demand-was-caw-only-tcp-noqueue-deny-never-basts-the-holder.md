---
name: trap-mxfs-lkf-demand-was-caw-only-tcp-noqueue-deny-never-basts-the-holder
description: TRAP (sess523): MXFS_LKF_DEMAND was honoured only by dlm_caw.c; on the TCP engine a NOQUEUE|DEMAND lock was denied silently, so any 'demanding nb pro…
metadata:
  type: feedback
---

# TRAP: DEMAND is a CAW-only flag before 0.75.42

- `mxfs_v5_dlm_ag_lock_nb(..., demand=true)` sets MXFS_LKF_DEMAND; dlm_caw.c CASes the slot's sticky revoke bit. dlm/dlm.c (TCP) ignored the flag at both NOQUEUE deny sites (local master ~4745, remote master ~7689): deny with MXFS_ERR_DEADLOCK, no BAST to the holder.
- Consequence measured sess523 on 2/tcp: the 0.75.41 pre-acquire poll (nb demand + nb retries, 100 ms, inode locks held) expired 84/84 times; unlink 1.5 s -> 41 s, 51 request deadlines, one lap past its 60 s bound (A's writer waited 12 s on the dir PR while B's rm relocked the dir via its cached grant every cycle, P36-MHT-REARM).
- Any "bounded nb sweep" that relies on demand (mxfs_ag_dlm_lock_bounded, D-488 fix) was therefore inert on TCP too — only the CAW rig ever exercised it.
- 0.75.42: dlm.c demand_collect_holders + demand_fire at both deny sites: BAST the conflicting GRANTED holders like a queued request would, do not queue; probe P-DEMAND-BAST on the master.
- Lesson: a DLM flag's semantics must be checked in BOTH engines (grep dlm/dlm.c AND dlm/dlm_caw.c) before building a fix on it; a 2/tcp-only campaign hits TCP gaps that the CAW-era fixes never saw.
