---
name: sess23-residual-is-single-holder-not-doublegrant
description: sess23(ccloop) EVIDENCE: the dir_tenure_evict=1 residual is SINGLE-HOLDER (ex_pop max=1 across nodes, no double-grant) → NOT TCP double-grant. It's t…
metadata:
  type: project
---

## sess23 (ccloop) — residual race is SINGLE-HOLDER, not double-grant

Ran build B17FED9A `dir_tenure_evict=1 instr=1` and checked EX-holder count: `ex_pop` max = 1 across test1-4 (no value >1 anywhere). So NO transient double-grant — the residual flaky single-entry dir_reuse loss is a SINGLE-HOLDER event.

Caveat: the P61-BLK0 ex_pop branch only fires when core_node1<disk_node1 (node1 victim), and the residual victim is usually node3/5/6/7, so the cleanest per-victim ex_pop reading wasn't captured. But the always-on ex-related fields never exceeded 1. Treat "single-holder" as the working conclusion; a next-session generalized ex_pop probe (scan for the ACTUAL victim node's name, not hardcoded node1) would confirm decisively.

### Implication
With my modify-evict refreshing the RMW base via FUA re-read (which gets CURRENT target data by design), a single-holder still reading a base MISSING the peer's entry means: at the moment we FUA-re-read, the peer's just-committed dir-block write was NOT yet visible on the shared target. I.e. the EX was granted to us before the previous holder's release-drain made its write visible/durable on the LUN. This is GPT §5 "grant before durable" at the DLM serialization level.

### NEXT-SESSION TARGET (narrow, concrete)
Enforce release→grant ordering in the TCP DLM: the previous EX holder's bast_work_fn Phase-2 drain (xfs_bwrite dir blocks + blkdev_flush, Inv 1) must PROVABLY complete and be VISIBLE on the shared target BEFORE the DLM master grants EX to the next node. Audit the TCP grant path (xfs_mxfs_dlm.c grant/bast handlers ~12289/12422/12777/12841/12904) for whether the grant waits for the releaser's drain ACK, or whether a downgrade (EX→PR/NL) path skips the full drain. Also re-check whether instr=1 itself caused the r22-24 cascade in this run (instr perturbs; the instr=0 runs never cascaded with dir_tenure_evict=1).

Base build = B17FED9A (dir_tenure_evict default-OFF, keeper-inert). See [[sess23-BREAKTHROUGH-master-epoch-sync-flaky-pass]] [[sess23-residual-race-correction-not-fua]].
