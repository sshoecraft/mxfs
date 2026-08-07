---
name: ccloop-c7ee71c6-sess39-END3-statfs-rootcause-gpt-design
description: sess39 END3: statfs drift ROOT-CAUSED (percpu lazy counters get local-only deltas; perag IS coherent); GPT design for 328 recorded; delalloc-overcomm…
metadata:
  type: project
---

# sess39 END3 — statfs accounting root cause + 328 design

## D-STATFS-IFREE-NEGATIVE-RANK1 root-caused (architectural)
- Reproduced on fresh 327: n1 used=-3445 after two boards (peers ~290); fdblocks drifts too (n1 sees +38MB free).
- ROOT: percpu m_icount/m_ifree/m_fdblocks receive only LOCAL transaction deltas — foreign deltas never land; rank1's cluster-wide cleanup rm guarantees asymmetry → monotonic drift. NOT a race.
- Per-AG summaries ARE cluster-coherent: overlay clears AGF/AGI_INIT on fresh acquire w/ advanced disk gen → re-init from FUA-fresh buffer (xfs_mxfs_dlm.c:33334 block).

## GPT-reviewed 0.11.328 plan (statfs fix — safe subset)
1. Mount-time init ALL AGI/AGF (normal DLM-aware reads, ~100, one-time) — else never-touched AGs sum as zeros.
2. statfs: icount=Σpagi_count, ifree=Σpagi_freecount (same-gen validated; keep m_maxicount + quota post-processing; warn free>count).
3. statfs blocks: Σpagf_freeblks + set-aside — physical truth; residual: omits foreign in-flight delalloc (seconds) vs unbounded drift now.
4. DO NOT adjust percpu admission counters externally (no safe path: reserved-pool/set-aside/negative-delta semantics; GPT explicit).

## NEW THREAD (verify before ledgering): cluster delalloc overcommit near ENOSPC
Each node's local m_fdblocks admits reservations against the same physical space → aggregate delalloc can exceed disk → writeback ENOSPC after write() success (silent-loss shape). fault_enospc currently passes (single-node-ish fill?). Need an instrumented multi-node concurrent-fill test. Fix shape if real: cluster reservation-credit ledger / per-node leased credits (GFS2 statfs_change / OCFS2 local-alloc precedent; GPT full design in ask log sess39).

## Cluster state at handoff
0.11.327 (E178A8149C6A2ABB7D6CAB9) deployed all 32, grace=10 default, FOURTH all-green board complete. Table clean (fresh 327 prep). Samplers may still run on n1/16/32 (/tmp/iosamp*.txt, harmless). tests/logs/sess39_lap/ holds lap evidence; host_write_sampler.sh may still append to scratchpad hostsamp2.txt (kill or ignore).
## NEXT (order)
1. 0.11.328: statfs fix (above) + s_inodes ref-census probe for D-DWORK-RUNTIME-PIN (both diagnostic-safe, disjoint verification: df cross-node agreement; pin holder named).
2. D-DWORK-RUNTIME-PIN fix once holder named (repro: 200 creates+sync+drop×2 on n12 → slab +200; rm breaks pin; peer-ls doesn't).
3. Overcommit fill test design (above).
4. Authority family: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-AGI (canary quiet all sess39).
5. Pace re-baseline under RIG RULE (≥25min idle): D-32NODE-SHARED-DIR-CREATE-PACE, D-READDIR-PEER-CACHED-DIR-PACE; in-mxfs lever = wire-unlock CAS (P138 sx p50 9.7/p90 44ms), drain refuted (1.6ms).
9 OPEN. Criteria NO.
