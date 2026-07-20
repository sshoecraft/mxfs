---
name: sess23-REFUTED-eager-evict-on-bast-harmful
description: sess23(ccloop) REFUTED: dir_bast_evict=1 (eager-evict clean dir blocks on cross-node BAST release, post-drain) is HARMFUL — dir_reuse 8/tcp r12 lost…
metadata:
  type: project
---

## sess23 (ccloop) — eager-evict-on-BAST REFUTED

Build EF6000F0 added `dir_bast_evict` (default-OFF): on a cross-node BAST release of a dir EX, after the release fence drains durable, eagerly evict clean cached dir DATA blocks (mxfs_dir_evict_data_blocks under nowait ILOCK_SHARED) so the next re-acquire cold-reads coherent.

RESULT: HARMFUL. dir_reuse 8/tcp: r11 lost 2 (798), **r12 lost 86 (714) + leaf-hash lookup_fail** — a big regression with leaf-index corruption. mxfs_dir_evict_data_blocks evicts DATA *and* LEAF blocks; evicting a leaf block at the BAST moment (then the peer rebuilds/RMWs it) corrupts the leaf hash index → readdir-present-but-lookup-ENOENT holes. So eager release-side eviction is the WRONG lever.

### Both invalidation sides now refuted
- ACQUIRE/read-side prior-tenure invalidation (epoch/gen, dir_tenure_evict): structurally racy, flaky (sess16 re-confirmed).
- RELEASE-side eager-evict-on-BAST (dir_bast_evict): harmful (leaf corruption).
=> Buffer EVICTION/invalidation is not the path. The fix must be PROTOCOL-level.

### NEXT SESSION — protocol-level release ordering (NOT eviction)
Per GPT-5.5 [[sess23-gpt5.5-grant-generation-coherency-design]]: the only remaining direction is to make the DLM HANDOFF itself correct — the master must not grant EX to the next node until the prior holder's release-drain is durable+visible on the shared LUN (close grant-before-durable), and/or serialize the tenure so the next holder's first addname RMW provably reads the prior holder's committed image. Audit the TCP grant/release message ordering in dlm/dlm.c (process_remote_release → grant waiter) and the bast_work_fn release path. Do NOT evict/invalidate buffers (both sides refuted).

### Keeper unchanged
Build EF6000F0 == 18064D1D behaviorally (dir_bast_evict + dir_tenure_evict both default-OFF). The validated keeper gain remains the dg_shadow eviction-immunity (reliable epoch; 1/tcp=16/16, 2/tcp=17/17, 4/tcp dir_reuse=4/4). 8/tcp dir_reuse is the lone blocker. See [[sess23-STATE-keeper-18064D1D-1and2-tcp-pass-8-is-lone-blocker]] [[sess23-eviction-immunity-fixes-epoch-but-residual-is-acquire-side-racy]].
