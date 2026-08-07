---
name: ccloop-c7ee71c6-sess131-CLOSED-354-plus-protogen-finding
description: sess131: closed D-CRASH-CONSISTENCY-32-NOTERMINAL-354 FIXED AND VERIFIED (ledger 29 to 28); found D-MIXED-VERSION-UNGATED-REPLAY's mechanism already…
metadata:
  type: reference
tags: [rule6, ledger, protogen, crash-consistency, mixed-version]
---

ём# sess131 (ccloop c7ee71c6) — ledger 29 -> 28

## 1. CLOSED: D-CRASH-CONSISTENCY-32-NOTERMINAL-354 -> FIXED AND VERIFIED

The prior next_step demanded a deliberate disposition call. Made it against all four RULE-6 tests:

- **RULE 4 proves the cause** — sess126 20 Hz stack sampling (30310 ticks / 34300 samples, 8 nodes) put ~100% of workload blocking wall on the CAW inode grant wait, contended inode = mount ROOT ino 128 (202 grants >5 ms, 713681 ms summed). sess127 re-rooted one level down to BAST delivery: single-threaded `bast_recv_fn` doing a synchronous shared-LUN slot READ per packet, UDP RcvbufErrors=8085.
- **Patch targets that cause** — sess128/129 BAST dispatch queue, 0.11.453.
- **Test exercising the cause passes under UNCHANGED criteria** — the deterministic virgin-fs recipe (`prep_cluster` then `crash_consistency`) that FAILED 3/3 on 0.11.452 now PASSES **5/5**: 79/79/77 s (sess129), 79 s hostload 15.72 and 82 s hostload 19.67 (sess130). 32/32 nodes, 204/204 checks, inside the unchanged 90 s budget.
- **Discriminators flipped** — RcvbufErrors 8085->0 over 614803 datagrams; yield-ticket age at defer p50 2873->10 ms with 0/567 defers within 500 ms of the 5 s valve; P139 grant waits >800 ms 172->0; ino-128 summed grant wall 713681->502 ms.

**The binding claim, retired by evidence**: the entry said it "cannot be dispositioned independently" of D-32NODE-SHARED-DIR-CREATE-PACE. That held while both symptoms ran through the same CAW grant wait. They no longer do — the residual pace shows only 19 grant waits >5 ms / 2026 ms total against a 79 s run, i.e. the pace term is now OUTSIDE the CAW inode grant path entirely.

**Explicitly NOT closed** (moved into D-32NODE-SHARED-DIR-CREATE-PACE's evidence): the virgin 77-82 s vs aged 15-21 s gap, AND the margin risk — the passing runs consume 86-91% of the 90 s budget, so that criterion is one modest regression from re-failing. Budget must NOT be widened (RULE 0).

## 2. sess130's GPT UAF concern on the bastq teardown — REFUTED by code

sess130's RULE-5 consult claimed `caw_bastq_join_workers` + `caw_bastq_free` is a UAF if a dispatcher is still live when the bound expires. It is not:
- `caw_join_bounded` (dlm_caw.c:4804) on timeout sets `unsafe_to_free`, then does a SECOND bounded join for the fail-stop grace, and `mxfs_pal_failstop()`s if that also times out. So it never returns without the thread confirmed exited.
- `mxfs_pal_thread_join_timeout` (pal/linux/kern.c:1735) waits on `t->exited`, which the wrapper signals only after the user fn returns. rc==0 really means exited.
- `mxfs_dlm_caw_destroy` gates `caw_bastq_free` behind `mxfs_dlm_caw_unsafe_to_free(ctx)` (dlm_caw.c:12182).

## 3. The bastq teardown DROP WINDOW is real but BENIGN — do not "fix" it blindly

`ctx->running = false` is published in stop() phase 0 (dlm_caw.c:11817). The dispatchers' loop predicate is `while (ctx->running)` (dlm_caw.c:10720), so ALL dispatchers exit immediately — but `bast_recv`/`bast_poll` are not joined until phase 3 (dlm_caw.c:11968-11978), after the whole phase-2 quiesce. In that window producers submit into a queue with zero consumers; entries accumulate, then `P264-BASTQ-FULL` overflow-drops.

**Why it is benign**: the work those hints would drive is a release, and every release entry point (`mxfs_dlm_caw_unlock_gen`, etc.) is gated by `caw_op_enter`, which refuses once `ops_closed` is set — in the SAME phase-0 section that clears `running`. So a delivered hint could not have been acted on either. Pre-sess128 behaviour (inline callback) reached the same refusal.

**What IS wrong**: two comments now lie and will mislead a future session.
- dlm_caw.c:10780-10786 states a caller contract ("must already have joined BOTH producers") that the main stop path structurally cannot satisfy.
- dlm_caw.c:11971-11977 says "Both producers are joined above, so nothing can submit any more" — false; the dispatchers left long before.
Correct the comments (cheap, batch with the next real build). Do not restructure the lifecycle for this.

## 4. D-MIXED-VERSION-UNGATED-REPLAY — the mechanism already exists and was simply never used

The tree already has the full three-layer C7 protocol gate:
1. `XFS_SB_FEAT_INCOMPAT_MXFS_PROTOGATE (1<<30)` (xfs/libxfs/xfs_format.h:412), set by mkfs_mxfs, in `XFS_SB_FEAT_INCOMPAT_ALL`. Pre-gate kernels inherit upstream's unknown-incompat refusal. One-shot/preventative only.
2. Envelope `MXFS_FORMAT_F_PROTOGATE` + `cluster_proto_gen`; mount enforces `== MXFS_PROTO_GEN` at pal/linux/xfs_super.c:3014-3029 (-EPROTONOSUPPORT), plus a half-upgraded-format check.
3. Disklock HB feature block: `P-VERGATE-JOIN` (-EPROTO) join refusal + monitor `P-VERGATE-FENCE` (dlm/disklock.c:1289, 2509).

`MXFS_PROTO_GEN` = **3** (include/mxfs/mxfs_super.h:90). History: 1->2 sess75 (recovery-descriptor v2 fence certificate), 2->3 sess86 (nonzero mount incarnation). **The 0.11.422 certified-replay gate did NOT bump it**, so a pre-0.11.422 / post-incarnation binary is gen 3, is admitted by all three layers, and does exactly the ungated replay the defect describes.

The in-tree rationale for both prior bumps applies verbatim here (sess74 ruling, quoted at include/mxfs/mxfs_super.h:56-88 and dlm/disklock.h:293-304): per-record fail-closed is no substitute, because the old replayer REPLAYS FIRST and only consults the descriptor afterwards.

**Proposal (consult in flight at session end)**: bump MXFS_PROTO_GEN 3 -> 4 as the hard prerequisite of the 0.11.422 gate, plus durably QUARANTINE legacy uncertified FENCED/NONE descriptors. `MXFS_RECOV_F_QUARANTINED` (dlm/disklock.h:357) already exists and is honoured as terminal everywhere (disklock.c:1917, 2015, 3082, 3239, 3477, 3897). Today such descriptors fail `mxfs_recov_cert_proves_exclusion()` with reason "fence_kind does not prove exclusion" (disklock.c:3483) but are never marked, so they block their slot forever with no operator-visible reason.

Open design questions sent to GPT: who may durably write the quarantine flag (no recovery ownership claimed => no owner/epoch CAS authority); whether quarantine needs an un-quarantine path; and whether `chk_mxfs --upgrade-protogate` (offline, all nodes unmounted, zero authority race) is the right place to quarantine instead of runtime.

**Verification asset that already exists**: `tests/vergate.sh` with arms legacy_refuse / upgrade / hb_intruder / join_refuse. Reuse it, do not write a new harness (RULE: reuse-existing-criteria-tests).
