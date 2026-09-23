---
name: compiled-recovery-completion-custody-barrier-design
description: D-FOREIGN-SLICE-INTENTS-ABANDONED/D-0962 sess610-617: recovery-completion custody barrier design, EFI obligation build, bulk-takeover backgrounding r…
metadata:
  type: project
tags: [compiled, dlm, recovery, tcp, authority-takeover, fencing, D-0962]
---

Topic: what actually gates recovery completion after a peer dies on 2-node TCP — the
EFI-obligation completion build (item 5, D-FOREIGN-SLICE-INTENTS-ABANDONED) and the
later ruling on backgrounding the bulk ledger-page takeover (D-0962) are the same
question asked twice: what is the *real* barrier, versus what coarse reservation is
being leaned on as a barrier by accident.

## sess610 — audit before design: the assumed-missing primitive already exists

[[trap-the-sess575-rulings-missing-base-stable-primitive-already-exists-as-images-replayed-plus-homeflush]]:
the sess575 Astra ruling named BASE_STABLE ("victim base images replayed and durable,
never re-replay") as a missing primitive to build. Grep proved it already in the tree:
`xfs_log.c` does `blkdev_issue_flush` after a clean shadow replay (`P226-FR-HOMEFLUSH`)
before the durable `IMAGES_REPLAYED` CAS, and the slice-replay path already skips once a
descriptor is at or past that stage. Catalogued what genuinely did NOT exist yet:
`MXFS_RECOV_F_CENSUS_ZERO`, the publication/purge guard, `RECOVERY_INSTALLING`/
`RECOVERY_EXCLUSIVE`, a recovery credential, `recovery_advance_obl_done`,
`OBLIGATION_FREEZE_LOST`/`SPARSE` outcomes, any completion transaction, any OPEN
(non-terminal) record publication — i.e. build only increments 3b/3c, not BASE_STABLE
over again. Measured the first sighting of the recurring failure mode below: on 2/tcp,
after a terminal refusal the survivor keeps the sole-survivor Write-Exclusive gate —
dependency cleared, gate never restored — so the returned victim's mount is refused
(`P-PRKEY-PUBLISHED rc=-52 UNATTRIBUTED`) and the cluster is stuck at one node with the
victim's AG answering EIO.

## sess611-614 — built the TCP custody model: AG-lock choke point, not a CAW transfer

[[design-tcp-obligation-custody-freeze-at-the-ag-lock-choke-point-not-a-caw-transfer]]
(0.85.0/0.85.1): the sess463 CAW ruling's transfer/receipt machinery does not fit TCP —
a dead node keeps mastership plus ledger EX holds until the remaster/purge trio runs, so
a custodian cannot even acquire a victim-mastered AG before that trio completes; and the
AG grant alone is not local exclusion (the nested fast path admits any local caller once
`pag_dlm_holders > 0`). Decision: freeze custody at the AG-lock choke point itself
(`__mxfs_ag_dlm_lock`), checked before every fast path — nonblock returns `-EAGAIN`,
blocking waits up to 120s then `-ETIMEDOUT`, custodian task and a txn already retaining
the grant are exempt. Verdict-flip CAS lives at `IMAGES_REPLAYED` (`P226-FR-INTENTS-RECOVERABLE`,
gated on TCP transport + not fswide/rmapbt/reflink/malformed/quarantine); OPEN records
retire dead grants exactly once per `(victim epoch, pub_seq)` — plain `pub_seq` aliased
the slot's next victim (sess612, see the trap that named this pattern generally). Fixed
the sess610 gate-outlives-holder failure directly: a joiner proves the holder dead over a
dead window and preempts it (`v5_tcp_dead_gate_holder`), a successor re-proves a kind-20
certificate as sole live member (`v5_gate_reprove`). Verified fails=0 across three runs
(323s/145s/142s).

## 2026-09-17 — ruling: the bulk authority takeover is not part of the barrier

[[ruling-background-the-bulk-authority-takeover-instead-of-holding-recovery-completion-behind-it]]
(D-0962): a *different* instance of the same coarse-reservation pattern. Recovery
completion ran `v5_handoff_takeover` inline — 7984 ledger pages × ~13ms = 103-107s —
before publishing `P163-RECOVERY-COMPLETE`/`P-PR-GATE-RESTORE`, holding a single-holder
Write-Exclusive reservation the whole time and blocking the rebooted victim from
rejoining. Astra's verdict: the necessary barrier is strictly weaker than "all pages
transferred" — only "the old incarnation can no longer write or grant authority, and
every request to an untransferred page has a safe live takeover path." Everything that
precondition needs was already built and separately ruled on: priority on-demand
takeover ahead of the pass, the progress-aware retryable wait with a 30s no-progress
bound, admission gating with cancel-only-between-pages and unbounded join at unmount, and
the safety-required ledger purges already running before the handoff (not after). So the
bulk pass is eager cleanup/latency-prewarming, not a safety requirement, and belongs on
the departure worker.

**The hazard this move creates, named explicitly rather than assumed away**: the current
one-shot check (`dlm_bootstrap_node(ctx) != ctx->local_node`, done once at entry) is only
sound because the held WE gate prevents the victim rejoining mid-pass — exactly the same
"is this coarse reservation silently load-bearing for something unrelated" question
sess610/611-614 hit with the sole-survivor gate. Required before backgrounding: revalidate
bootstrap certification and page ownership *per page*, not once per pass (a candidate
bitmap is not authority); pin recovery ownership to the survivor for a recovery epoch
rather than rebalancing immediately; treat identity as `(node, incarnation)` never the
bare node number, so a returning node can't reclaim its own dead incarnation's records and
a purge can't delete a newer incarnation's records on a numeric-id collision; and audit
whether the WE reservation is *also* quietly providing single-writer serialization for
`mxfs_tauth_ledger_prepare` — if that CAS-like op is only locally serialised, releasing the
gate early opens a protocol hole. Also flagged as a prerequisite fix, not an add-on: the
progress counter `ctx->takeover_pages_done` currently increments even when
`mxfs_tauth_ledger_activate` fails, so a waiter can see "progress" on a pass transferring
nothing — fix the accounting before backgrounding the pass.

## Recurring pattern across all three

MXFS repeatedly reaches for one coarse Write-Exclusive/single-holder reservation as an
implicit barrier for invariants it was never designed to cover (local AG exclusion,
single-writer ledger CAS, "victim can't rejoin mid-pass") — and each time that
reservation's holding pattern gets narrowed, backgrounded, or its holder dies, a hidden
dependency on it surfaces as a stuck cluster. Audit every consumer of a broad
reservation for an implicit narrower guarantee before shrinking or backgrounding it.
Second, cheaper lesson: read the tree for what already exists before designing a
"missing" primitive — BASE_STABLE was sitting there as `IMAGES_REPLAYED` + homeflush.
